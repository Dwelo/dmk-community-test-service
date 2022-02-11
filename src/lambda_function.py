"""
A Lambda function that tests our SOAP connection to a qa or prod environment Dormakaba Community server.

Be aware that the script tries to create a DMK resident key for a bogus user to a bogus unit and
a bogus encoder id. So this *should* fail. But the receipt of a failure message tells us that
the DMK Community server is running, and most importantly, that our credentials to it are good,
i.e. the pem files, username, and password.
"""

import base64
import json
import logging
import os
import requests
import ssl
import sys
import urllib.parse
import urllib.request
from suds.client import Client as SudsClient
from suds.sax.element import Element
from suds.transport.http import HttpTransport
from dwelo.s3_file_manager import S3FileManager

# Logging
logger = logging.getLogger(__name__)
log_level = os.environ.get('LOG_LEVEL', 'WARNING')
logger.setLevel(log_level)

# Token needed to authenticate with special endpoint on cloud host.
auth_token = os.environ.get('DMK_TEST_SERVICE_LAMBDA_KEY')
if not auth_token:
    logger.error(f"ERROR - DMK_TEST_SERVICE_LAMBDA_KEY not found")
    sys.exit(1)

session = requests.Session()
session.headers = {'Authorization': auth_token}

# Possible values of STAGE are ['dev', 'qa', 'staging', 'prod']
STAGE = os.environ.get('STAGE').lower()

S3_CERT_FOLDER = {
    'dev': 'dev',
    'qa': 'qa',
    'staging': 'stg',
    'prod': 'prd',
}

DMK_COMMUNITIES_URL = "/v3/integrations/dormakaba/lambda/"

CLOUD_HOST = {
    # Feature branches require manually adding an env var with the host, i.e. https://cloudapi-BRANCH-SLUG.n.dwelo.com
    'dev': os.environ.get('FEATURE_BRANCH_HOST', 'https://cloudapi.n.dwelo.com'),
    'qa': 'https://api.qa.dwelo.com',
    'staging': 'https://api.stg.dwelo.com/',
    'prod': 'https://api.dwelo.com/',
}


class ClientHttpsTransport(HttpTransport):

    def __init__(self, certfile, keyfile, cafile, *args, **kwargs):
        super(ClientHttpsTransport, self).__init__(*args, **kwargs)
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile

    def u2handlers(self):
        handlers = super(ClientHttpsTransport, self).u2handlers()
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
        context.load_cert_chain(self.certfile, self.keyfile)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
        return handlers


def get_dmk_community_list_from_cloud():
    """ Query cloudapi for the list of DMK communities to be tested
    """
    try:
        url = urllib.parse.urljoin(CLOUD_HOST[STAGE], DMK_COMMUNITIES_URL)
        logger.info(f"Requesting DMK community list from: {url=}")

        r = session.get(url)
        if r.status_code != 200:
            logger.error(f"Error - invalid response ({r.status_code}) from server")
            return []

        communities = r.json()['results']
        return communities

    except Exception as ex:
        logger.error(f"{ex=}")

    return []


def download_cert_files_for_community(community_uid):

    # Store certs in the /tmp folder. The AWS Lambda docs state:
    #    "Each execution environment provides 512 MB of disk space in the /tmp directory.
    #     The directory content remains when the execution environment is frozen, providing
    #     a transient cache that can be used for multiple invocations."
    local_cert_dir = os.path.join("/tmp", "cert_files")

    cert_filename = f"dmk-{community_uid}-cert.pem"
    pk_filename = f"dmk-{community_uid}-pk.pem"
    ca_filename = f"dmk-{community_uid}-ca.pem"

    cert_path = os.path.join(local_cert_dir, cert_filename)
    pk_path = os.path.join(local_cert_dir, pk_filename)
    ca_path = os.path.join(local_cert_dir, ca_filename)

    try:
        # Make sure we have the SSL cert files copied locally.
        file_manager = S3FileManager(
            s3_bucket_name=f"dwelo-config",
            s3_bucket_subdir=f"cloud-api/certs/{S3_CERT_FOLDER[STAGE]}",
            local_dir=local_cert_dir
        )
        file_manager.get_files([cert_filename, pk_filename, ca_filename])

        cert_path_exists = os.path.exists(cert_path)
        pk_path_exists = os.path.exists(pk_path)

        # If there are no cert or key files, or they are 0-byte files, then we will fallback to
        # attempting an insecure connection by setting all pem paths to None.
        if (not cert_path_exists or not pk_path_exists) \
                or (cert_path_exists and os.path.getsize(cert_path) == 0
                    and pk_path_exists and os.path.getsize(pk_path) == 0):
            cert_path = None
            pk_path = None
            ca_path = None

        # If we have cert and key files but there is not a certificate authority
        # chain file then the soap client expects None for the ca_path.
        elif os.path.exists(ca_path) and os.path.getsize(ca_path) == 0:
            ca_path = None

        return cert_path, pk_path, ca_path

    except Exception as ex:
        logger.error(f"Exception - {ex}")
        return None, None, None


def send_soap_message_to_community_server(community, cert_path, pk_path, ca_path):

    logger.info(f"Testing connection to community '{community['name']}' "
                f"with api_user_name '{community['api_user_name']}' "
                f"and URL '{community['server_url']}'")

    try:
        soap_client = SudsClient(url=community['server_url'], transport=ClientHttpsTransport(cert_path, pk_path, ca_path))
        security_options = Element('AuthHeader', ns=('ssn', "https://CommunityAPI.dormakaba.net"))
        encoded_auth = base64.b64encode(f"{community['api_user_name']}:{community['api_user_password']}".encode('utf-8'))

        security_options.setText(encoded_auth.decode())
        soap_client.set_options(soapheaders=security_options)

        unit_list = soap_client.factory.create('ArrayOfString')
        unit_list.string = ['12341234']

        resident_data = {
            'LeaseID': 'e43f69636de648b4a0f35492c68f37c6',
            'FirstName': 'u123',
            'LastName': 'LastName',
            'UnitList': unit_list,
            'CommonAreaList': list(),
            'ExpirationDate': '2026-04-14T03:00:00',
            'NumberOfKeys': 1,
            'bInvalidateActiveKeys': "false",
            'DeviceType': 'EncoderId',
            'MobileID': 123,
            'RequesterID': 'Dwelo'
        }

        result = soap_client.service.CreateResidentKey(**resident_data)
        return str(result)

    except Exception as ex:
        logger.error(f"Exception - {ex}")
        return None


def test_connection_to_community(community):
    cert_path, pk_path, ca_path = download_cert_files_for_community(community['uid'])
    result = send_soap_message_to_community_server(community, cert_path, pk_path, ca_path)

    if result and 'Invalid room name 12341234' in result:
        return True
    else:
        logger.info(f"Soap result: {str(result)}")
        return False


def lambda_handler(event, context):
    communities = get_dmk_community_list_from_cloud()
    for community in communities:
        success = test_connection_to_community(community)
        logger.info(f"Test to community {community['name']} was {('Successful' if success else 'Unsuccessful')}")

    return {
        'statusCode': 200,
        'body': json.dumps(f'{len(communities)} communities tested')
    }
