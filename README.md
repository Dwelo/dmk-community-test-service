# dmk-community-test-service
Cloud service for periodically testing DMK Community Server connectivity

# Motivation for this Service
When we install our MDU product in a community using DMK door locks we integrate with the local DMK Community server in order to create key cards and mobile keys for the locks.
These Community servers are installed and maintained by third parties, usually IT contractors employed by the community management.
Because we don't control physical or network access to these servers our MDU cloud is susceptible to outages or communication breakdowns.
Any outage will only be manifested when a community staff member tries to create keys for a resident or staff member. 
The key creation will fail and there won't be a simple remedy for the staff. 
We have also learned by experience that most of the DMK Community servers are not being monitored by third parties either.
So the intent of this service is to run in our MDU cloud and to periodically test the connection from our cloud to each DMK Community server that is installed.
If and when the connection is down, and alert will be sent to the appropriate channels at Dwelo so that the staff at the community can be notified, and we can engage the right partners to remedy the situation.
It is not anticipated that the number of these servers will ever be very large.

# Development

## Prerequisites

You'll need the [Serverless framework](https://serverless.com/), which is a node app that can be installed via npm.

```
npm install serverless -g
```

You'll also need AWS credentials available in your environment.

## Developing

The `dev` stage is the default stage for development. Make local code changes and deploy your changes manually to the dev stage: 

```
serverless deploy
```

See the [Serverless AWS Guide](https://serverless.com/framework/docs/providers/aws/guide/) for more workflow details.

# Deployment

There are three automatically-deployed stages: `qa`, `staging` and `prod`.

1. Travis CI deploys the `qa` branch to the `qa` environment on every commit to `qa`.

2. Travis CI deploys the `master` branch to the `staging` environment on every commit to `master`.

3. Travis CI deploys new GitHub tags/releases to the `prod` stage as they are created and pushed.
```
# switch to master branch
git checkout master

# get list of tags ordered by date
git for-each-ref --sort=creatordate --format '%(refname) %(creatordate) %(subject)' refs/tags

# create a new tag
git tag -a v1.0.0 -m "description of release"

# this push to GitHub will cause the deployment to 'prod' to begin 
git push origin v1.0.0 
```

Deployment notifications for all stages will appear in the `#releases-announce` Slack channel.

Travis CI uses the `ci-lambda` role user in our AWS account.

# Release Management

- Perform local development on a feature branch, deploying it manually to the `dev` stage as needed.
- PR your feature branch into the `qa` branch and receive merge approval. Merge to `qa` to automatically deploy the `qa` stage.
- Upon QA's approval, merge `qa` branch into `master` to automatically deploy the `staging` stage.
- Create a GitHub Release via the UI, incrementing the version number by one from the last-used tag. The `prod` stage will automatically deploy.

If needed, you can manually deploy to any named stage:

```
serverless deploy --stage [stage]
```
