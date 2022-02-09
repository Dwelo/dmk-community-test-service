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
