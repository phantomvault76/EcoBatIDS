#!/bin/bash
# EcoBat IDS Run Script

# Start Redis
redis-server --daemonize yes

# Start PostgreSQL
sudo service postgresql start

# Start EcoBat Server
perl /opt/ecobat/bin/server.pl &

# Start EcoBat Capture Node
perl /opt/ecobat/bin/ecobat.pl &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?