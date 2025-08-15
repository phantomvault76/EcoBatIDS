#!/bin/bash
# EcoBat IDS Installation Script

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "Installing dependencies..."
apt-get install -y \
  postgresql \
  redis-server \
  libpcap-dev \
  libpq-dev \
  perl \
  cpanminus \
  build-essential \
  libssl-dev \
  libmojolicious-perl \
  libjson-perl \
  libdbd-pg-perl \
  libredis-perl \
  libnet-pcap-perl \
  libnetpacket-perl \
  libsys-syslog-perl

# Setup PostgreSQL
echo "Setting up PostgreSQL..."
sudo -u postgres psql -c "CREATE DATABASE ecobat;"
sudo -u postgres psql -c "CREATE USER ecobat WITH PASSWORD 'db-p@ssw0rd';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ecobat TO ecobat;"

# Import database schema
echo "Importing database schema..."
sudo -u ecobat psql -d ecobat -f db.sql

# Configure Redis
echo "Configuring Redis..."
bash redis.sh

# Create system user for ecobat
echo "Creating ecobat system user..."
useradd -r -s /bin/false ecobat
mkdir -p /opt/ecobat/{bin,logs}
chown -R ecobat:ecobat /opt/ecobat

# Install Perl modules
echo "Installing Perl modules..."
cpanm -n \
  Mojo::UserAgent \
  JSON::MaybeXS \
  Sys::Hostname \
  Sys::Syslog \
  Time::HiRes \
  POSIX \
  Redis \
  DBI \
  DBD::Pg

# Copy files
echo "Copying application files..."
cp ecobat.pl /opt/ecobat/bin/
cp server.pl /opt/ecobat/bin/
chmod +x /opt/ecobat/bin/*.pl

# Create systemd services
echo "Creating systemd services..."
cat > /etc/systemd/system/ecobat.service <<EOL
[Unit]
Description=EcoBat IDS Capture Node
After=network.target postgresql.service redis-server.service

[Service]
User=ecobat
Group=ecobat
WorkingDirectory=/opt/ecobat
ExecStart=/opt/ecobat/bin/ecobat.pl
Restart=always
Environment="ECOBAT_SERVER=http://localhost:8080/api"
Environment="ECOBAT_CLUSTER_KEY=s3cr3t-clust3r-k3y"
Environment="ECOBAT_IFACE=eth0"

[Install]
WantedBy=multi-user.target
EOL

cat > /etc/systemd/system/ecobat-server.service <<EOL
[Unit]
Description=EcoBat IDS Server
After=network.target postgresql.service redis-server.service

[Service]
User=ecobat
Group=ecobat
WorkingDirectory=/opt/ecobat
ExecStart=/opt/ecobat/bin/server.pl
Restart=always
Environment="ECOBAT_DSN=dbi:Pg:dbname=ecobat;host=localhost"
Environment="ECOBAT_DBUSER=ecobat"
Environment="ECOBAT_DBPASS=db-p@ssw0rd"
Environment="ECOBAT_REDIS=127.0.0.1:6379"
Environment="ECOBAT_CLUSTER_KEY=s3cr3t-clust3r-k3y"

[Install]
WantedBy=multi-user.target
EOL

# Enable and start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable ecobat.service ecobat-server.service
systemctl start ecobat.service ecobat-server.service

echo "Installation complete!"
echo "EcoBat IDS is now running."
echo "Dashboard: http://localhost:8080/dashboard"