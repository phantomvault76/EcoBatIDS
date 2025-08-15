requires 'Net::PcapUtils';
requires 'NetPacket::Ethernet';
requires 'NetPacket::IP';
requires 'NetPacket::TCP';
requires 'Data::HexDump';
requires 'Net::Traceroute';

# Para os nós
sudo cpanm Geo::IP Mojo::UserAgent Digest::MD5

# Para o servidor
sudo cpanm Mojolicious DBI DBD::Pg Redis JSON::XS Compress::Zlib