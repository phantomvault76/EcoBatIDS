#!/usr/bin/perl
use strict;
use warnings;

use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;
use Mojo::UserAgent;
use JSON::MaybeXS qw(encode_json decode_json);
use Sys::Hostname qw(hostname);
use Sys::Syslog;
use POSIX qw(strftime);
use Time::HiRes qw(gettimeofday);
use Sys::Hostname 'hostname';

# =========================
# Configuration Constants
# =========================
use constant {
    SYN_FLAG => 0x02,
    ACK_FLAG => 0x10,
    RST_FLAG => 0x04,
    FIN_FLAG => 0x01,
};

# =========================
# Global Configuration
# =========================
my $config = {
    node_id            => generate_node_id(),
    interface          => $ENV{ECOBAT_IFACE} // 'eth0',
    snaplen            => 65535,
    promisc            => 1,  # Promiscuous mode
    to_ms              => 1000,
    batch_size         => 100,
    send_interval_s    => 2,
    heartbeat_interval => 15,
    max_retries        => 3,
    central_server     => $ENV{ECOBAT_SERVER} // 'http://localhost:8080/api',
    cluster_key        => $ENV{ECOBAT_CLUSTER_KEY} // 's3cr3t-clust3r-k3y',

    # Threat detection thresholds
    syn_flood_threshold   => 50,
    port_scan_threshold   => 20,
    icmp_flood_threshold  => 100,
    dns_tunnel_suspect    => 512,
};

# =========================
# Global State
# =========================
my @packet_buffer;
my %local_stats = (
    protocols => {},
    threats   => {
        syn_flood    => {},
        port_scans   => {},
        icmp_floods  => {},
        dns_tunnels  => 0,
        weird_traffic => 0,
    },
);

my $last_send      = time;
my $last_heartbeat = 0;
my $pcap;  # Will hold our pcap object
my $node_id = $ENV{ECOBAT_NODE_ID} // stable_node_id();
# =========================
# Main Execution
# =========================
init_system();
run_capture_loop();

# =========================
# Core Functions
# =========================


sub init_system {
    openlog('ecobat_ids', 'ndelay,pid', 'local3');
    
    # Initialize network capture
    my $err;
    $pcap = Net::Pcap::open_live($config->{interface}, $config->{snaplen}, 
                               $config->{promisc}, $config->{to_ms}, \$err)
        or die "Failed to open interface $config->{interface}: $err";

    # Register with central server
    unless (register_with_central()) {
        die "Failed to register with central server after retries";
    }

    # Apply initial network filter
    apply_network_filter();
}

sub stable_node_id {
  my $id = eval {
    my $m = `cat /etc/machine-id`; chomp $m; $m;   # Linux
  } || hostname();
  $id =~ s/[^A-Za-z0-9_-]/_/g;
  return $id;
}

sub run_capture_loop {
    syslog('info', "Starting capture loop on $config->{interface}");
    Net::Pcap::loop($pcap, -1, \&process_packet, '');
    Net::Pcap::close($pcap);
    closelog();
}

sub process_packet {
    my ($user_data, $hdr, $pkt) = @_;

    my $eth = NetPacket::Ethernet->decode($pkt);
    return unless $eth && $eth->{type} == NetPacket::Ethernet::ETH_TYPE_IP;

    my $ip = NetPacket::IP->decode($eth->{data});
    return unless $ip;

    my ($src_ip, $dst_ip, $proto) = ($ip->{src_ip}, $ip->{dest_ip}, $ip->{proto});
    my $now = time;

    # Threat analysis
    analyze_threats($ip, $src_ip, $proto);

    # Store packet for sending
    store_packet($src_ip, $dst_ip, $proto, $ip->{len}, $now);

    # Send packets if needed
    check_send_packets($now);

    # Send heartbeat if needed
    check_heartbeat($now);
}

# =========================
# Threat Detection Functions
# =========================
sub analyze_threats {
    my ($ip, $src_ip, $proto) = @_;
    
    eval {
        if ($proto == 6) {  # TCP
            my $tcp = NetPacket::TCP->decode($ip->{data});
            if ($tcp) {
                detect_syn_flood($src_ip, $tcp);
                detect_port_scan($src_ip, $tcp->{dest_port});
                detect_weird_tcp($src_ip, $tcp);
            }
        }
        elsif ($proto == 17) {  # UDP
            my $udp = NetPacket::UDP->decode($ip->{data});
            detect_dns_tunnel($src_ip, $udp) if $udp && ($udp->{dest_port} == 53 || $udp->{src_port} == 53);
        }
        elsif ($proto == 1) {  # ICMP
            detect_icmp_flood($src_ip);
        }
    };
    syslog('warning', "Threat analysis error: $@") if $@;
}

sub detect_syn_flood {
    my ($src_ip, $tcp) = @_;
    if (($tcp->{flags} & SYN_FLAG) && !($tcp->{flags} & ACK_FLAG)) {
        $local_stats{threats}{syn_flood}{$src_ip}++;
        if ($local_stats{threats}{syn_flood}{$src_ip} >= $config->{syn_flood_threshold}) {
            syslog('warning', "SYN Flood detected from $src_ip (" 
                  . $local_stats{threats}{syn_flood}{$src_ip} . " SYN packets/s)");
            $local_stats{threats}{syn_flood}{$src_ip} = 0;
        }
    }
}

sub detect_port_scan {
    my ($src_ip, $dst_port) = @_;
    $local_stats{threats}{port_scans}{$src_ip}{ports}{$dst_port} = time;
    
    my $now = time;
    my $unique_ports = 0;
    for my $port (keys %{$local_stats{threats}{port_scans}{$src_ip}{ports}}) {
        $unique_ports++ if ($now - $local_stats{threats}{port_scans}{$src_ip}{ports}{$port} <= 5);
    }

    if ($unique_ports >= $config->{port_scan_threshold}) {
        syslog('warning', "Port Scan detected from $src_ip ($unique_ports ports in 5s)");
        delete $local_stats{threats}{port_scans}{$src_ip};
    }
}

sub detect_icmp_flood {
    my ($src_ip) = @_;
    $local_stats{threats}{icmp_floods}{$src_ip}++;
    if ($local_stats{threats}{icmp_floods}{$src_ip} >= $config->{icmp_flood_threshold}) {
        syslog('warning', "ICMP Flood detected from $src_ip (" 
              . $local_stats{threats}{icmp_floods}{$src_ip} . " packets/s)");
        $local_stats{threats}{icmp_floods}{$src_ip} = 0;
    }
}

sub detect_dns_tunnel {
    my ($src_ip, $udp) = @_;
    if ($udp->{len} > $config->{dns_tunnel_suspect}) {
        $local_stats{threats}{dns_tunnels}++;
        syslog('warning', "Suspicious DNS tunneling from $src_ip (size: " . $udp->{len} . " bytes)");
    }
}

sub detect_weird_tcp {
    my ($src_ip, $tcp) = @_;
    if ($tcp->{flags} == 0) {
        syslog('notice', "Weird TCP packet from $src_ip (NULL flags)");
        $local_stats{threats}{weird_traffic}++;
    }
    elsif (($tcp->{flags} & FIN_FLAG) && ($tcp->{flags} & 0x28)) {
        syslog('warning', "Possible XMAS attack from $src_ip");
    }
}

# =========================
# Network Functions
# =========================
sub apply_network_filter {
    my $range = get_network_range() || '0.0.0.0/0';
    
    eval {
        Net::Pcap::compile($pcap, \my $filter, "net $range", 0, 0) 
            or die "BPF compile error: $!";
        Net::Pcap::setfilter($pcap, $filter);
        syslog('info', "Applied network filter: $range");
        1;
    } or do {
        syslog('err', "Failed to set BPF filter: $@");
        # Continue without filter rather than dying
    };
}

sub get_network_range {
    my $ua = Mojo::UserAgent->new(request_timeout => 3);
    my $tx = eval { $ua->get("$config->{central_server}/network_range") };
    
    if ($@) {
        syslog('warning', "Network range request failed: $@");
        return undef;
    }
    
    if ($tx->result && $tx->result->is_success) {
        return $tx->result->json->{range};
    }
    
    syslog('warning', "Failed to get network range: " . ($tx->error ? $tx->error->{message} : 'Unknown'));
    return undef;
}

# =========================
# Communication Functions
# =========================
sub register_with_central {
    my $retries = 3;
    while ($retries--) {
        my $ua = Mojo::UserAgent->new(request_timeout => 5);
        my $tx = eval {
            $ua->post(
                "$config->{central_server}/register" => json => {
                    node_id => $config->{node_id},
                    host    => hostname(),
                    key     => $config->{cluster_key},
                }
            );
        };
        
        if ($@) {
            syslog('warning', "Registration error: $@. Retries left: $retries");
            sleep 2;
            next;
        }
        
        if ($tx->result && $tx->result->is_success) {
            syslog('info', "Successfully registered with central server");
            return 1;
        }
        
        syslog('warning', "Registration failed: " . ($tx->error ? $tx->error->{message} : 'Unknown'));
        sleep 2;
    }
    
    return 0;
}

sub send_to_central {
    my ($packets) = @_;
    return unless @$packets;

    my $ua = Mojo::UserAgent->new(request_timeout => 5);
    my $tx = eval {
        $ua->post(
            "$config->{central_server}/packets" => json => {
                packets => $packets,
                node_id => $config->{node_id},
                key     => $config->{cluster_key},
                stats   => \%local_stats,
            }
        );
    };
    
    if ($@) {
        syslog('err', "Packet send error: $@");
        return 0;
    }
    
    unless ($tx->result && $tx->result->is_success) {
        syslog('err', "Failed to send packets: " . ($tx->error ? $tx->error->{message} : 'Unknown'));
        return 0;
    }
    
    return 1;
}

sub send_heartbeat {
    my $ua = Mojo::UserAgent->new(request_timeout => 5);
    my $tx = eval {
        $ua->post(
            "$config->{central_server}/heartbeat" => json => {
                node_id => $config->{node_id},
                key     => $config->{cluster_key},
            }
        );
    };
    
    if ($@) {
        syslog('warning', "Heartbeat error: $@");
        return;
    }
    
    unless ($tx->result && $tx->result->is_success) {
        syslog('warning', "Heartbeat failed: " . ($tx->error ? $tx->error->{message} : 'Unknown'));
    }
}

# =========================
# Utility Functions
# =========================
sub store_packet {
    my ($src_ip, $dst_ip, $proto, $len, $now) = @_;
    
    push @packet_buffer, {
        timestamp => strftime("%Y-%m-%dT%H:%M:%S", gmtime($now)) . sprintf(".%03dZ", (gettimeofday)[1] / 1000),
        src_ip    => $src_ip,
        dst_ip    => $dst_ip,
        protocol  => ($proto == 6 ? 'TCP' : $proto == 17 ? 'UDP' : $proto == 1 ? 'ICMP' : $proto),
        length    => $len || 0,
    };
}

sub check_send_packets {
    my ($now) = @_;
    
    if (@packet_buffer >= $config->{batch_size} || 
        ($now - $last_send) >= $config->{send_interval_s}) {
        if (send_to_central(\@packet_buffer)) {
            @packet_buffer = ();
            $last_send = $now;
        }
    }
}

sub check_heartbeat {
    my ($now) = @_;
    
    if (($now - $last_heartbeat) >= $config->{heartbeat_interval}) {
        send_heartbeat();
        $last_heartbeat = $now;
    }
}

sub generate_node_id {
    my @chars = ('a'..'z', 0..9);
    join '', map { $chars[rand @chars] } 1..8;
}

END {
    if ($pcap) {
        Net::Pcap::close($pcap);
    }
    closelog();
}