#!/usr/bin/perl -w
# kindhcpd ver 0.1
use FindBin qw($Bin);
use lib $Bin;

use utf8;
use strict;
use Socket;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use POSIX qw(setsid strftime);
use IO::Socket::INET;
use IO::Interface qw(:flags);
use IO::Interface::Simple;
use IO::Select;
use Encode;

use Sys::Syslog qw(:DEFAULT setlogsock);
use Getopt::Long qw/GetOptions/;
use Storable qw(freeze thaw);

use constant PROGNAME => 'kindhcpd';
use constant VERSION => '0.4';

use DHCPUtils;
use DHCPLeases;
use DHCPPlugin;

use Data::Dumper;
use constant {
    SERVER_PORT => 67,
    CLIENT_PORT => 68
};

use vars qw($cfg $DBG $oplugin);

my $config = {
	foreground	=> 0,
	debug		=> 0,
	port		=> SERVER_PORT,
	config		=> 'kindhcpd.conf',
	pid			=> '/var/run/kindhcpd.pid',
	leases		=> '/tmp/kindhcpd.leases'
};

my $time_to_die = 0;
my $ADDR_BCAST;

#####################################################
#
#                 Subroutines
#
#####################################################
sub signal_handler {
    $time_to_die = 1;
}

sub logger($)
{
    my $msg = encode("utf-8",$_[0]);
	if($config->{foreground}) {
		print STDOUT strftime "[%d/%m/%Y %H:%M:%S] ", localtime;
		print STDOUT $msg, "\n";
	}
	else {
		syslog('info', $msg);
	}
	return 1;
}

sub checkpid($)
{
    my $pidfile = shift;
    if(-e $pidfile) {
        unless(open(F,$pidfile)) {
            logger("Can't open pidfile $pidfile");
            return 0;
        }
        my $oldpid = <F>;
        close F;
        chomp $oldpid;
        if($oldpid>0 && kill(0,$oldpid)) {
            logger("Process already start! Pid = $oldpid");
            return 0;
        }
		unlink($pidfile);
        logger("Remove stale pidfile $pidfile");
    }
	return 1;
}

sub createpid($)
{
    my $pidfile = shift;
	return 0 unless(checkpid($pidfile));
    unless(open(F,">$pidfile")) {
        logger("Can't create pidfile $pidfile");
        return 0;
    }
    print F $$;
    close F;
    return 1;
}

sub clearpid($)
{
    my ($pidfile) = @_;
    logger("Can't remove self pidfile $pidfile!\n") unless(unlink $pidfile);
}

sub create_lease($$$)
{
	my ($hip,$type,$leases) = @_;
	my $l = DHCPLeases::lease_create($hip,$type);
	if($leases->{$hip}) {
		DHCPLeases::lease_loadstate($l,$leases->{$hip});
		delete $leases->{$hip};
	}
	return $l;
}

sub create_range($$$)
{
	my ($start,$stop,$leases) = @_;
	return undef,'Start IP: Expected IP addres or FQDN' unless($start =~ /^([\w\.-]+)/);
	my $ip1 = gethostbyname($1);
	return undef,"Cant get ip address for $1" unless(defined $ip1);
	$ip1 = unpack("N",$ip1);
	return undef,'End IP: Expected IP addres or FQDN' unless($stop =~ /^([\w\.-]+)/);
	my $ip2 = gethostbyname($1);
	$ip2 = unpack("N",$ip2);
	return undef,"Cant get ip address for $1" unless(defined $ip2);
	my (@range,$ip);
	($ip2,$ip1) = ($ip1,$ip2) if($ip1>$ip2);
	for($ip=$ip1;$ip<=$ip2;$ip++) {
		my $l = create_lease(ntoh($ip),1,$leases);
		push @range,$l if($l);
	}
	return \@range,undef;
}

sub load_leases {
	my ($config) = @_;
	# load leases
	my $leases = {};
	my $fname = $config->{leases};
	$fname .= '~' unless(-e $fname);
	if(-e $fname) {
		my $pid = open(FOO, '-|');
		return undef,"Cannot fork!" unless(defined $pid);
		if($pid) {
			# parent
			my $r = '';
			$r.=$_ while(<FOO>);
			close FOO;
			my $a = thaw $r;
			wait();
			return $a->[0],$a->[1] if($a->[1]);
			$leases = $a->[0];
		}
		else {
			#child
			my $r;
			if(open F,$fname) {
				my $s = '';
				$s .= $_ while(<F>);
				close F;
				require DHCPConfig;
				my $e = DHCPConfig::dhcp_lease_parse($s,$leases,$fname);
				if($e) {
					print freeze([undef,$e]);
					exit(1);
				}
				print freeze([$leases,$e]);
				exit 0;
			}
			else {
				print freeze([undef,"Can't open file $fname! $!"]);
				exit(1);	
			}
		}
	}
    return $leases, undef;
}

sub load_config($)
{
	my ($config) = @_;
	# load config
	my $conf = {
		'log-facility'      => 'local6',
		'local-port'        => $config->{port},
		'pid-file-name'     => $config->{pid}
	};

	my $pid = open(FOO, '-|');
	return undef,"Cannot fork!" unless(defined $pid);
	if($pid) {
		# parent
		my $r = '';
		$r.=$_ while(<FOO>);
		close FOO;
		my $a = thaw $r;
		wait();
		return $a->[0],$a->[1] if($a->[1]);
		my $cf = $a->[0];
		return $cf,undef;
	}
	else {
		#child
		my $file = $config->{config};
		my $r;
		if(open F,$file) {
			my $s = '';
			$s .= $_ while(<F>);
			close F;
			require DHCPConfig;
			DHCPConfig::add_config_words(DHCPPlugin::get_config_words());
			my $e = DHCPConfig::dhcp_config_parse($s,$conf,'G',$file);
			if($e) {
				print freeze([undef,$e]);
				exit(1);
			}
			print freeze([$conf,$e]);
			exit 0;
		}
		else {
			print freeze([undef,"Can't open file $file! $!"]);
		    exit(1);	
		}
	}
}

sub create_config_leases {
    my ($cf, $leases) = @_;
    # subnet create leases pools and hosts
    for my $sn (values %{$cf->{'subnets'}}) {
        if($sn->{'ranges'}) {
            for my $r (@{$sn->{'ranges'}}) {
                my ($rl,$e) = create_range($r->[0],$r->[1],$leases);
                logger($e), die if($e);
                push @{$sn->{'pool'}},@$rl;
            }
        }
        if($sn->{'hosts'}) {
            for my $r (values %{$sn->{'hosts'}}) {
                my $ip = $r->{'fixed-address'} || $r->{'host'};
                $ip = atoh($ip);
                my $l = create_lease($ip,0,$leases);
                logger("Can't create lease for host ".htoa($ip)),next unless($l);
                $r->{'lease'} = $l;
                $sn->{'hosts_hw'}->{$r->{'hardware'}} = $r if($r->{'hardware'});
                $sn->{'hosts_ip'}->{$r->{'host'}} = $r;
            }
        }
    }
    # global hosts entries
    if($cf->{'hosts'}) {
        for my $r (values %{$cf->{'hosts'}}) {
            my $ip = $r->{'fixed-address'} || $r->{'host'};
            $ip = atoh($ip);
            my $l = create_lease($ip,0,$leases);
            logger("Can't create lease for host ".htoa($ip)),next unless($l);
            $r->{'lease'} = $l;
            $cf->{'hosts_hw'}->{$r->{'hardware'}} = $r if($r->{'hardware'});
            $cf->{'hosts_ip'}->{$r->{'host'}} = $r;
        }
    }
    my $t = time();
    for (keys %$leases) {
        next if($leases->{$_}->{ends}<$t);
        create_lease($_,1,$leases);
    }
    return $cf;
}

sub gendhcppkt
{
	my ($dhcpreq) = @_;
	my $dhcpresp = new Net::DHCP::Packet(
		Op       => BOOTREPLY(),
		Htype    => $dhcpreq->htype(),
		Hlen     => $dhcpreq->hlen(),
		Hops     => 0, # - not copyed in responce
		Xid      => $dhcpreq->xid(),
		Secs     => $dhcpreq->secs(),
		Flags    => $dhcpreq->flags(),
		Ciaddr   => $dhcpreq->ciaddr(),
		#Yiaddr => '0.0.0.0',
		Siaddr   => $dhcpreq->siaddr(),
		Giaddr   => $dhcpreq->giaddr(),
		Chaddr   => $dhcpreq->chaddr(),
		Sname    => $cfg->{'server-name'},
		File     => '',
		DHO_DHCP_MESSAGE_TYPE() => DHCPACK, # must be owerwritten
	);
	return $dhcpresp;
}

sub send_reply
{
	my ($sock,$fromaddr,$dhcpreq,$dhcpresp) = @_;
	my ($dhcpresppkt, $toaddr);

	# add last!!!!
	$dhcpresp->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()))
		if (defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())));

	$dhcpresppkt = $dhcpresp->serialize();

	if ($dhcpreq->giaddr() eq '0.0.0.0') {
		# client local, not relayed
		if($dhcpresp->DHO_DHCP_MESSAGE_TYPE() == DHCPNAK) {# allways broadcast DHCPNAK
			$toaddr = $ADDR_BCAST;
		}
		else {
			if ($dhcpreq->ciaddr() eq '0.0.0.0') {
				# ALL HERE NON RFC 2131 4.1 COMPLIANT!!!
				# perl can not send to hw addr unicaset with ip 0.0.0.0, and we send broadcast
				if ($dhcpreq->flags() == 0 || 1) {# send unicast XXXXXXXXX - flags ignored!
					# here we mast send unicast to hw addr, ip 0.0.0.0
					my ($port,$addr) = unpack_sockaddr_in($fromaddr);
					my $ipaddr = inet_ntoa($addr);
					if ($ipaddr eq '0.0.0.0') {
						$toaddr = $ADDR_BCAST;
					}else{# giaddr and ciaddr is zero but we know ip addr from received packet
						# Pull the ip that the packet came from
						$toaddr = sockaddr_in(CLIENT_PORT, $addr);
					}
				}
				else{
					# only this comliant to rfc 2131 4.1
					$toaddr = $ADDR_BCAST;
				}
			}
			else{# client have IP addr, send unicast
				$toaddr = sockaddr_in(CLIENT_PORT, $dhcpreq->ciaddrRaw());
			}
		}
	}
	else{# send to relay
		$toaddr = sockaddr_in(SERVER_PORT, $dhcpreq->giaddrRaw());
	}
	send($sock, $dhcpresppkt, 0, $toaddr) || logger("send error: $!");

	if ($DBG>=2) {
		my ($port, $addr) = unpack_sockaddr_in($toaddr);
		my $ipaddr = inet_ntoa($addr);
		logger("Sending response to = $ipaddr:$port length = ".length($dhcpresppkt)) if($DBG>=2);
		logger($dhcpresp->toString()) if($DBG>=10);
	}
}

sub hostname($)
{
	my $hn = $_[0]->getOptionValue(DHO_HOST_NAME);
	return '' unless($hn);
    my $hn2 = decode("cp866",$hn);
	$hn =~ s/[[:^print:]]/?/g;
	return ' ('.$hn2.')';
}

sub via($)
{
	my $gw = $_[0]->giaddr();
	return '' if($gw eq '0.0.0.0');
	my $r = ' via '.$gw;
	my $h = getrelayagentoptions($_[0]);
	return $r unless($h);
	$r .= sprintf(" (port=%d/%d vlan=%d id=%s)",$h->{CircuitID}->{unit},$h->{CircuitID}->{port},$h->{CircuitID}->{vlan},$h->{RemoteID});
	return $r;
}

#####################################################
#
#                Main programm
#
#####################################################

my $usage = <<EOF;
Usage: $0 [options] [interface ...]
KinNet DHCP daemon, for assign users ip
    -?,  --help               show this help
    -d,  --debug=level        set debug level
    -f,  --foreground         run as a foreground process
    -p,  --port=number        set listen port (default: $config->{port})
    -cf, --config=filename    set config filename (default: $config->{config})
    -pf, --pid=filename       set file for store process pid (default: $config->{pid})
    -lf, --leases=filename    set file for store leases (default: $config->{leases})
EOF

# Get command string options
Getopt::Long::Configure(qw/no_ignore_case/);
GetOptions($config, qw/
	help|?
	debug|d:1
	foreground|f
	port|p=i
	config|cf=s
	pid|pf=s
	leases|lf=s
/) || die $usage;
do { print $usage; exit; } if($config->{help});
$DBG = $config->{debug};


my ($e,$leases);
($leases, $e) = load_leases($config);
die 'Error: '.$e if($e);

($cfg,$e) = load_config($config);
die 'Error: '.$e if($e);

my (@iflist,%ifaces,%sockets);
if(@ARGV) {
# Get interfaces list
	my @interfaces = IO::Interface::Simple->interfaces;
	die "No interfaces found!\n" unless(@interfaces);
	%ifaces = map { $_->name => $_ } @interfaces;
	for (@ARGV) {
		if($ifaces{$_}) {
			push @iflist,$_;
		}
		else {
			warn "Interface $_ don't exists! Skip\n";
		}
	}
	die "No active interfaces!\n" unless(@iflist);
}

die "Only root can start ".PROGNAME."!\n" if($>);
die "\n" unless checkpid($cfg->{'pid-file-name'});

# Logger
setlogsock('unix');
openlog(PROGNAME,'',$cfg->{'log-facility'});

# Tell the world we're here
logger('Starting '.PROGNAME.' v'.VERSION);

# Create a scalar to hold the process id
my $pid;

# If daemon is set, run in daemon mode
unless($config->{foreground}) {
	logger('Entering Daemon mode');
	chdir '/'                 or die "Can't chdir to /: $!";
	umask 0;

	open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
	open STDOUT, '>/dev/null' or die "Can't write to /dev/null: $!";
	open STDERR, '>/dev/null' or die "Can't write to /dev/null: $!";

	# Try and fork
	$pid = fork();
	# If the child has spawned exit			
	exit if ($pid);

	# All the post fork stuff
	POSIX::setsid() || die "Can't start a new session: $!";
	logger('Now in Daemon mode');
}

$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
$SIG{PIPE} = 'IGNORE';
unless($config->{foreground}) {
    $SIG{__WARN__} = sub { logger("warn(". join('',@_). ")") };
}
die "\n" unless createpid($cfg->{'pid-file-name'});

$oplugin = DHCPPlugin->new($cfg);
if($oplugin->{error}) {
	logger("Plugin initialisation error: ".$oplugin->{error});
	exit(1);
}

$e = $oplugin->load_config($cfg);
if($e) {
	logger("Plugin config error: ".$e);
	exit(1);
}

$cfg = create_config_leases($cfg, $leases);

my $select = IO::Select->new();

for my $if (@iflist) {
	my $sock = IO::Socket::INET->new(	
			LocalPort => $cfg->{'local-port'},
			Proto     => 'udp',
			Reuse     => 1,
			Broadcast => 1,
		) || ( logger("In socket creation error: $@"), die );

	# Bind to an interface and set the netid and iface scalars
	$sock->sockopt('25', pack('Z*', $if));
	$select->add($sock);
	$sockets{$sock} = { ip=>atoh($ifaces{$if}->address), mode=>'interface'};
}

if($cfg->{'local-address'}) {
	for my $ip (@{$cfg->{'local-address'}}) {
		my $sock = IO::Socket::INET->new(
			LocalAddr => $ip,
			LocalPort => $cfg->{'local-port'},
			Proto     => 'udp',
			Reuse     => 1
		) || (logger("In socket creation error: $@"), next);
		$select->add($sock);
		$sockets{$sock} = { ip=>atoh($ip), mode=>'ip'};
	}
}

unless($select->handles) {
	logger("Nothing to listen!");
	exit(1);
}


$ADDR_BCAST = sockaddr_in(CLIENT_PORT, INADDR_BROADCAST);
# Main loop
my @ready;
my %limits;
until($time_to_die) {
	@ready = $select->can_read(0.5);
    unless (@ready) {
        my $t = time();
        while (my ($k,$v) = each %limits) {
            delete $limits{$k} if ($v->{'time'} && $v->{'time'} < $t);
        }
        next;
    }
	for my $sock (@ready) {
		# Catch fatal errors
		eval {{
			my $buf = "";

			# Receive packet
			my $fromaddr = $sock->recv($buf, 16384) || logger("recv:$!");			

			# Continue only if an error didn't happen
			next if($!);
			next if (length($buf) < 260);

			# Pull the ip that the packet came from
			my ($port,$addr) = unpack_sockaddr_in($fromaddr);

			# Create the DHCP packet object from the recieved packet
			my $dhcpreq = new Net::DHCP::Packet($buf);						 	

			# Find out what the packet was asking for and run the sub for it.	
			next if ($dhcpreq->op() != BOOTREQUEST || $dhcpreq->isDhcp() == 0);
			next if ($dhcpreq->htype() != HTYPE_ETHER || $dhcpreq->hlen() != 6);
            if ($cfg->{'client-ratelimit'}) {
                my $climac = $dhcpreq->chaddr();
                if ($limits{$climac}->{'time'} && $limits{$climac}->{'time'} == time()) {
                    if (++$limits{$climac}->{'cnt'} > $cfg->{'client-ratelimit'}) {
                        logger('Limit packet rate from '.formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq))
                            if ($limits{$climac}->{'cnt'} == $cfg->{'client-ratelimit'}+1);
                        last;
                    }
                }
                else {
                    $limits{$climac} = { time => time(), cnt => 1 };
                }
            }

			logger($dhcpreq->toString()) if($DBG>=10);

			my $messtype = $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
			# handle packet
			if($messtype == DHCPDISCOVER) { #-> DHCPOFFER
				handle_discover($sock, $fromaddr, $dhcpreq);
			}
			elsif($messtype == DHCPREQUEST) { #-> DHCPACK/DHCPNAK
				handle_request($sock, $fromaddr, $dhcpreq);
			}
			elsif($messtype == DHCPDECLINE) {
				handle_decline($sock, $fromaddr, $dhcpreq);
			}
			elsif($messtype == DHCPRELEASE) {
				handle_release($sock, $fromaddr, $dhcpreq);
			}
			elsif($messtype == DHCPINFORM) { #-> DHCPACK
				handle_inform($sock, $fromaddr, $dhcpreq);
			}
			else {
				logger("Bad packet recieved:".$dhcpreq->toString()) if($DBG>=1);
			}
		}};

		# If an error was created in the eval loop print that error
		if ($@ && !$time_to_die) {
			logger("Caught error in main loop:$@");
		}
	}
}

my $fname = $config->{leases};
if($fname) {
	rename($fname,$fname.'~') if(-e $fname);
	my $r = DHCPLeases::save_leases($fname);
	logger($r) if($r);
}

# Goodbye
logger('Exiting '.PROGNAME.' v'.VERSION);

# Clean select list and close sockets
for ($select->handles) {
	$select->remove($_);
	$_->close;
}

# Remove pid file
clearpid($cfg->{'pid-file-name'});
exit 0;

sub get_cfgopt($$)
{
	return $_[0]->{$_[1]} || $cfg->{$_[1]};
}


sub set_respoptions
{
	my ($dhcpresp,$dhcpreq,$ipserv,$o,$l,$cf) = @_;
	$dhcpresp->siaddrRaw($ipserv);
	$dhcpresp->addOptionRaw(DHO_DHCP_SERVER_IDENTIFIER,$ipserv);
	my $dhcpreqparams = $dhcpreq->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());
	$dhcpresp->yiaddrRaw($l->{ipaddr});
    my $hostname = gethostbyaddr($l->{ipaddr}, AF_INET);
    $o->{12} = $hostname if($hostname);
	my $ltime = get_cfgopt($cf,'default-lease-time') || 86400;
	$dhcpresp->addOptionValue(DHO_DHCP_LEASE_TIME(), $ltime);
	return unless($dhcpreqparams);
	for (split / /,$dhcpreqparams) {
		next unless(defined $o->{$_});
		$dhcpresp->addOptionRaw($_,$o->{$_});
	}
}

sub find_lease
{
	my ($ip,$hw,$dhcpreq) = @_;
	my (%o,%lcfg,$l,$subnet,$pip);
	%o = %{$cfg->{option}} if($cfg->{option});
	$hw = substr($hw,0,6);
	my $r = $oplugin->get_lease($ip,$hw,$dhcpreq);
	return undef unless($r); # plugin error
	# no answer if return empty ip
	if(exists($r->{ip}) && !$r->{ip}) {
		logger("Plugin return empty IP") if($DBG>=5);
		return undef;
	}
	$pip = $r->{ip} if($r->{ip});
	if($pip) {
		if(ref $pip) {
			# if return many ip find free leases or oldes lease in list
			logger("Plugin return IPs (".join(',',@$pip).")") if($DBG>=5);
			for (@$pip) {
				$ip = atoh($_);
				my $ll = DHCPLeases::lease_getbyip($ip);
                if(my $rr = DHCPLeases::lease_check($ll,$hw)) {
                    # find lease with same mac
                    if($rr == 2) {
                        $l = $ll;
                        last;
                    }
                }
				unless($ll) {
					$ll = DHCPLeases::lease_create($ip,0);
				}
				$l = $ll if(!$l || $l->{start} > $ll->{start})
			}
			%o = (%o, %{$r->{option}}) if($r->{option});
			%lcfg = (%lcfg, %{$r->{config}}) if($r->{config});
			if($l) {
				$ip = $l->{ipaddr};
			}
			else {
				$ip = atoh($r->{subnet}) if($r->{subnet});
			}
		}
		else {
			logger("Plugin return IP=$pip") if($DBG>=5);
			$ip = $pip = atoh($pip);
			$l = DHCPLeases::lease_getbyip($pip) || DHCPLeases::lease_create($pip,0);
			%o = (%o, %{$r->{option}}) if($r->{option});
			%lcfg = (%lcfg, %{$r->{config}}) if($r->{config});
		}
	}
	else {
		$ip = atoh($r->{subnet}) if($r->{subnet});
	}
	my $v = $cfg->{hosts_hw}->{$hw};
	if($v) {
		%o = (%o, %{$v->{option}}) if($v->{option});
		%lcfg = (%lcfg,%$v);
		unless($pip) {
			$l = $v->{lease};
			$ip = atoh($v->{'fixed-address'}) if($v->{'fixed-address'});
		}
	}

	if($cfg->{subnets}) {
		for my $k (keys %{$cfg->{subnets}}) {
			next unless(hinsubnet($ip,$k));
			$subnet = $cfg->{subnets}->{$k};
			%o = (%o, %{$subnet->{option}}) if($subnet->{option});
			$v = $subnet->{hosts_hw}->{$hw};
			if($v && !$pip) {
				%o = (%o, %{$v->{option}}) if($v->{option});
				%lcfg = (%lcfg,%$v);
				unless($pip) {
					$l = $v->{lease};
					$ip = atoh($v->{'fixed-address'}) if($v->{'fixed-address'});
				}
			}
			elsif(!$pip) {
				my $ll = DHCPLeases::lease_getfree($subnet->{pool},$hw);
				$l = $ll if($ll);
			}
		}
	}
	return $l,\%o,\%lcfg;
}

sub handle_discover 
{
	my ($sock, $fromaddr, $dhcpreq) = @_;
	my ($dhcpresp);
	my $ip = $sockets{$sock}->{ip};
	my ($port,$addr) = unpack_sockaddr_in($fromaddr);
	$addr = $ip if($addr eq "\0\0\0\0");
	my $hw = substr($dhcpreq->chaddrRaw(),0,6);
	my $s = "DHCPDISCOVER from ".formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
	logger($s);
	my ($lease,$o,$cf) = find_lease($addr,$hw,$dhcpreq);
	unless($lease) {
		logger("Can't find lease for request") if($DBG);
		return;
	}
	$dhcpresp = gendhcppkt($dhcpreq);
	$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C',DHCPOFFER);
   	my $l = DHCPLeases::lease_offer($lease->{ipaddr},substr($dhcpreq->chaddrRaw(),0,6),1);
	if ($l) {
		set_respoptions($dhcpresp,$dhcpreq,$ip,$o,$l,$cf);
		my $s = 'DHCPOFFER on '.htoa($l->{ipaddr}).' to '.formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
		logger($s);
		send_reply($sock, $fromaddr, $dhcpreq, $dhcpresp);
	}
}

sub handle_request 
{
	my ($sock, $fromaddr, $dhcpreq) = @_;
	my ($dhcpresp);
	my $reqip = $dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS()) || $dhcpreq->ciaddrRaw();
	my $ip = $sockets{$sock}->{ip};
	my ($port,$addr) = unpack_sockaddr_in($fromaddr);
	$addr = $ip if($addr eq "\0\0\0\0");
	my $s = "DHCPREQUEST for ".htoa($reqip)." from ".formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
	logger($s);
	my $hw = substr($dhcpreq->chaddrRaw(),0,6);
	my ($lease,$o,$cf) = find_lease($addr,$hw,$dhcpreq);
	unless($lease) {
		logger("Can't find lease for request") if($DBG);
		return;
	}
	$dhcpresp = gendhcppkt($dhcpreq);
	my $ltime = get_cfgopt($cf,'default-lease-time') || 86400;
   	my $l;
   	$l = DHCPLeases::lease_request($reqip,substr($dhcpreq->chaddrRaw(),0,6),$ltime,1) if($lease->{ipaddr} && $lease->{ipaddr} eq $reqip);

	if ($l) {
		set_respoptions($dhcpresp,$dhcpreq,$ip,$o,$l,$cf);
		my $s = 'DHCPACK on '.htoa($l->{ipaddr}).' to '.formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
		logger($s);
		send_reply($sock, $fromaddr, $dhcpreq, $dhcpresp);
	}
	else {
		$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
		my $s = 'DHCPNACK to '.formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
		logger($s);
		send_reply($sock, $fromaddr, $dhcpreq, $dhcpresp);
	}
}

sub handle_release 
{
	my ($sock, $fromaddr, $dhcpreq) = @_;
	my ($dhcpresp);
	my $reqip = $dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS()) || $dhcpreq->ciaddrRaw();
	my $s = "DHCPRELEASE for ".htoa($reqip)." from ".formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
	logger($s);
   	DHCPLeases::lease_release($reqip,substr($dhcpreq->chaddrRaw(),0,6));
}

sub handle_inform 
{
	my ($sock, $fromaddr, $dhcpreq) = @_;
	my ($dhcpresp);
	my $addr = $dhcpreq->ciaddrRaw();
	my $s = "DHCPINFORM from ".htoa($addr).hostname($dhcpreq).via($dhcpreq);
	logger($s);
	my $hw = substr($dhcpreq->chaddrRaw(),0,6);
	my ($lease,$o,$cf) = find_lease($addr,$hw,$dhcpreq);
	return unless($lease);
	$dhcpresp = gendhcppkt($dhcpreq);
	my $ltime = get_cfgopt($cf,'default-lease-time') || 86400;
   	my $l;
    $l = DHCPLeases::lease_inform($addr,substr($dhcpreq->chaddrRaw(),0,6),$ltime) if($lease->{ipaddr} && $lease->{ipaddr} eq $addr);
	if ($l) {
		my $ip = $sockets{$sock}->{ip};
		set_respoptions($dhcpresp,$dhcpreq,$ip,$o,$l,$cf);
		my $s = 'DHCPACK on '.htoa($l->{ipaddr}).' to '.formatmac($dhcpreq->chaddr()).hostname($dhcpreq).via($dhcpreq);
		logger($s);
		send_reply($sock, $fromaddr, $dhcpreq, $dhcpresp);
	}
}

sub handle_decline 
{
	my ($sock, $fromaddr, $dhcpreq) = @_;
	my ($dhcpresp);
	my $reqip = $dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS()) || $dhcpreq->ciaddrRaw();
	my $s = "DHCPDECLINE from ".htoa($reqip).via($dhcpreq);
	logger($s);
}
