package DHCPPlugin;

use strict;
use warnings;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use DHCPUtils;
use DHCPLeases;
use Pg;

use Data::Dumper;

my @gwsub = (
	'0.0.0.0/255.255.255.255' => ['192.168.13.0/24']
);

sub new {
	my $class = shift;
	my ($a) = @_;
	my $self = { config=>$a };
	bless($self, $class);
	my ($r,$e) = connect_base($a);
	if($e) {
		$self->{error} = $e;
	}
	else {
		$self->{db} = $r;
	}
	return $self;
}

sub connect_base
{
	my ($cfg) = @_;
	my ($dbhost,$dbname,$dbuser,$dbpass) = @{$cfg}{qw(dbhost dbname dbuser dbpass)};
	my $sql = Pg::connectdb("host=$dbhost dbname=$dbname user='$dbuser' password='$dbpass'");
	if($sql->status ne PGRES_CONNECTION_OK) {
		return undef,$sql->errorMessage;
	}
	return $sql;
}

sub base_error
{
    my $self = shift;
    return $self->{db}->errorMessage if($self->{db});
    return 'Нет соединения с базой';
}

sub exec_select
{
    my ($self,$q) = @_;
	my $res = $self->{db}->exec($q);
	unless($res->resultStatus eq PGRES_TUPLES_OK) {
		main::logger($self->base_error());
        if($self->{db}->status() != PGRES_CONNECTION_OK) {
            my ($r,$e) = connect_base($self->{config});
            if($e) {
                main::logger($self->base_error());
            }
            else {
                $self->{db} = $r;
            }
        }
		return undef;
	}
    return $res;
}

sub exec_dml
{
    my ($self,$q) = @_;
	my $res = $self->{db}->exec($q);
	unless($res->resultStatus eq PGRES_COMMAND_OK) {
		main::logger($self->base_error());
        if($self->{db}->status() != PGRES_CONNECTION_OK) {
            my ($r,$e) = connect_base($self->{config});
            if($e) {
                main::logger($self->base_error());
            }
            else {
                $self->{db} = $r;
            }
        }
		return undef;
	}
    return $res;
}

sub parse_subnethints($$) {
	my ($ct,$conf) = @_;
	skipspaces($ct);
	return "Expected left curly bracket" unless(getchar($ct) eq '{');
	nextchar($ct);
    my @hints;
    my $c;

	while(!iseof($ct)) {
		skipspaces($ct);
		$c = getchar($ct);
		last if($c eq '}');
		my $w = getipmask($ct);
		return 'Expected ip/mask' unless($w =~ m!^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})!);
		my $k = [ asubnetton($w) ];
        skipspaces($ct);
        return "Expected left curly bracket" unless(getchar($ct) eq '{');
        nextchar($ct);

        my @subs;
        while(!iseof($ct)) {
            skipspaces($ct);
            $c = getchar($ct);
            last if($c eq '}');
            my $n = getipmask($ct);
            return 'Expected ip/mask' unless($n =~ m!^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})!);
            push @subs, [ asubnetton($n) ];
        }
        return "Expected right curly bracket" unless(getchar($ct) eq '}');
        nextchar($ct);
		skipspaces($ct);
        return 'Expected semicolon' unless(getchar($ct) eq ';');
        nextchar($ct);
        return 'No subnets for subnet '.$w unless(@subs);
        push @hints, [ $k, \@subs ];
	}

	return "Expected right curly bracket" unless(getchar($ct) eq '}');
	nextchar($ct);
	nochecksemicolon($ct);
    $conf->{'subnethints'} = \@hints;
	return undef;
}

sub get_config_words
{
	my %cfg = (
		'dbhost'      => { where=>'G', type=>'ip' },
		'dbname'      => { where=>'G', type=>'string' },
		'dbuser'      => { where=>'G', type=>'string' },
		'dbpass'      => { where=>'G', type=>'string' },
        'subnethints' => { where=>'G', type=>'sub',  'sub'=>\&parse_subnethints },
	);
	return \%cfg;
}

sub get_ip_by_mac
{
	my ($self,$mac) = @_;
	$mac = uc $mac;
	my $q = "SELECT ip,mac,vlan FROM net_ips WHERE mac='$mac'";
	my $res = $self->exec_select($q);
	unless($res && $res->resultStatus eq PGRES_TUPLES_OK) {
		main::logger($self->base_error);
		return undef;
	}
	my @r;
	while(my ($ip,$m,$v) = $res->fetchrow()) {
		push @r, {ip=>$ip, mac=>$m, vlan=>$v};
	}
	return \@r;
}

sub get_iplist_by_opt82
{
	my ($self,$agent) = @_;
	my $remid = uc $agent->{RemoteID};
	my ($unit, $port, $vlan) = @{$agent->{CircuitID}}{qw/unit port vlan/};
	my $q = "SELECT port,vlan,unit,ip,mac,account_id FROM net_dhcp WHERE remoteid='$remid'";
	my $res = $self->exec_select($q);
	unless($res && $res->resultStatus eq PGRES_TUPLES_OK) {
		main::logger($self->base_error());
		return undef;
	}
	my @r;
	while(my ($p,$v,$u,$ip,$m,$ac) = $res->fetchrow()) {
		next unless($ip);
		next if(defined($p) && $port != $p);
		next if($v && $vlan != $v);
		next if(defined($u) && defined($unit) && $unit != $u);
		push @r, {port=>$p, vlan=>$v, unit=>$u, ip=>$ip, mac=>$m, accid=>$ac};
	}
	return \@r;
}

sub find_subs_for_ip
{
	my ($self, $ip) = @_;
	$ip = aton($ip);
	my $enasubs = $self->{config}->{subnethints} || [];
	for (@$enasubs) {
		return $_->[2] if(ninsubnet($ip,$_->[0],$_->[1]));
	}
	return;
}

sub filter_iplist
{
	my ($list,$enasubs) = @_;
	return @$list unless($enasubs && @$enasubs);
	my @l;
	for my $r (@$list) {
		my $ipn = aton($r->{ip});
		push @l,$r if(grep {ninsubnet($ipn,$_->[0],$_->[1]) } @$enasubs);
	}
	return @l;
}

sub log_request
{
    my ($self, $giaddr) = @_;
	my $q = "UPDATE net_dhcp_gwiplast SET tstamp = now() WHERE ip='$giaddr'";
	my $res = $self->exec_dml($q);
	unless($res && $res->resultStatus eq PGRES_COMMAND_OK) {
		main::logger($self->base_error());
		return undef;
	}
    return if ($res->cmdTuples);

	$q = "INSERT INTO net_dhcp_gwiplast (ip) VALUES('$giaddr')";
	$res = $self->exec_dml($q);
	unless($res && $res->resultStatus eq PGRES_COMMAND_OK) {
		main::logger($self->base_error());
		return undef;
	}
}

sub get_lease
{
	my ($self,$ip,$hw,$dhcpreq) = @_;
	my $giaddr = $dhcpreq->giaddr();
	my $enasubs = $self->find_subs_for_ip($giaddr);
    $self->log_request($giaddr);
	my $agent = getrelayagentoptions($dhcpreq);
	my (@list,$pip);
	if($agent && $agent->{RemoteID}) {
		my $lst = $self->get_iplist_by_opt82($agent);
		@list = @$lst if($lst && @$lst);
		return {ip=>$list[0]->{ip}} if(@list==1); #short path if get only 1 IP
	}
	unless(@list) {
		my $l = $self->get_ip_by_mac(hexbuf($hw));
		@list = @$l if($l);
		return {ip=>$list[0]->{ip}} if(@list==1); # short path if only 1 IP
	}
	if(@list) {
		return {ip=>$list[0]->{ip}} if(@list==1); #short path if get only 1 IP
		@list = filter_iplist(\@list,$enasubs); #filter IP in not enabled subnets
		return {ip=>$list[0]->{ip}} if(@list==1); #short path if get only 1 IP
		my (@l2,%accs); #list for IP with unknown macs, hash for account ids
		my $hwtxt = hexbuf($hw);
		for (@list) {
			return {ip=>$_->{ip}} if($_->{mac} && $hwtxt eq $_->{mac}); # return ip with known mac from list
			push @l2,$_->{ip} unless($_->{mac});
            $accs{$_->{accid}} = 1 if($_->{accid}); 
		}
		return {ip=>$l2[0]} if(@l2==1); # return IP with empty MAC if only one
		return {ip=>\@l2} if(@l2); # return list IPs with empty MAC
        return {ip=>[map {$_->{ip}} @list]} if(keys %accs == 1); # return list with all available IPs if ips owned by one account

        # all ips have mac return subnet for lease allocate
		return {subnet=>ntoa($enasubs->[0]->[0])} if($enasubs && @$enasubs);
	}
	else {
		return {subnet=>ntoa($enasubs->[0]->[0])} if($enasubs && @$enasubs);
	}
	return;
}

sub load_config {
	my ($self, $conf) = @_;
	my $q = "SELECT net,gateway,dns,routerip FROM net_nets";
	my $res = $self->exec_select($q);
	unless($res && $res->resultStatus eq PGRES_TUPLES_OK) {
		return $self->base_error();
	}
	while(my ($net,$gw,$dns,$router) = $res->fetchrow()) {
		my $netstr = asubnettoh($net);
        # previous config
		my $sconf = $conf->{'subnets'}->{$netstr} || {};
		my ($n,$m) = unpack('NN',$netstr);
		$n = $n | (0xFFFFFFFF & ~$m);
		$sconf->{'option'}->{1}  ||= substr($netstr,4,4);
		$sconf->{'option'}->{3}  ||= atoh($gw);
		$sconf->{'option'}->{28} ||= pack('N',$n);
		$sconf->{'ranges'} ||= [[ntoa($n-8), ntoa($n-1)]];
		$conf->{'subnets'}->{$netstr} = $sconf;
	}
	return undef;
}

1;
