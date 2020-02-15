package DHCPConfig;
use strict;
use warnings;
use Socket;
use Data::Dumper;
use DHCPUtils;

my %dhcp_int_types = (
	uint8  => [0,255,'C'],        int8  => [-128,127,'c'], 
	uint16 => [0,65536,'n'],      int16 => [-32768,32767,'n'],
	uint32 => [0,4294967295,'N'], int32 => [-2147483648,2147483647,'N']
);

my %dhcp_options = (
	'subnet-mask'			=> { code=>1,  type=>'ip' },
	'time-offset'			=> { code=>2,  type=>'int32' },
	'routers'				=> { code=>3,  type=>'lip' },
	'time-servers'			=> { code=>4,  type=>'lip' },
	'ien116-name-servers'	=> { code=>5, type=>'lip' },
	'domain-name-servers'	=> { code=>6, type=>'lip' },
	'log-servers'			=> { code=>7,  type=>'lip' },
	'cookie-servers'		=> { code=>8,  type=>'lip' },
	'lpr-servers'			=> { code=>9,  type=>'lip' },
	'impress-servers'		=> { code=>10, type=>'lip' },
	'resource-location-servers'	=> { code=>11, type=>'lip' },
	'host-name'				=> { code=>12, type=>'string' },
	'boot-size'				=> { code=>13, type=>'uint16' },
	'merit-dump'			=> { code=>14, type=>'string' },
	'domain-name'			=> { code=>15, type=>'string' },
	'swap-server'			=> { code=>16, type=>'ip' },
	'root-path'				=> { code=>17, type=>'string' },
	'ip-forwarding'			=> { code=>19, type=>'flag' },
	'non-local-source-routing'	=> { code=>20, type=>'flag' },
	'policy-filter'			=> { code=>21, type=>'lip,ip' },
	'max-dgram-reassembly'	=> { code=>22, type=>'uint16' },
	'default-ip-ttl'		=> { code=>23, type=>'uint8' },
	'path-mtu-aging-timeout'	=> { code=>24, type=>'uint32' },
	'path-mtu-plateau-table'	=> { code=>25, type=>'luint16' },
	'interface-mtu'			=> { code=>26, type=>'uint16' },
	'all-subnets-local'		=> { code=>27, type=>'flag' },
	'broadcast-address'		=> { code=>28, type=>'ip' },
	'perform-mask-discovery'	=> { code=>29, type=>'flag' },
	'mask-supplier'			=> { code=>30, type=>'flag' },
	'router-discovery'		=> { code=>31, type=>'flag' },
	'router-solicitation-address'	=> { code=>32, type=>'ip' },
	'static-routes'			=> { code=>33, type=>'lip,ip' },
	'trailer-encapsulation'	=> { code=>34, type=>'flag' },
	'arp-cache-timeout'		=> { code=>35, type=>'uint32' },
	'ieee802-3-encapsulation'	=> { code=>36, type=>'flag' },
	'default-tcp-ttl'		=> { code=>37, type=>'uint8' },
	'tcp-keepalive-interval'	=> { code=>38, type=>'uint32' },
	'tcp-keepalive-garbage'	=> { code=>39, type=>'flag' },
	'nis-domain'			=> { code=>40, type=>'string' },
	'nis-servers'			=> { code=>41, type=>'lip' },
	'ntp-servers'			=> { code=>42, type=>'lip' },
	'netbios-name-servers'	=> { code=>44, type=>'lip' },
	'netbios-dd-server'		=> { code=>45, type=>'lip' },
	'netbios-node-type'		=> { code=>46, type=>'uint8' },
	'netbios-scope'			=> { code=>47, type=>'string' },
	'font-servers'			=> { code=>48, type=>'lip' },
	'x-display-manager'		=> { code=>49, type=>'lip' },
	'dhcp-client-identifier'	=> { code=>61, type=>'data-string' },
	'nisplus-domain'		=> { code=>64, type=>'string' },
	'nisplus-servers'		=> { code=>65, type=>'lip' },
	'tftp-server-name'		=> { code=>66, type=>'string' },
	'bootfile-name'			=> { code=>67, type=>'string' },
	'mobile-ip-home-agent'	=> { code=>68, type=>'lip' },
	'smtp-server'			=> { code=>69, type=>'lip' },
	'pop-server'			=> { code=>70, type=>'lip' },
	'nntp-server'			=> { code=>71, type=>'lip' },
	'www-server'			=> { code=>72, type=>'lip' },
	'finger-server'			=> { code=>73, type=>'lip' },
	'irc-server'			=> { code=>74, type=>'lip' },
	'streettalk-server'		=> { code=>75, type=>'lip' },
	'streetalk-directory-assistance-server'	=> { code=>76, type=>'lip' },
);

our %dhcp_config_words = (
	'allow'					=> { where=>'G',   type=>'ibool', value=>1, subnames=>['unknown-clients','duplicates','declines'] },
	'deny'					=> { where=>'G',   type=>'ibool', value=>0, subnames=>['unknown-clients','duplicates','declines'] },
	'ignore'				=> { where=>'G',   type=>'ibool', value=>-1, subnames=>['unknown-clients','duplicates','declines'] },
	'always-broadcast'		=> { where=>'G',   type=>'flag'   },
	'hardware'				=> { where=>'HL',  type=>'sub', 'sub'=>\&parse_sub_hardware },
	'local-port'			=> { where=>'G',   type=>'uint16' },
	'local-address'			=> { where=>'G',   type=>'lip'    },
	'default-lease-time'	=> { where=>'GSH', type=>'uint32' },
	'max-lease-time'		=> { where=>'GSH', type=>'uint32' },
	'min-lease-time'		=> { where=>'GSH', type=>'uint32' },
	'pid-file-name'			=> { where=>'G',   type=>'string' },
	'server-identifier'		=> { where=>'G',   type=>'string' },
	'stash-agent-options'	=> { where=>'G',   type=>'flag'   },
	'server-name'			=> { where=>'G',   type=>'string' },
	'fixed-address'			=> { where=>'H',   type=>'ip'     },
	'get-lease-hostnames' 	=> { where=>'G',   type=>'flag'   },
	'use-host-decl-names' 	=> { where=>'G',   type=>'flag'   },
	'server-identifier'  	=> { where=>'G',   type=>'string' },
	'log-facility'			=> { where=>'G',   type=>'string' },
	'option'				=> { where=>'GHS', type=>'sub', 'sub'=>\&parse_sub_option },
	'subnet'                => { where=>'G',   type=>'sub', 'sub'=>\&parse_sub_subnet },
	'host'                  => { where=>'GS',  type=>'sub', 'sub'=>\&parse_sub_host },
	'range'                 => { where=>'S',   type=>'sub', 'sub'=>\&parse_sub_range },
	'include'               => { where=>'GS',  type=>'sub', 'sub'=>\&sub_include },
	'starts'                => { where=>'L',   type=>'int32'  },
	'ends'                  => { where=>'L',   type=>'int32'  },
	'binding'               => { where=>'L',   type=>'sub', 'sub'=>\&parse_sub_binding },
	'client-hostname'       => { where=>'L',   type=>'string' },
	'lease'                 => { where=>'l',   type=>'sub', 'sub'=>\&parse_lease_sub },
	'client-ratelimit'	    => { where=>'G',   type=>'uint16' },
);

my %dhcp_lease_states = (
	'free'   => 0,
	'offer'  => 1,
	'active' => 2
);

sub add_config_words
{
	my ($cfg) = @_;
	while(my($k,$v)=each(%$cfg)) {
		$dhcp_config_words{$k} = $v;
	}
}

sub dhcp_config_options_get
{
	return \%dhcp_options;
}

sub parse_option_type($);
sub parse_option_type($)
{
	my ($ct) = @_;
	my ($res,$err);
	skipspaces($ct);
	if(getchar($ct) eq '{') {
		nextchar($ct);
		while(1) {
			skipspaces($ct);
			my ($t,$e) = parse_option_type($ct);
			return undef,$e unless(defined $t);
			$res .= $t.',';
			skipspaces($ct);
			if(getchar($ct) eq '}') {
				nextchar($ct);
				last;
			}
			return undef,$e unless(getchar($ct) eq ',');
			nextchar($ct);
		}
		chop $res;
		return $res,undef;
	}
	my $word = getword($ct);
	if($word eq 'boolean') {
		return 'flag',undef;
	}
	if($word eq 'ip-address') {
		return 'ip',undef;
	}
	if($word eq 'cidr') {
		return 'cidr',undef;
	}
	if($word eq 'text') {
		return 'string',undef;
	}
	if($word eq 'string') {
		return 'data-string',undef;
	}
	$res = '';
	if($word eq 'unsigned' || $word eq 'signed') {
		skipspaces($ct);
		$res .= 'u' if($word eq 'unsigned');
		$word = getword($ct);
	}
	if($word eq 'integer') {
		skipspaces($ct);
		my $n = getnumber($ct);
		return undef,'Wrong integer size '.$n unless($n==8 || $n==16 || $n==32);
		$res .= 'int'.$n;
		return $res,undef;
	}
	if($word eq 'array') {
		skipspaces($ct);
		$word = getword($ct);
		return undef,"Expect 'of'" unless($word eq 'of');
		skipspaces($ct);
		($res,$err) = parse_option_type($ct);
		return $res,$err unless(defined $res);
		return 'l'.$res,$err;
	}
	return undef,'Unknown type';
}

sub parse_data($$)
{
	my ($ct,$def) = @_;
	my ($res,$err,$w);
	if($def eq 'flag') {
		$w = getword($ct);
		if($w =~ /^(on|off|true|false)$/) {
			$res = [chr(1), 1];
			$res = [chr(0), 0] if($1 eq 'off' || $1 eq 'false');
			return $res,undef;
		}
		return undef,'Wrong boolean value';
	}
	if($def eq 'ip') {
		$w = getword($ct);
		return undef,'Expected IP addres or FQDN' unless($w =~ /^([\w\.-]+)/);
		my $pip = gethostbyname($1);
		return undef,"Cant get ip address" unless(defined $pip);
		return [$pip, inet_ntoa($pip)],undef; 
	}
	if($def eq 'cidr') {
		$w = getipmask($ct);
		return undef,'Expected ip/mask' unless($w =~ m!^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})!);
		my $mask = int($2);
		my $pip = gethostbyname($1);
		return undef,'Cant get ip address '.$1 unless(defined $pip);
		return undef,'Wrong mask '.$mask if($mask<=0 || $mask>32);
		return [chr($mask).substr($pip,0,int(($mask-1)/8)+1), inet_ntoa($pip).'/'.$mask],undef; 
	}
	if($def eq 'string') {
		$w = getstring($ct);
		return undef,'Expected string' unless(defined $w);
		return [$w, $w],undef; 
	}
	if($def eq 'data-string') {
		$w = getdatastring($ct);
		return undef,'Expected data-string' unless(defined $w); 
		return [$w,$w],undef;
	}
	if($def =~ /^(u?int(?:8|16|32))$/) {
		my $d = $dhcp_int_types{$1};
		return undef,'Unknown int type' unless($d);
		$w = getnumber($ct);
		return undef,'Not a number' unless($w =~ /^(?:-|\+)?\d+$/);
		my $n = int($w);
		return undef,'Number out of type borders' if($n<$d->[0] || $n>$d->[1]);
		return [pack($d->[2],$n), $n],undef;
	}
	return undef,'Unknown type';
}

sub parse_optdata($$)
{
	my ($ct,$def) = @_;
	my ($res,$err);
	my $list = 0;
	if($def=~/^l/) {
		$def = $';
		$list = 1;
	}
	my @def = split /,/,$def;
	do {
		for my $d (@def) {
			skipspaces($ct);
			my ($r,$e) = parse_data($ct,$d);
			return undef,$e if($e);
			$res .= $r->[0];
		}
		skipspaces($ct);
		$list = 0 if(getchar($ct) eq ';');
		nextchar($ct) if($list && getchar($ct) eq ',');
	} while($list);
	return $res,undef;
}

sub parse_worddata($$)
{
	my ($ct,$def) = @_;
	my ($res,$err);
	unless($def=~/^l/) {
		($res,$err) = parse_data($ct,$def);
		return $res->[1],$err;
	}
	$def = $';
	my $list = 1;
	my @def = split /,/,$def;
	do {
		for my $d (@def) {
			skipspaces($ct);
			my ($r,$e) = parse_data($ct,$d);
			return undef,$e if($e);
			push @$res,$r->[1];
		}
		skipspaces($ct);
		$list = 0 if(getchar($ct) eq ';');
		nextchar($ct) if($list && getchar($ct) eq ',');
	} while($list);
	return $res,undef;
}

sub parse_option($$)
{
	my ($ct,$options) = @_;
	my ($ret,$e,$code);
	skipspaces($ct);
	my $name = getword($ct);
	return undef,"No option name" unless($name =~ /^[\w-]+$/);
	my $r = $options->{$name};
	if($r) {
		($ret,$e) = parse_optdata($ct,$r->{type});
		return $ret,$e unless(defined $ret);
		return { code=>$r->{code}, data=>$ret },undef;
	}
	skipspaces($ct);
	my $w = getword($ct);
	return undef,"Unknown option $name" unless($w eq 'code');
	skipspaces($ct);
	($code,$e) = parse_data($ct,'uint8');
	return undef,$e if($e);
	skipspaces($ct);
	return undef,"Expected '='" unless(getchar($ct) eq '=');
	nextchar($ct);
	# define new option
	($ret,$e) = parse_option_type($ct);
	return $ret,$e unless(defined $ret);
	$options->{$name} = {code=>$code->[1], type=>$ret};
	return { code=>0 }, undef;
}

sub parse_sub_option($$)
{
	my ($ct,$conf) = @_;
	my ($r,$e) = parse_option($ct,\%dhcp_options);
	return $e unless(defined $r);
	$conf->{option}->{$r->{code}} = $r->{data} if($r->{code});
	return undef; 
}

sub parse_sub_range($$)
{
	my ($ct,$conf) = @_;
	skipspaces($ct);
	my $subnet = $conf->{subnet};
	return "No subnet defined" unless($subnet);
	my ($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $ip1 = $v->[1];
	return "$ip1 out of subnet range" unless(DHCPUtils::hinsubnet($v->[0],$subnet));
	skipspaces($ct);
	($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $ip2 = $v->[1];
	return "$ip2 out of subnet range" unless(DHCPUtils::hinsubnet($v->[0],$subnet));
	push @{$conf->{'ranges'}},[$ip1,$ip2];
	return undef;
}

sub parse_sub_hardware($$)
{
	my ($ct,$conf) = @_;
	skipspaces($ct);
	my $name = getword($ct);
	return "Support only 'ethernet' hardware type" unless($name eq 'ethernet');
	skipspaces($ct);
	my ($v,$e) = parse_data($ct,'data-string');
	return $e if($e);
	$conf->{'hardware'} = $v->[0];
	return undef;
}

sub parse_sub_host($$)
{
	my ($ct,$conf) = @_;
	my ($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $ip = $v->[1];
	my $iph = $v->[0];
	skipspaces($ct);
	return "Expected left curly bracket" unless(getchar($ct) eq '{');
	nextchar($ct);
	my $sconf = {'host' => $iph};
	my $c;
	while(!iseof($ct)) {
		skipspaces($ct);
		$c = getchar($ct);
		last if($c eq '}');
		my $e = parse_word($ct,$sconf,'H');
		return $e if($e);
		skipspaces($ct);
		return 'Expected semicolon' unless(getchar($ct) eq ';');
		nextchar($ct);
	}
	return "Expected right curly bracket" unless(getchar($ct) eq '}');
	nextchar($ct);
	nochecksemicolon($ct);
	return "Host $ip redefined" if($conf->{'hosts'}->{$iph});
	$conf->{'hosts'}->{$iph} = $sconf;
	return undef; 
}

sub parse_sub_subnet($$)
{
	my ($ct,$conf) = @_;
	my ($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $ip = $v->[1];
	my $net = $v->[0];
	skipspaces($ct);
	my $w = getword($ct);
	return "Expected 'netmask'" unless($w eq 'netmask');
	skipspaces($ct);
	($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $netmask = $v->[1];
	$net .= $v->[0];
	skipspaces($ct);
	return "Expected left curly bracket" unless(getchar($ct) eq '{');
	nextchar($ct);
	my $sconf = {'subnet' => $net};
    #set broadcast option by default
    my ($n,$m) = unpack('NN',$net);
    $n = $n | (0xFFFFFFFF & ~$m);
    $sconf->{'option'}->{28} = pack('N',$n);
	my $c;
	while(!iseof($ct)) {
		skipspaces($ct);
		$c = getchar($ct);
		last if($c eq '}');
		my $e = parse_word($ct,$sconf,'S');
		return $e if($e);
		skipspaces($ct);
		return 'Expected semicolon' unless(getchar($ct) eq ';');
		nextchar($ct);
	}
	return "Expected right curly bracket" unless(getchar($ct) eq '}');
	nextchar($ct);
	nochecksemicolon($ct);
	return "Subnet $ip/$netmask redefined" 
		if ($conf->{'subnets'}->{$net} && $conf->{'subnets'}->{$net}->{'_set'});
	$sconf->{'_set'} = 1;
	$conf->{'subnets'}->{$net} = $sconf;
	return undef; 
}

sub sub_include($$)
{
	my ($ct,$conf,$context) = @_;
	my ($v,$e) = parse_data($ct,'string');
	return $e if($e);
	skipspaces($ct);
	return 'Expected semicolon' unless(getchar($ct) eq ';');
	$v = $v->[1];
	return "File '$v' not found" unless(-e $v);
	open(CFG,$v) || return "Can't open file '$v'! $!";
	my $s = '';
	$s .= $_ while(<CFG>);
	close CFG;
	$e = DHCPConfig::dhcp_config_parse($s,$conf,$context,$v);
	return $e;
}

sub parse_sub_binding($$)
{
	my ($ct,$conf) = @_;
	skipspaces($ct);
	my $name = getword($ct);
	return "Expect 'state' word" unless($name eq 'state');
	skipspaces($ct);
	$name = getword($ct);
	return "Unknown state '$name'" unless($dhcp_lease_states{$name});
	$conf->{'state'} = $name;
	return undef;
}

sub parse_word($$$)
{
	my ($ct,$conf,$context) = @_;
	my $name = getword($ct);
	return undef unless($name);
	my $cf = $dhcp_config_words{$name};
	return "Unknown '$name'" unless($cf);
	return "'$name' not acceptable in this context" unless($cf->{'where'} =~ /$context/);
	skipspaces($ct);
	if($cf->{type} eq 'sub') {
		return $cf->{'sub'}->($ct,$conf,$context);
	}
	else {
		my ($v,$e) = parse_worddata($ct,$cf->{type});
		return $e if($e);
		$conf->{$name} = $v;
		return undef;
	}
	return "Error in program!";	
}

sub parse_lease_sub
{
	my ($ct,$conf) = @_;
	my ($v,$e) = parse_data($ct,'ip');
	return $e if($e);
	my $ip = $v->[1];
	my $iph = $v->[0];
	skipspaces($ct);
	return "Expected left curly bracket" unless(getchar($ct) eq '{');
	nextchar($ct);
	my $sconf = {'ip' => $iph};
	my $c;
	while(!iseof($ct)) {
		skipspaces($ct);
		$c = getchar($ct);
		last if($c eq '}');
		my $e = parse_word($ct,$sconf,'L');
		return $e if($e);
		skipspaces($ct);
		return 'Expected semicolon' unless(getchar($ct) eq ';');
		nextchar($ct);
	}
	return "Expected right curly bracket" unless(getchar($ct) eq '}');
	nextchar($ct);
	nochecksemicolon($ct);
	$conf->{$iph} = $sconf;
	return undef; 

}

sub format_error($$)
{
	my ($ct,$e) = @_;
	my $m = $e.' on line '.$ct->{lastline};
	$ct->{pos} = $ct->{last};
	my $w = getword($ct);
	return $m." near '".$w."' in file '$ct->{file}'";
}

sub dhcp_lease_parse($$$)
{
	my ($text,$conf,$file) = @_;
	my $ct = {
		text   => $text,
		pos    => 0,
		line   => 1,
		length => length($text),
		file   => $file
	};
	my $context = 'l';
	while(!iseof($ct)) {
		skipspaces($ct);
		last if(iseof($ct));
		my $e = parse_word($ct,$conf,$context);
		return format_error($ct,$e) if($e);
		next if(skipchecksemicolon($ct));
		skipspaces($ct);
		return format_error($ct,'Expected semicolon') unless(getchar($ct) eq ';');
		nextchar($ct);
	}
	return undef;

}

sub dhcp_config_parse($$$;$)
{
	my ($text,$conf,$context,$file) = @_;
	my $ct = {
		text   => $text,
		pos    => 0,
		line   => 1,
		length => length($text),
		file   => $file
	};
	while(!iseof($ct)) {
		skipspaces($ct);
		last if(iseof($ct));
		my $e = parse_word($ct,$conf,$context);
		return format_error($ct,$e) if($e);
		next if(skipchecksemicolon($ct));
		skipspaces($ct);
		return format_error($ct,'Expected semicolon') unless(getchar($ct) eq ';');
		nextchar($ct);
	}
	return undef;
}

1;
