package DHCPLeases;
use strict;
use warnings;
use Socket;
use POSIX qw(strftime);
use DHCPUtils;
use Data::Dumper;

use constant {
	STATE_FREE    => 0,
	STATE_OFFER   => 1,
	STATE_ACTIVE  => 2
};

use constant {
	STATIC_L  => 0,
	DYNAMIC_L => 1
};

my %Leases;

my %_lstates = ( 0=>'free', 1=>'offer', 2=>'active' );
my %_rstates = map { $_lstates{$_} => $_ } keys %_lstates;

sub lease_create($$)
{
	return undef if($Leases{$_[0]});
	my $l = {
		ipaddr   => $_[0],
		hwaddr   => undef,
		state    => STATE_FREE,
		start    => 0,
		end      => 0,
		type     => $_[1]
	};
	$Leases{$_[0]} = $l;
	return $l;
}

sub lease_loadstate($$)
{
	my ($l,$st) = @_;
	$l->{hwaddr} = $st->{hardware};
	$l->{start} = $st->{starts};
	$l->{end} = $st->{ends};
	$l->{state} = $_rstates{$st->{state}};
}

sub lease_getbyip($)
{
	return $Leases{$_[0]};
}

sub lease_check($$)
{
	my ($l,$hw) = @_;
	return unless($l);
    return 2 if($l->{hwaddr} eq $hw);
	return if($l->{state} && $l->{end}>time() && $l->{hwaddr} ne $hw);
    return 1;
}

sub lease_offer($$;$)
{
	my ($ip,$hw,$force) = @_;
	my $l = $Leases{$ip};
	return unless($l);
	my $t = time();
	return if(!$force && $l->{state} && $l->{end}>$t && $l->{hwaddr} ne $hw);
	$l->{start} = $t;
	$l->{end} = $t+15;
	$l->{state} = STATE_OFFER;
	$l->{ipaddr} = $ip;
	$l->{hwaddr} = $hw;
	return $l;
}

sub lease_request($$$;$)
{
	my ($ip, $hw, $time,$force) = @_;
	my $l = $Leases{$ip};
	return unless($l);
	my $t = time();
	return if(!$force && $l->{state} && $l->{end}>$t && $l->{hwaddr} ne $hw);
	$l->{start} = $t;
	$l->{end} = $t + $time;
	$l->{state} = STATE_ACTIVE;
	$l->{hwaddr} = $hw;
	return $l;
}

sub lease_inform($$$;$)
{
	my ($ip, $hw, $time,$force) = @_;
	my $l = $Leases{$ip};
	return unless($l);
	return undef if(!$force && $l->{state} != STATE_FREE && $l->{hwaddr} ne $hw);
	my $t = time();
	$l->{start} = $t;
	$l->{end} = $t + $time;
	$l->{state} = STATE_ACTIVE;
	$l->{hwaddr} = $hw;
	return $l;
}

sub lease_release($$)
{
	my ($ip,$hw) = @_;
	my $l = $Leases{$ip};
	return unless($l && $l->{hwaddr});
	return if($l->{state} != STATE_ACTIVE || $l->{hwaddr} ne $hw);
	$l->{stop} = time();
	$l->{state} = STATE_FREE;
	delete $Leases{$ip} unless($l->{type});
	return $l;
}

sub lease_getfree($$)
{
	my ($range,$hw) = @_;
	return undef unless($range);
	my $t = time();
	for (@$range) {
		return $_ if($_->{hwaddr} && $_->{hwaddr} eq $hw && $_->{state} != STATE_FREE);
		return $_ if($_->{end}<$t || $_->{state} == STATE_FREE);
	}
	return undef;
}


sub save_lease($)
{
	my ($l) = @_;
	my $s = "lease ".htoa($l->{ipaddr})." {\n";;
	$s .= "  starts ".$l->{start}.";\n";
	$s .= "  ends ".$l->{end}.";\n";
	$s .= "  binding state ".$_lstates{$l->{state}}.";\n";
	$s .= "  hardware ethernet ".hexmac($l->{hwaddr}).";\n";
	$s .= "}\n";
	return $s;
}

sub save_leases($)
{
	my ($file) = @_;
	open(L,'>',$file) || return "Can't open for write file '$file'. $!";
	my $t = time();
	for (values %Leases) {
		print L save_lease($_) if($_->{state} && $_->{end}>$t);
	}
	close L;
	return;
}

1;

