package DHCPUtils;
use strict;
use warnings;
use Socket;
use Exporter qw(import);
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use vars qw(@EXPORT);

@EXPORT = qw(
	hton ntoh aton ntoa	atoh htoa
	ninsubnet hinsubnet hsubnettoa hsubnettobr
	hexbuf formatmac hexmac getrelayagentoptions
	asubnetton asubnettoh
    nochecksemicolon skipchecksemicolon iseof getchar nextchar backchar
    skipspaces skipline getwordqr getword getipmask getstring
    getdatastring getnumber
);

my %masks = ( 
	0=>'0.0.0.0', 
	1=>'128.0.0.0', 2=>'192.0.0.0', 3=>'224.0.0.0', 4=>'240.0.0.0', 5=>'248.0.0.0', 6=>'252.0.0.0', 7=>'254.0.0.0', 8=>'255.0.0.0',
	9=>'255.128.0.0', 10=>'255.192.0.0', 11=>'255.224.0.0', 12=>'255.240.0.0', 13=>'255.248.0.0', 14=>'255.252.0.0', 15=>'255.254.0.0', 16=>'255.255.0.0',
	17=>'255.255.128.0', 18=>'255.255.192.0', 19=>'255.255.224.0', 20=>'255.255.240.0', 21=>'255.255.248.0', 22=>'255.255.252.0', 23=>'255.255.254.0', 24=>'255.255.255.0',
	25=>'255.255.255.128', 26=>'255.255.255.192', 27=>'255.255.255.224', 28=>'255.255.255.240', 29=>'255.255.255.248', 30=>'255.255.255.252', 31=>'255.255.255.254', 32=>'255.255.255.255'
);

sub nochecksemicolon($)
{
	$_[0]->{nosemicolon} = 1;
}

sub skipchecksemicolon($)
{
	return delete $_[0]->{nosemicolon};
}

sub iseof($)
{
	my $ct = shift;
	return ($ct->{pos}>=$ct->{length});
}

sub getchar($)
{
	my $ct = shift;
	return undef if($ct->{pos}>=$ct->{length});
	my $c = substr($ct->{text},$ct->{pos},1);
	return $c;
}

sub nextchar($)
{
	my $ct = shift;
	my $c = getchar($ct);
	return unless(defined $c);
	$ct->{pos}++;
	$ct->{line}++ if($c eq "\n");
}

sub backchar($)
{
	my $ct = shift;
	$ct->{pos}--;
}

sub skipline($)
{
	my $ct = shift;
	my $c;
	do {
		$c = getchar($ct);
		nextchar($ct);
		return if($c eq "\n");
	} while(defined $c);
}

sub skipspaces($)
{
	my $ct = shift;
	my $c;
	while(defined($c = getchar($ct))) {
		if($c eq '#') {
			nextchar($ct);
			skipline($ct);
			next;
		}
		last if($c =~/\S/);
		nextchar($ct);
	};
	$ct->{last} = $ct->{pos};
	$ct->{lastline} = $ct->{line};
}

sub getwordqr($$;$)
{
	my ($ct,$qr,$max) = @_;
	my $w = '';
	my $c;
	$max ||= -1;
	while(defined($c = getchar($ct))) {
		last unless($c=~$qr);
		$w.=$c;
		nextchar($ct);
		$max-- if($max>0);
		last if($max==0);
	}
	return $w;
}

sub getword($)
{
	my $ct = shift;
	return getwordqr($ct,qr/[\w\.-]/);
	my $w = '';
	my $c;
	while(defined($c = getchar($ct))) {
		last unless($c=~//);
		$w.=$c;
		nextchar($ct);
	}
	return $w;
}

sub getipmask($)
{
	my $ct = shift;
	my $w = '';
	my $c;
	while(defined($c = getchar($ct))) {
		last unless($c=~/[\d\.\/]/);
		$w.=$c;
		nextchar($ct);
	}
	return $w;
}

my %spc = ( 't'=>"\t", 'n'=>"\n", 'r'=>"\r", 'b'=>"\b" );

sub getstring($)
{
	my $ct = shift;
	my $w = '';
	my $c = getchar($ct);
	return unless($c eq '"');
	nextchar($ct);
	while(defined($c = getchar($ct))) {
		if($c eq '\\') {
			nextchar($ct);
			$c = getchar($ct);
			if($spc{$c}) {
				$w.=$spc{$c};
				nextchar($ct);
				next;
			}
			elsif($c eq '"') {
				$w.='"';
				nextchar($ct);
				next;
			}
			elsif($c eq 'x') {
				nextchar($ct);
				my $cod = getwordqr($ct,qr/[\da-fA-F]/,2);
				$w .= $cod?chr(hex($cod)):'x';
				next;
			}
			elsif($c =~ /[0-7]/) {
				my $cod = getwordqr($ct,qr/[0-7]/,3);
				my $cod2 = oct($cod);
				$w .= $cod2<256?chr($cod2):$cod;
				next;
			}
			else {
				backchar($ct);
				next;
			}
		}
		if($c eq '"') {
			nextchar($ct);
			return $w;
		}
		$w.=$c;
		nextchar($ct);
	}
	return $w;
}

sub getdatastring($)
{
	my $ct = shift;
	my $w = '';
	my $c = getchar($ct);
	return getstring($ct) if($c eq '"');
	return undef unless($c =~ /[0-9a-f]/i);
	$w = getwordqr($ct,qr/[0-9a-f:]/i);
	return undef unless($w =~ /^([0-9a-f]{1,2}(?::[0-9a-f]{1,2})*)/i);
	my $r= '';
	map { $r.=chr(hex) } split /:/,$1;
	return $r;
}

sub getnumber($)
{
	my $ct = shift;
	my $w = '';
	my $c = getchar($ct);
	if($c eq '-' || $c eq '+') {
		$w .= $c;
		nextchar($ct);
	}
	while(defined($c = getchar($ct))) {
		last unless($c=~/[0-9]/);
		$w .= $c;
		nextchar($ct);
	}
	return $w;
}

sub hton($)
{
	return unpack('N',$_[0]);
}

sub ntoh($)
{
	return pack('N',$_[0]);
}

sub aton($)
{
	return unpack('N',inet_aton($_[0]));
}

sub ntoa($)
{
	return inet_ntoa(pack('N',$_[0]));
}

sub atoh($)
{
	return inet_aton($_[0]);
}

sub htoa($)
{
	return inet_ntoa($_[0]);
}

sub asubnetton($)
{
	my ($ip,$mask) = split '/',$_[0];
	$mask = $masks{int($mask)} unless($mask=~/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
	return aton($ip),aton($mask);
}

sub asubnettoh($)
{
	return pack('NN',asubnetton($_[0]));
}

sub ninsubnet($$$)
{
	my ($ip,$net,$mask) = @_;
	return ($ip & $mask) == $net;
}

sub hinsubnet($$)
{
	my($ip,$s) = @_;
	my ($n,$m) = unpack('NN',$s);
	return ninsubnet(unpack('N',$ip),$n,$m);
}

sub hsubnettoa($)
{
	return inet_ntoa(substr($_[0],0,4)),inet_ntoa(substr($_[0],4,4));
}

sub hsubnettobr($)
{
	my ($n,$m) = unpack('NN',$_[0]);
    my $br = $n | (0xFFFF & $m);
    return pack('N',$br);
}

sub hexbuf($)
{
	my $a = $_[0];
	return join('',map { sprintf("%02X",ord($_))} split //,$_[0]);
}

sub hexmac($)
{
	my $a = $_[0];
	return join(':',map { sprintf("%x",ord($_))} split //,$_[0]);
}

sub formatmac {
	$_[0] =~ /([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})/i;
	return(lc(join(':', $1, $2, $3, $4, $5, $6)));
}

sub getrelayagentoptions($)
{
    use bytes;
	my $dhcpreq = $_[0];
	return unless(defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())));

	my %RelayAgent = $dhcpreq->decodeRelayAgent($_[0]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));
	my $r;
    if (my $data = $RelayAgent{1}) {
		my %cid;
        if (length($data) == 6) {
			@cid{qw/vlan unit port/} = unpack('nCC',substr($data,2));
        }
        elsif (length($data) == 5) { # так отдает GEPON BDCOM
			@cid{qw/vlan port unit/} = unpack('nnC',$data);
        }
		$r->{CircuitID} = \%cid;
    }
    if (my $data = $RelayAgent{2}) {
        if (length($data) == 8) {
			$r->{RemoteID} = unpack('H*',substr($data,2,6));
        }
        elsif (length($data) == 6) { # так отдает GEPON BDCOM
			$r->{RemoteID} = unpack('H*',$data);
        }
    }
	return $r;
}

1;
