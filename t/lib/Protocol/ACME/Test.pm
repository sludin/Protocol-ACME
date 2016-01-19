package Protocol::ACME::Test;

use strict;
use warnings;
use File::Spec;
use IO::File;
use MIME::Base64;

our $host = "acme-staging.api.letsencrypt.org";
our $openssl = which( "openssl" );
our $rsa    = 0;
our $bignum = 0;




eval
{
  require Crypt::OpenSSL::RSA;
};
if ( ! $@ )
{
  $rsa = 1;
}

eval
{
  require Crypt::OpenSSL::Bignum;
};
if ( ! $@ )
{
  $bignum = 1;
}




our $account_key_pem = <<'END_KEY';
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHGxwbOMSEvw90
GluzQjVGAKn7ytfcGVccGrsKEHLJ1axxLcJ5svLfBa2JYcAEL/Kp+rJ3PvWJhbNr
uZEO77XbCvlz55yIxKXao39hfDUjwZ0wZgmPoVXatgmdP49rIdGH9O1kKvyTg/Vl
ptVdmCf2On2l5pCVEJIt+KEhiR4oZsROEd0rNV99TrlpqNbtTJHwAO5OmcIs0uP/
F9hHfsx+139VhezChjaAKTL/37bcmu30hQJGQ5qy9hskvfcb4b4MeSIQ8uYIRGAH
XjSOmefEFgAAXMn7p8RXKS+35clLV24YW2ADkIV2lfMWIYzHHS2MI8kclOERs16V
G1BIpjfbAgMBAAECggEAQi8vy5i2Mo40O9rbKp5SiR+FYa6OzJoby7rS+8h178O4
W7LjV4L1ms8PXYCBzKKHnps4Ic1q3zjzaFa58mYaZGKkgzO1Y/1CSIhaunQIUgd1
EfaJLRZrLJWgYoYTTYBjXzc6hjaH2R1fQFgRytfeSMoupCwdWX+1p9Ri83vZ64GO
ywq/GuQ7iueLlt4HrUvi6el7pbY80DjTKjKT2aD+Uo3Hm61JoA0DGGt4gJf9eZ+A
MzzW6hsftNbqqH5vBNSUroT6wLUA/yPfeApCIswbUeCIsOLxq6zy2WgtGZkS2viS
s1PALdSToZ2h6zSf2xrwQrlEgO+DAVGnjFC11OHL2QKBgQD6oSMtt3fnPSw/EEzv
FjAtac4aiYnOVUx5Tzyc14/yyialxIimFotPMvp61S6KzjuRq4Zpg5reyW6IMiQE
iXdGLDq8v5Ce789w5GXuMw/RKdRk7CmFFdYsflU1H8Ju006JR2lmOgCSwkVPulnR
+to1xuE7S2+IA8woyS7xYwEFLwKBgQDLX1Uzfi7XGsnPLRjAunp1ZrxkWrQZUqWN
im6LcuJoDbF4hQEdetc/p1rGjKr3dljyR9SnplmahwkRAn/poEx8I/VJz+BxL8jR
nlxVkyGqa9E16Ghmyuy4c9B7mgcrLneYEfubE9s1h/yBRSocK+s3oWyh4rm7JMNk
30xLRv8lFQKBgHfnw6bJkcnFkHeTWts/qEjxx7MWfiGC2ZVn/T2kO7ASWq8P+bhM
LNX1M7S0bRHnXMRyZVnxppRTllf+dRDem3utCWTn2U7QuFPwUXvGXhjZhE3MVojf
S5n5ztYdna3b1kUDLz/DHCcaXoKoSvSUqPT1cyglDPTrrC8PITBHB2PtAoGBAJDU
w4h4RENMAIxaQVZ/dtZE48VUEw41nVC/VRpaJoKTvd9mWPT1lnTuaeccJmU1EwL3
xKnf/c/eesZyUUW/srh1oyl9sQjqTsl5Tahjr4X+Ym9Ro4gQ26RAViiv+Ir3/JN/
uv8llOb6gQhOiT6myExF2WcwX7S26a/clijF1s5BAoGAOmJLv2mWRfibo6R/qt8f
AAncMLalXb9TdB/K2pj6r999aP9JP5PV+Zbd7grjBBB6pG+FmpDJbtnhoYUTS5TA
zsDyDLvwJIGpFA5CRpLXWrt1qj0Aoqjknq0CHpF8cxmejeG6o3F6WsDKhcvUHSdr
eEN8XoB/noSGJ0mW8StwJVw=
-----END PRIVATE KEY-----
END_KEY

our $cert_key_pem = <<'END_CERT_KEY';
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhQ/7UZ/JmUDi/
iPao7Co0fEROgPPS7akgW0P5lr6CxrY1l36UaLbgwpSg3w4aUXP/BHPm50Ro4qtB
nubzyk0LxD/j6i7CPhc+8FpoZdMy0IQ9E01swhgRV9L74BJAF4yGF+pKqJw7DHJG
lGuXJn+5oy42B73+/+ayyC/UrXQYt7PCMoi2LfuLqzjJdRxxY3ofmciAP/jJiLya
P85kZETKMQaY5+dgVb+b0jWFJSjvGiWpeaSGfJoSA0gL3QD9uVlBtzO6EFoWLmIt
CQDGUMs/WLGzPJljyIX7JpOHH1kOxHeWXMzuQ1eFqjePZxE+Cg3WMCJ8/ooCsZTj
NB6A9/fFAgMBAAECggEAaErYwnJVsbTWcSbyPAcLCz21Sjs9p5xMvyRB9l4qWdWy
KmG3QvKwKKMtuMVMfDbV422mU3MjIwQ+kaUF/DzfKuFzSwvzFg81J/iTgt4Rx+bu
MnCrWf0Ks4zbq610BaRhdPvBh0tE+bmrdq3kmhhC7il0jaNL/bFwl7lDG84qf/4+
qG3VSookBQFOk16li9JL+msKjO7btOIhAalzVISrdQHoVa3+QzjzLlyO17ATizgy
JJIN5PxBEa7c+RPo9n9couhzeHNN0u+BSojEvYINJ6EOkxxJ4WyHSJNrLtslhuRr
5AWw9a1m2mUsjuD5T66rFjuGNgrCSTeN1S1FHDqKAQKBgQDwnk92LmVApx4pxgKv
axu80UJMarHdIGefsLUBQEPkqo2zCv7jzVjMPXfT7Cbk9tyMiqsfphLEy0vEU04f
gpaGRX+pqg3yNhEBago+YLmlj8jLACjbH5MvYOEloi5CMZxpBcFuH+nyCRtmiUf/
gLo4V5rm2cjbG1StpXqRDmTbBQKBgQDvqnBDExplngWprXZMmuS9WcHNLqtHP8jT
2SuWkeTPNbcGNL5fgxC9pYfy1SjC8Bev3EUKSv1/6OEjTTrp9yAqUwarC0/Snsh7
QQdfEodHn2lgG9NTXsPaR8RPJaKR6TSFOKC6Y2FFsnRD4wbaYuH1ewRuTD+NSlT/
TDXllhTFwQKBgQDRQaxzaAfwgSYPSEAflHOr8wTIdmW2nC7iRwgzTVN+MwFGe0KO
lJAsFyz15cMxjqrhotsNjB14fiCnXZdseeI0ZY6P2++C/Jgvdavw8aeiH3iNatcd
McmMA6HqW7AFKyYOg83j2udW8aqdsrglsSrCQxXYvAAc5RjwZyA/tJfrjQKBgQCY
pRh9UBR29k+rA2UeY2UeyKUr1vaWGaUCcQZXDzMJWq/ojv1VfffSojRVULh2eE7N
3mBGrv6IUj3aqxzD2XcuHdVYaYr8nc8Y2ZElV3q7/mcyJGbTab8aLq10r4a8oiim
VSvhqtxQdNmiR12dCG/cVu66hWvQxLAgLl0BjjZKwQKBgB1DCAFZ6ByQkBrNXR2N
QGVRQBE2wU23dqYno+44aYs77VgZlEkJAyxh4CqkTcfeDFVdwmcoIOdlPrpBNFjD
+NbDOuWHkTVp6t8rqS4dj/djY+kaxu5HuNyNZL4BbPo2AURoZNgweSxWU7BYY7f6
GQXI5j5yuY62bnJ3hBRXRGlV
-----END PRIVATE KEY-----
END_CERT_KEY

our $csr_pem = <<'END_CSR';
-----BEGIN CERTIFICATE REQUEST-----
MIICXzCCAUcCAQAwGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UP+1GfyZlA4v4j2qOwqNHxEToDz0u2p
IFtD+Za+gsa2NZd+lGi24MKUoN8OGlFz/wRz5udEaOKrQZ7m88pNC8Q/4+ouwj4X
PvBaaGXTMtCEPRNNbMIYEVfS++ASQBeMhhfqSqicOwxyRpRrlyZ/uaMuNge9/v/m
ssgv1K10GLezwjKIti37i6s4yXUccWN6H5nIgD/4yYi8mj/OZGREyjEGmOfnYFW/
m9I1hSUo7xolqXmkhnyaEgNIC90A/blZQbczuhBaFi5iLQkAxlDLP1ixszyZY8iF
+yaThx9ZDsR3llzM7kNXhao3j2cRPgoN1jAifP6KArGU4zQegPf3xQIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAM1d2reHUdENf/3g1lPfytvxBoC9AqWJzqNXfXG7
Cgw/4ww2TVr0WGEAmQ5P5K30uWgKEyGb7440tNydqI7QcSmRIBdp5lGi+lcBa+k8
6D8rGHcZ0s6DBBpzOR0dp68KesXofxslweizA5u/MjD5j/ifAc9s2Ef14YMaVVlh
Y8Heyd7aGw5TWXK7YDOaWHA3lL1kdmOOAJC3h8DX/BgDpAlbOUP2+pIykusylyDP
IscB8BpqKMoxDNReGB4ix+eCQB+ohb5pmHXByplpvOuUpPoMKaPyXtRJe8G8s2Vi
tn7ucsckttFhXk6EBlTr+C0KiKHTUWyt6JK1r3e+m9igtbM=
-----END CERTIFICATE REQUEST-----
END_CSR


our $csr_der = pem2der( $csr_pem );
our $account_key_der = pem2der( $account_key_pem );
our $cert_key_der = pem2der( $cert_key_pem );


our $test_objs =
{
  account_key => { filename => "test_account_key", pem => $account_key_pem, der => $account_key_der },
  csr         => { filename => "test_csr",         pem => $csr_pem,         der => $csr_der         },
  cert_key    => { filename => "test_cert_key",    pem => $cert_key_pem,    der => $cert_key_der    },
};


sub pem2der {
  my ($pem) = @_;

  chomp $pem;

  $pem =~ s<.+?[\x0d\x0a]+><>s;
  $pem =~ s<[\x0d\x0a]+[^\x0d\x0a]+?\z><>s;

  return MIME::Base64::decode($pem);
}

sub which {
	my @path = File::Spec->path;
	my $bin = shift;
	while (my $p = shift @path) {
		my $candidate = File::Spec->catfile($p, $bin);
		return $candidate if -x $candidate;
	}
	return;
}

sub _write_key_files
{
  for my $object ( keys %$test_objs )
  {
    for my $format ( qw( pem der ) )
    {
      my $fh = IO::File->new( "t/$test_objs->{$object}->{filename}.$format", "w" ) || die $!;
      print $fh $test_objs->{$object}->{$format};
      $fh->close();
    }
  }
}


1;
