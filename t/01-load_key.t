#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempfile );
use FindBin;
use File::Spec;
use Protocol::ACME;

my $tests = 7;


# This will test up through the acceptance of TOS

my $host = "acme-staging.api.letsencrypt.org";

my $openssl = which( "openssl" );

if ( ! $openssl )
{
  plan skip_all => "Cannot find openssl binary for testing";
}
else
{
  plan tests => $tests;
}

my $rsa = 0;
my $bignum = 0;

eval
{
  require Crypt::OpenSSL::RSA;
};
if ( ! $@ )
{
  $rsa = 1;
}
else
{
  diag( "Crypt::OpenSSL::RSA not found.  Skipping" );
}

eval
{
  require Crypt::OpenSSL::Bignum;
};
if ( ! $@ )
{
  $bignum = 1;
}
else
{
  diag( "Crypt::OpenSSL::RSA not found.  Skipping" );
}

SKIP: {
  skip "Crypt::OpenSSL::RSA not found", $tests unless $rsa;
  skip "Crypt::OpenSSL::Bignum not found", $tests unless $bignum;

  my $pkey;

  (undef, $pkey) = tempfile( "test_key_XXXX", OPEN => 0);

  ok($pkey);




  my $openssl = which( "openssl" );

  ok($openssl);



  my $cmd = "$openssl genpkey -out $pkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048";



  `$cmd 2>&1`;

  ok($? == 0);

  my $acme = Protocol::ACME->new( host               => $host,
                                  account_key_path   => $pkey,
                                );

  ok($acme);


  eval {
    $acme->directory();
  };
  ok( ! $@ );


  eval {
    $acme->register();
  };
  ok( ! $@ );

  eval {
    $acme->accept_tos();
  };
  ok( ! $@ );


  unlink $pkey;

};

sub which {
	my @path = File::Spec->path;
	my $bin = shift;
	while (my $p = shift @path) {
		my $candidate = File::Spec->catfile($p, $bin);
		return $candidate if -x $candidate;
	}
	return;
}



