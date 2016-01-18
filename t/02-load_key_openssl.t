#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempfile );
use FindBin;
use File::Spec;
use Protocol::ACME;

my $tests = 6;


#plan tests => $tests;

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


my $pkey;

(undef, $pkey) = tempfile( "test_key_XXXX", OPEN => 0);

ok($pkey);






my $cmd = "$openssl genpkey -out $pkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048";



`$cmd 2>&1`;

ok($? == 0);

my $acme = Protocol::ACME->new( host               => $host,
                                account_key        => $pkey,
                                openssl            => $openssl
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

sub which {
	my @path = File::Spec->path;
	my $bin = shift;
	while (my $p = shift @path) {
		my $candidate = File::Spec->catfile($p, $bin);
		return $candidate if -x $candidate;
	}
	return;
}



