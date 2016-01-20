#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempfile );
use FindBin;
use File::Spec;
use Protocol::ACME;
use Test::Exception;

use lib 't/lib';

use Protocol::ACME::Test;

my $tests = 5;

# Testing the openssl version of the library

if ( ! $Protocol::ACME::Test::openssl )
{
  plan skip_all => "Cannot find openssl binary for testing";
}
else
{
  plan tests => $tests;
}

our $pkey;

eval
{
  our $acme;

  lives_ok
  {
    $acme = Protocol::ACME->new( host               => $Protocol::ACME::Test::host,
                                 account_key        => \$Protocol::ACME::Test::account_key_pem,
                                 openssl            => $Protocol::ACME::Test::openssl
                               );
  } 'Create ACME Object';

  ok($acme);

  lives_ok { $acme->directory();  } 'Get the ACME directory';
  lives_ok { $acme->register();   } 'Register';
  lives_ok { $acme->accept_tos(); } 'Accept TOS';

};
if ( $@ )
{
  diag( $@ );
}





