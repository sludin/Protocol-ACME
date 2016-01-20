#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw( encode_base64url );

use lib 't/lib';

use Protocol::ACME::Test;

plan tests => 1;

# If there is not OpenSSL binary and no Crypt::OpenSSL::RSA fail
# At least of these is needed to run the module

if ( ! $Protocol::ACME::Test::openssl && ! $Protocol::ACME::Test::rsa )
{
  diag( "The openssl binary or Crypt::OpenSSL::RSA must be present" );
  ok(0);
}
else
{
  ok(1);
}


