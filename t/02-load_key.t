#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use Crypt::RSA::Parse;
use Data::Dumper;
use Protocol::ACME;
use MIME::Base64 qw( encode_base64url );

use lib 't/lib';

use Protocol::ACME::Test;


my $tests = 47;

plan tests => $tests;

my $test_objs = $Protocol::ACME::Test::test_objs;

sub _bigint_to_binary {
  my ( $bigint ) = @_;

  # TODO: Inelegant hack to deal with different Bignum implementations
  my $hex;
  if ( UNIVERSAL::isa( $bigint, "Math::BigInt" ) )
  {
    $hex = substr( $bigint->as_hex(), 2 );
    #Prefix a 0 as needed to get an even number of digits.
    if (length($hex) % 2)
    {
      substr( $hex, 0, 0, 0 );
    }

    return pack 'H*', $hex;
  }
  else
  {
    $bigint->to_bin();
  }

}

sub check_key
{
  my $key = shift;

  my $private_rsa = Crypt::RSA::Parse::private($test_objs->{account_key}->{pem});

  if ( $key->{n} ne encode_base64url(_bigint_to_binary($private_rsa->modulus())) )
  {
    return 0;
  }

  return 1;
}

eval
{
  our $acme;

 SKIP:
  {
    if ( ! $Protocol::ACME::Test::rsa || ! $Protocol::ACME::Test::bignum )
    {
      skip "Crypt::OpenSSL::Bignum or Crypt::OpenSSL::RSA not found", 23;
    }

    lives_ok { $acme = Protocol::ACME->new( host => $Protocol::ACME::Test::host, debug => 1 ) } 'Create ACME Object';
    lives_ok { $acme->account_key( \$test_objs->{account_key}->{pem} ) } 'Load PEM Buffer';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( \$test_objs->{account_key}->{der} ) } 'Load DER Buffer';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( "t/$test_objs->{account_key}->{filename}.pem" ) } 'Load PEM File';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( "t/$test_objs->{account_key}->{filename}.der" ) } 'Load DER File';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem} } ) } 'Load PEM Buffer 2';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der} } ) } 'Load DER Buffer 2';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { filename => "t/$test_objs->{account_key}->{filename}.pem"  } ) } 'Load PEM File 2';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { filename => "t/$test_objs->{account_key}->{filename}.der"  } ) } 'Load DER File 2';
    ok ( check_key( $acme->{key} ) );

    dies_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem},
                                    format => "DER" } ) } 'Load PEM Buffer 3';
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem},
                                     format => "PEM" } ) } 'Load PEM Buffer 4';
    ok ( check_key( $acme->{key} ) );

    dies_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der},
                                    format => "PEM" } ) } 'Load DER Buffer 3';
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der},
                                     format => "DER" } ) } 'Load DER Buffer 4';
    ok ( check_key( $acme->{key} ) );
    $acme = undef;
  }

 SKIP:
  {
    skip "openssl binary not found", 24 unless $Protocol::ACME::Test::openssl;

    lives_ok { $acme = Protocol::ACME->new( host => $Protocol::ACME::Test::host,
                                            openssl => $Protocol::ACME::Test::openssl,
                                            debug => 1 ) } 'Create ACME Object - OpenSSL';
    lives_ok { $acme->account_key( \$test_objs->{account_key}->{pem} ) } 'Load PEM Buffer - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( \$test_objs->{account_key}->{der} ) } 'Load DER Buffer - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( "t/$test_objs->{account_key}->{filename}.pem" ) } 'Load PEM File - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( "t/$test_objs->{account_key}->{filename}.der" ) } 'Load DER File - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem} } ) } 'Load PEM Buffer 2 - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der} } ) } 'Load DER Buffer 2 - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { filename => "t/$test_objs->{account_key}->{filename}.pem"  } ) } 'Load PEM File 2 - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { filename => "t/$test_objs->{account_key}->{filename}.der"  } ) } 'Load DER File 2 - OpenSSL';
    ok ( check_key( $acme->{key} ) );

    dies_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem},
                                    format => "DER" } ) } 'Load PEM Buffer 3 - OpenSSL';
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{pem},
                                     format => "PEM" } ) } 'Load PEM Buffer 4 - OpenSSL';
    ok ( check_key( $acme->{key} ) );

    # NOTE: becasue of the way Crypt::RSA::Parse was written, the 'format' is effectively ignored hence this works regardless.
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der},
                                     format => "PEM" } ) } 'Load DER Buffer 3 - OpenSSL';
    ok ( check_key( $acme->{key} ) );
    lives_ok { $acme->account_key( { buffer => $test_objs->{account_key}->{der},
                                     format => "DER" } ) } 'Load DER Buffer 4 - OpenSSL';
    ok ( check_key( $acme->{key} ) );
  }
};
if ( $@ )
{
  diag ( $@ );
}







