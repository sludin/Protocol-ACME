package Protocol::ACME::Key;

# A shim that imitates Crypt::OpenSSL::RSA.

use strict;
use warnings;

our $VERSION = '0.12';

use Crypt::RSA::Parse;
use Math::BigInt ();

use Protocol::ACME::Utils;

sub new
{
  my ($class, %opts) = @_;

  my $key = Crypt::RSA::Parse::private($opts{'keystring'});

  my $self = {
    _keystring => $opts{'keystring'},
    _openssl_bin => $opts{'openssl'},
    _private_key => $key,
    e => Math::BigInt->new( $key->publicExponent() ),
    n => $key->modulus(),
  };

  return bless $self, $class;
}

sub use_sha256_hash
{
  # NOOP for compatibility with Crypt::OpenSSL::RSA
}

sub get_key_parameters
{
  my $self = shift;
  return ( $self->{n}, $self->{e} );
}

sub sign {
  my ($self, $payload) = @_;

  #TODO: Use an available SHA256-digest module, if any.

  $self->{'_openssl'} ||= do {
    require Protocol::ACME::OpenSSL;
    Protocol::ACME::OpenSSL->new($self->{'_openssl_bin'});
  };

  require File::Temp;
  my $fh = File::Temp->new();
  my $kpath = $fh->filename();
  print {$fh} $self->{'_keystring'} or die "write($kpath) failed: $!";
  close $fh or die "close($kpath) failed: $!";

  return $self->{'_openssl'}->run(
    command => [
      'dgst',
      '-sha256',
      '-binary',
      '-sign' => $kpath,
    ],
    stdin => $payload,
  );
}

1;
