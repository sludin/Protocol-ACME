package Protocol::ACME::OpenSSL;


package Protocol::ACME::OpenSSL::FakeNum;

use strict;
use warnings;

sub new
{
  my $class = shift;
  my $self = { value => $_[0] };
  bless $self, $class;
  return $self;
}

sub to_bin
{
  my $self = shift;
  return $self->{value};
}


package Protocol::ACME::OpenSSL;

use strict;
use warnings;

use IO::File;
use IO::Pipe;

use IPC::Open2;

use MIME::Base64 qw( encode_base64url );
use Data::Dumper;

use Carp;

our $VERSION = '0.01';


sub _init
{
  my $self = shift;
  my $args;

  if ( @_ == 1 )
  {
    $args = shift;
    if ( ref $args ne "HASH" )
    {
      croak "Must pass a hash or hashref to challenge constructor";
    }
  }
  else
  {
    $args = {@_};
  }

  for my $required_arg ( qw ( openssl keyfile ) )
  {
    if ( ! exists $args->{$required_arg} )
    {
      croak "Require arg $required_arg missing from constructor";
    }
    else
    {
      $self->{$required_arg} = $args->{$required_arg};
    }
  }


}

sub new_private_key
{
  my $class = shift;
  my $self = {};
  bless $self, $class;
  $self->_init( @_ );

  my $cmd = "$self->{openssl} pkey -in $self->{keyfile} -noout -text_pub";
  my $output = `$cmd`;

  my ($modulus)  = $output =~ /^Modulus:([\s0-9a-f:]+)/ms;
  my ($exponent) = $output =~ /^Exponent: (\d+)/ms;

	$modulus =~ s/[^0-9a-f]//g;
  $modulus = pack("H*", $modulus);
  $modulus =~ s/^\x00*//;

  $exponent = pack("N", $exponent);
	$exponent =~ s/^\x00*//;

  $self->{n} = Protocol::ACME::OpenSSL::FakeNum->new( $modulus );
  $self->{e} = Protocol::ACME::OpenSSL::FakeNum->new( $exponent );

  return $self;
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

sub sign
{
  my $self = shift;
  my $payload = shift;

  my $cmd = "$self->{openssl} dgst -sha256 -binary -sign $self->{keyfile}";

  my ( $out, $in );
  my $pid = open2( $out, $in, $cmd );

  print $in $payload;
  close($in);
  my $output = "";
  while( <$out> )
  {
    $output .= $_;
  }

  return $output;
}


1; # End of Protocol::ACME::OpenSSL
