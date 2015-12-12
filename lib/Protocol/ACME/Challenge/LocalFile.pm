package Protocol::ACME::Challenge::LocalFile;

use parent qw ( Protocol::ACME::Challenge );
use Carp;
use IO::File;

sub new
{
  my $class = shift;
  my $self = {};
  bless $self, $class;
  $self->_init( @_ );
  return $self;
}

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
    $args = \%_;
  }

  for my $required_arg ( qw ( www_root ) )
  {
    if ( ! exists $args->{$required_arg} )
    {
      croak "Require arg $required_arg missing from chalenge constructor";
    }
    else
    {
      $self->{$required_arg} = $args->{$required_arg};
    }
  }
}


sub handle
{
  my $self          = shift;
  my $challenge     = shift;
  my $fingerprint   = shift;

  my $filename = "$self->{www_root}/.well-known/acme-challenge/$challenge";
  my $content = "$challenge.$fingerprint";

  my $fh = IO::File->new( $filename, "w" );
  if ( ! $fh )
  {
    carp "Could not open $filename for write";
    return 1;
  }

  print $fh $content;
  $fh->close();

  return 0;
}


1;
