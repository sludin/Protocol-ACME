package Protocol::ACME::Challenge::SimpleSSH;

use parent qw ( Protocol::ACME::Challenge );
use Carp;

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

  for my $required_arg ( qw ( ssh_host www_root ) )
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

  my $cmd = "ssh -q $self->{ssh_host} 'echo $challenge.$fingerprint > " .
            "$self->{www_root}/.well-known/acme-challenge/$challenge'";

  my $output = `$cmd`;

  return $? == 0 ? 0 : 1;
}


1;
