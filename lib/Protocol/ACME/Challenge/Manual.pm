package Protocol::ACME::Challenge::Manual;

use parent qw ( Protocol::ACME::Challenge );
use Carp;
use IO::File;

our $VERSION = '0.01';

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
}


sub handle
{
  my $self          = shift;
  my $challenge     = shift;
  my $fingerprint   = shift;

  my $filename = $challenge;
  my $content = "$challenge.$fingerprint";

  print "Challenge filename: $challenge\n";
  print "Challenge text: $content\n";
  print "\n";
  print "Create a file with the above filename and coentn under <WWW>/.well-known/acme-challenge\n";
  print "where <WWW> is your web server's document root.  Let's Encrypt will make an HTTP request\n";
  print "for this file and confirm that it has the correct content.";
  print "\n";
  print "Hit return when the file is in place: ";

  my $x = <STDIN>;

  return 0;
}


1;
