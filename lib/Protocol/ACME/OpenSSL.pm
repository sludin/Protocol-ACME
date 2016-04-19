package Protocol::ACME::OpenSSL;

use strict;
use warnings;

our $VERSION = '0.12';

sub new
{
  my ( $class, $openssl_bin ) = @_;

  return bless { _bin => $openssl_bin }, $class;
}

sub run
{
  my ($self, %opts) = @_;

  my @cmd = @{ $opts{'command'} };

  local( $!, $^E );

  my ($crdr, $pwtr) = _pipe_or_die() if length $opts{'stdin'};

  my ($perr, $cerr) = _pipe_or_die();
  my ($prdr, $cwtr) = _pipe_or_die();

  my $pid = fork();
  if (!$pid)
  {
    die "Failed to fork(): $!" if !defined $pid;

    close $pwtr;
    close $perr;
    close $prdr;

    if (length $opts{'stdin'})
    {
      open \*STDIN, '<&=' . fileno($crdr) or do
      {
        warn "dup STDIN failed: $!";
        exit $!;
      };
    }

    open \*STDOUT, '>&=' . fileno($cwtr) or do
    {
      warn "dup STDOUT failed: $!";
      exit $!;
    };

    open \*STDERR, '>&=' . fileno($cerr) or do
    {
      warn "dup STDERR failed: $!";
      exit $!;
    };

    exec {$self->{_bin}} $self->{_bin}, @cmd or do
    {
      warn "exec($self->{_bin}) failed: $!";
      exit $!;
    };
  }

  close $crdr;
  close $cwtr;
  close $cerr;

  if (length $opts{'stdin'})
  {
    print {$pwtr} $opts{'stdin'} or die "Failed to write to $self->{_bin}: $!";
  }

  close $pwtr or die "close() on pipe to $self->{_bin} failed: $!";

  my ($output, $error) = ( q<>, q<> );
  $output .= $_ while <$prdr>;
  $error .= $_ while <$perr>;

  close $prdr;
  close $perr;

  waitpid $pid, 0;

  if ($?)
  {
    my $failure = ($? & 0xff) ? "signal $?" : sprintf("error %d", $? >> 8);
    die "$error\n$self->{_bin} failed: $failure";
  }

  return $output;
}

sub _pipe_or_die
{
  pipe( my ($rdr, $wtr) ) or die "pipe() failed $!";

  return ($rdr, $wtr);
}

1; # End of Protocol::ACME::OpenSSL
