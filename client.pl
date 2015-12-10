use strict;
use warnings;
use Protocol::ACME;
use IO::File;

use Convert::X509;

use Data::Dumper;

my $host = "acme-staging.api.letsencrypt.org";
#my $host = "acme-v01.api.letsencrypt.org";


# Usage:
#  Generate a new private key for the Let's Encrypt account. For example:
#    $ openssl genrsa -out account_key.pem 2048
#
#  Generate a new private key for the certificate. For example:
#    $ openssl genrsa -out cert_key.pem 2048
#
#  Generate a certificate signing request (CSR).  For example (for a single domain cert):
#    $ openssl req -new -sha256 -key cert_key.pem -outform der -subj "/CN=cloud.example.org" > csr.der
#
#  Generating a CSR for a SAN cert ( multiple domains ) is a bit more work.  Grab a version
#    of openssl.cnf and add the following:
#
#    [SAN]
#    subjectAltName=DNS:domain1.example.com,DNS:domain2.example.com
#
#   and then generate with something like:
#
#   $ openssl req -new -out test.csr -outform der -key cert_key.pem -config openssl.cnf -reqexts SAN -subj "/CN=domain.example.com" -sha256
#
#   This will create a cert with three domains.  domain.example.com will be in the subject and
#   domain1.example.com and domain2.example.com will be in the SAN extension.
#
#  Tailor the below script to your needs
#

my $account_key_file = shift;
my $csr_file         = shift;
my $cert_file        = shift;
my $names            = shift;

if ( ! $csr_file or ! $account_key_file or ! $cert_file )
{
  die "Usage: perl foo.pl <account_key_file> <csr_file> <cert_file> [<names_comma_delim>]";
}

my @names;

if ( ! $names )
{
  @names = pull_identifiers_from_csr( $csr_file );
}
else
{
  @names = split( /,/, $names );
}

my $challenges = { 'www.example.org'   =>   [ "bluehost", "~/www/.well-known/acme-challenge" ],
                   'cloud.example.org' => [ "home", "/opt/local/www/htdocs/.well-known/acme-challenge" ] };

eval
{

  my $acme = Protocol::ACME->new( host               => $host,
                                  account_key        => $account_key_file,
                                  account_key_format => "PEM" );


  
  # The fist request of for the directory.  This provides
  # all of the top level resources. All urls needed will come
  # from these resources, the location header, or the link
  # header(s).
  $acme->directory();

  # Regsiter will call the new-reg resource and create an accoutn associated
  # with the loaded account key.  If that key has already been registered
  # this method will gracefully and silently handle that.
  $acme->register();

  # In order to use the API you need to accept the TOS.  This takes care
  # of that.  No harm is done if this is an existing account and the TOS
  # have already been accepted. If not done the auth request will return
  # a 403
  $acme->accept_tos();

  # authz will start the process of authenticating the identifiers ( domains )
  # for each domain you call authx, meet_challenge, and send_challenge_met_message
  for my $domain ( @names )
  {
    $acme->authz( $domain );

    $acme->handle_challenge( simple_http_ssh_handler( $challenges->{$domain}->[0],
                                                      $challenges->{$domain}->[1] ) );

    $acme->check_challenge();
  }

  my $cert = $acme->sign( $csr_file );

  my $fh = IO::File->new( $cert_file, "w" ) || die "Could not open cert file for write: $!";
  print $fh $cert;
  $fh->close();

};
if ( $@ )
{
  die $@ if ref $@ ne "Protocol::ACME::Exception";
  print "Error occured: Status: $@->{status}, Detail: $@->{detail}, Type: $@->{type}\n";
}
else
{
  print "Success\n";
}


# new_reg
# reg
# new_authz
# authz
# challenge
# new_cert
# cert
# cert_chain
# revoke

sub simple_http_ssh_handler
{
  my @args = @_;

  return sub {
    my $challenge     = shift;
    my $fingerprint   = shift;
    my $ssh_host      = $args[0];
    my $challenge_dir = $args[1];

    my $cmd = "ssh -q $ssh_host 'echo $challenge.$fingerprint > $challenge_dir/$challenge'";

    # TODO: replace with IO::Pipe
    my $output = `$cmd`;

    return $? == 0 ? 0 : 1;
  };
}

sub pull_identifiers_from_csr
{
  my $csr_file = shift;
  my %names;

  my $fh = IO::File->new( $csr_file ) or die "Could not open CSR: $!";
  my $content;
  while( <$fh> ) { $content .= $_ };

  my $req = Convert::X509::Request->new( $content );


  my $subject = $req->subject()->{CN}->[0];
  $subject =~ s/^.*=//;
  $names{$subject} = 1;

  my $san = $req->{extensions}->{'2.5.29.17'}->{value};
  if ( $san )
  {
    for ( @$san )
    {
      $names{$_->{dNSName}} = 1;
    }
  }

  return keys %names;
}
