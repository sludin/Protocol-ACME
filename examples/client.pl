use strict;
use warnings;
use Protocol::ACME;
use Protocol::ACME::Challenge::Manual;
use Protocol::ACME::Challenge::SimpleSSH;
use Protocol::ACME::Challenge::LocalFile;
use IO::File;


use Data::Dumper;

my $host = "acme-staging.api.letsencrypt.org";  # LE Staging Server
#my $host = "acme-v01.api.letsencrypt.org";     # LE Production Server

# Note: calls to the LE production server are rate limited.  Use it only
# after you have fully debugged your script against staging

# IMPORTANT: This script is not intended to be a fully functional client
#            for handling the creation and renewal of certificates.  Its
#            goal is to demonstrate the usage of the Protocol::ACME library.
#            For a fully functional client built on Protocol::ACME I recommend
#            looking at Tobias Oetiker's AcmeFetch client:
#              https://github.com/oetiker/AcmeFetch
#

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
#   $ openssl req -new -out test.csr -outform der -key cert_key.pem -config openssl.cnf \
#                 -reqexts SAN -subj "/CN=domain.example.com" -sha256
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
  require Convert::X509;
  @names = pull_identifiers_from_csr( $csr_file );
}
else
{
  @names = split( /,/, $names );
}

my $challenges = {
                   'www.ludin.org' => Protocol::ACME::Challenge::SimpleSSH->new(
                     { ssh_host => "bluehost", www_root => "./www" }
                   ),
                   'cloud.ludin.org' => Protocol::ACME::Challenge::SimpleSSH->new(
                     { ssh_host => "home", www_root => "/opt/local/www/htdocs" }
                   )
                 };

eval
{

  my $data = Protocol::ACME::_slurp( $account_key_file );

  my $acme = Protocol::ACME->new( host               => $host,
                                  account_key        => \$data,
                                  debug              => 1,
                                  mailto             => 'sludin@ludin.org'
                                  #openssl            => "/opt/local/bin/openssl",
                                );



  # The first request is for the directory.  This provides
  # all of the top level resources. All urls needed will come
  # from these resources, the location header, or the link
  # header(s).
  $acme->directory();

  # Register will call the new-reg resource and create an account associated
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

    $acme->handle_challenge( $challenges->{$domain} );

    $acme->check_challenge();

    $acme->cleanup_challenge( $challenges->{$domain} );
  }


  my $buf = Protocol::ACME::_slurp( $csr_file );
  my $cert = $acme->sign( $csr_file );

  my $fh = IO::File->new( $cert_file, "w" ) || die "Could not open cert file for write: $!";
  print $fh $cert;
  $fh->close();

  my $chain = $acme->chain();
  # Do something rational with the cert chain, like save it somewhere.

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
