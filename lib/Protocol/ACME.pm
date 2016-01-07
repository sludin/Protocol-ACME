package Protocol::ACME;

use 5.007003;
use strict;
use warnings;

our $VERSION = '0.04';

=head1 NAME

Protocol::ACME - Interface to the Let's Encrypt ACME API

=head1 VERSION

Version 0.04

=head1 SYNOPSIS

 use Protocol::ACME;

 my @names = qw( www.example.com cloud.example.com );

 my $challenges = {
                    'www.example.com'   => Protocol::ACME::Challenge::SimpleSSH->new(
                      { ssh_host => "host1", www_root => "~/www" }
                    ),
                   'cloud.example.com' => Protocol::ACME::Challenge::SimpleSSH->new(
                     { ssh_host => "home2", www_root => "/opt/local/www/htdocs" }
                   )
                 };

 eval
 {
   my $acme = Protocol::ACME->new( host               => $host,
                                   account_key        => $account_key_pem_or_der,
                                 );

   $acme->directory();

   $acme->register();

   $acme->accept_tos();

   for my $domain ( @names )
   {
     $acme->authz( $domain );

     $acme->handle_challenge( $challenges->{$domain} );

     $acme->check_challenge();
   }

   my $cert = $acme->sign( $csr_file );
 };
 if ( $@ )
 {
   die $@ if ref $@ ne "Protocol::ACME::Exception";
   print "Error occured: Status: $@->{status},
                         Detail: $@->{detail},
                         Type: $@->{type}\n";
 }
 else
 {
   # do something appropriate with the DER encoded cert
   print "Success\n";
 }

=head1 DESCRIPTION

The C<Protocol::ACME> is a class implementing an interface for the
Let's Encrypt ACME API.

NOTE: This code at this point is functional but should be considered
'alpha' quality.

The class handles the protocol details behind provisioning a Let's
Encrypt certificate.

=head1 CONSTRUCTOR METHODS

The following constructor methods are available:

=over 4

=item $acme = Protcol::ACME->new( %options )

This method constructs a new C<Protocl::ACME> object and returns it.
Key/value pair arguments may be provided to set up the initial state.
The may be passed in as a hash or a hashref. The following options
correspond to attribute methods described below. Items marked with
a * are required.

   KEY                     DEFAULT
   -----------             --------------------
   *host                   undef
   account_key             undef
   account_key_path        undef
   openssl                 undef

B<host>: The API end point to connect to.  This will generally be acme-staging.api.letsencrypt.org
or acme-v01.api.letsencrypt.org

B<account_key>: The account private key as a string. DER or PEM format. Excludes C<account_key_path>.

B<account_key_path>: The filesystem path to the account private key. Excludes C<account_key>.

B<openssl>: The path to openssl.  If this option is used a local version of the openssl binary will
be used for crypto operations rather than C<Crypt::OpenSSL::RSA>.

=back

=head2 METHODS

=over

=item load_key_from_disk( $key_path )

Load a key from disk.  Currently the key needs to be unencrypted.
Callbacks for handling password protected keys are still to come.

=item directory()

Loads the directory from the ACME host.  This call must be made first
before any other calls to the API in order the bootstrap the API
resource list.

=item register()

Call the new-reg resource and create an account associated with the
loaded account key.  If that key has already been registered this method
will gracefully and silently handle that.

=item accept_tos()

In order to use the Let's Encrypt service, the account needs to accept
the Terms of Service.  This is provided in a link header in response
to the new-reg ( or reg ) resouce call.  If the TOS have already been
accepted as indicated by the reg structure returned by the API this
call will be a noop.

=item authz( $domain )

C<authz> needs to be called for each domain ( called identifiers in
ACME speak ) in the certifcate.  This included the domain in the subject
as well as the Subject Alternate Name (SAN) fields.  Each call to
C<authz> will result in a challenge being issued from Let's Encrypt.
These challenges need to be handled individually.

=item handle_challenge( $challenge_object )

C<handle_challenge> is called for each challenge issued by C<authz>.
The challenge object must be a subclass of C<Protocol::ACME::Challenge>
which implements a 'handle' method.  This objects handle method
will be passed three arguments and is expected to fulfill the
preconditions for the chosen challenge.  The three areguments
are:

  fingerprint: the sha256 hex digest of the account key
  token: the challenge token
  url: the url returned by the challenge

Fully describing how to handle every challenge type of out of the
scope of this documentation ( at least for now ).  Two challenge
classes have been included for reference:

C<Protocol::ACME::Challenge::SimpleSSH> is initialized with the
ssh host name and the www root for the web server for the http-01
challenge.  It will ssh to the host and create the file in
the correct location for challenge fulfillment.

C<Protocol::ACME::Challenge::LocalFile> is initialized with just the
www root for the web server for the http-01 challenge.  It will
simply create the challenge file in the correct place on the local
filesystem.

C<Protocol::ACME::Challenge::Manual> is intended to be run in an
interactive manner and will stop and prompt the user with the relevant
information so they can fulfill the challenge manually.

but below is an example for handling the simpleHTTP ( http-01 )
challenge.


=item check_challenge()

Called after C<handle_challenge>.  This will poll the challenge status
resource and will return when the state changes from 'pending'.

=item $cert = sign( $csr )


Call C<sign> after the challenge for each domain ( itentifier ) has
been fulfilled.  C<$csr> is the DER encoded Certificate Signing
Request ( CSR ).  On success Let's Encrypt will return the DER encoded
signed certificate.

=item revoke( $certfile )

Call C<revoke> to revoke an already issued certificate. C<$certfile>
must point the a DER encoded form of the certificate.

=item recovery_key()

LE does not yet support recovery keys.  This method will die when
called.


=back

=cut


package Log::Any::Adapter::AcmeLocal;

use Log::Any::Adapter::Util ();
use Time::HiRes qw( gettimeofday );
use base qw/Log::Any::Adapter::Base/;

my $trace_level = Log::Any::Adapter::Util::numeric_level('trace');

sub init {
    my ($self) = @_;
    if ( exists $self->{log_level} ) {
        $self->{log_level} =
          Log::Any::Adapter::Util::numeric_level( $self->{log_level} )
          unless $self->{log_level} =~ /^\d+$/;
    }
    else {
        $self->{log_level} = $trace_level;
    }
}

foreach my $method ( Log::Any::Adapter::Util::logging_methods() ) {
    no strict 'refs';
    my $method_level = Log::Any::Adapter::Util::numeric_level($method);
    *{$method} = sub {
        my ( $self, $text ) = @_;
        return if $method_level > $self->{log_level};

        my ( $sec, $usec ) = gettimeofday();

        printf STDOUT "%d.%06d %s\n", $sec, $usec, $text;
    };
}

foreach my $method ( Log::Any::Adapter::Util::detection_methods() ) {
    no strict 'refs';
    my $base = substr( $method, 3 );
    my $method_level = Log::Any::Adapter::Util::numeric_level($base);
    *{$method} = sub {
        return !!( $method_level <= $_[0]->{log_level} );
    };
}


package Protocol::ACME::Exception;

sub new
{
  my $class = shift;

  my $error = shift;
  my $self = { status => 0, detail => "", type => "unknown" };

  if ( ref $error eq "HASH" )
  {
    @$self{keys %$error} = values %$error;
  }
  elsif ( ref $error )
  {
    $self->{detail} = "double error: bad arg passed to exception constructor";
  }
  else
  {
    $self->{detail} = $error;
  }

  bless $self, $class;

  return $self;
}


package Protocol::ACME;

use strict;
use warnings;

use Protocol::ACME::Utils;

use Crypt::RSA::Parse ();

use MIME::Base64 qw( encode_base64url decode_base64url decode_base64 encode_base64 );

use LWP::UserAgent;
use JSON;
# use Crypt::OpenSSL::EC; For key recovery when the API supports it
# use Crypt::PK::ECC;
use Digest::SHA qw( sha256 );
use Log::Any qw( $log );
use Log::Any::Adapter ('AcmeLocal', log_level => 'debug' );

use Carp;



my $NONCE_HEADER = "Replay-Nonce";

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

  if ( ref $_[0] eq "HASH" )
  {
    $args = $_[0];
  }
  else
  {
    %$args = @_;
  }

  $self->{host} = $args->{host} if exists $args->{host};
  $self->{ua} = $args->{ua} if exists $args->{ua};
  $self->{openssl} = $args->{openssl} if exists $args->{openssl};

  if ( ! exists $self->{ua} )
  {
    $self->{ua} = LWP::UserAgent->new();
  }

  if ( ! exists $self->{host} )
  {
    die Protocol::ACME::Exception->new( { detail => "host parameter is required for Protocol::ACME::new" } );
  }

  if ( exists $args->{account_key} )
  {
    if (defined $args->{account_key_path}) {
      _throw( detail => "You cannot submit both â€œaccount_keyâ€ and â€œaccount_key_pathâ€ to Protocol::ACME::new()." );
    }

    if ( UNIVERSAL::isa($args->{account_key}, "Crypt::OpenSSL::RSA") )
    {
      $self->{key} = $args->{account_key};
      # TODO: add derivatives
    }
    else
    {
      $self->load_key( $args->{'account_key'} );
    }
  }
  elsif (exists $args->{account_key_path})
  {
    $self->load_key_from_disk( $args->{account_key_path} );
  }
  else
  {
    _throw( detail => "You must submit one (and only one) of either â€œaccount_keyâ€ or â€œaccount_key_pathâ€." );
  }

  $self->{links}->{directory} = "https://" . $self->{host} . '/directory';

  $self->{nonce} = undef;
}

sub _throw
{
  my (@args) = @_;
  die Protocol::ACME::Exception->new( { @args } );
}

sub load_key_from_disk
{
  my $self   = shift;
  my $path   = shift;

  my $keystring = _slurp( $path );
  if ( ! $keystring )
  {
    croak( Protocol::ACME::Exception->new( { detail => "Could not open the key file ($path): $!" } ) );
  }

  return $self->load_key($keystring);
}

sub load_key
{
  my ($self, $keystring) = @_;

  my $key;

  if ( exists $self->{openssl} )
  {
    require Protocol::ACME::Key;
    # TODO: DER format for the openssl path?
    $key = Protocol::ACME::Key->new( keystring => $keystring,
                                                     openssl => $self->{openssl} );
  }
  else
  {
    eval
    {
      require Crypt::OpenSSL::RSA;
      require Crypt::OpenSSL::Bignum;
    };
    if ( $@ )
    {
      die "Invoked usage requires Crypt::OpenSSL::RSA and Crypt::OpenSSL::Bignum. " .
      "To avoid these dependencies use the openssl parameter when creating the " .
      "Protocol::ACME object.  This will use a native openssl binary instead.";
    }

    if ( !Protocol::ACME::Utils::looks_like_pem($keystring) )
    {

      #TODO: This should detect/handle PKCS8-formatted private keys as well.
      $keystring = Protocol::ACME::Utils::der2pem( $keystring, "RSA PRIVATE KEY" );
      print $keystring;
    }

    $key = Crypt::OpenSSL::RSA->new_private_key($keystring);
  }

  if ( ! $key )
  {
    die Protocol::ACME::Exception->new( { detail => "Could not load key into key structure" } );
  }

  $key->use_sha256_hash();

  $self->{key}->{key} = $key;

  my ( $n_b64, $e_b64 ) = map { encode_base64url(_bigint_to_binary($_)) } $key->get_key_parameters();
  $self->{key}->{n} = $n_b64;
  $self->{key}->{e} = $e_b64;

  $log->debug( "Private key loaded" );
}


sub directory
{
  my $self = shift;

  my $resp = $self->_request_get( $self->{links}->{directory} );

  if ( $resp->code() != 200 )
  {
    die Protocol::ACME::Exception->new( { detail => "Failed to fetch the directory for $self->{host}", resp => $resp } );
  }

  my $data = decode_json( $resp->content() );

  @{$self->{links}}{keys %$data} = values %$data;

  $log->debug( "Let's Encrypt Directories loaded." );
}

#
# Register the account or load the reg url for an existing account ( new-reg or reg )
#
sub register
{
  my $self = shift;

  my $msg = encode_json( { resource => 'new-reg' } );
  my $json = $self->_create_jws( $msg );

  $log->debug( "Sending registration message" );

  my $resp = $self->_request_post( $self->{links}->{'new-reg'}, $json );

  if ( $resp->code() == 409 )
  {
    $self->{links}->{'reg'} = $resp->header( 'location' );

    $log->debug( "Known key used" );
    $log->debug( "Refetching with location URL" );

    my $json = $self->_create_jws( encode_json( { "resource" => 'reg' } ) );

    $resp = $self->_request_post( $self->{links}->{'reg'}, $json );

    if ( $resp->code() == 202 )
    {
      my $links = _link_to_hash( $resp->header( 'link' ) );

      @{$self->{links}}{keys %$links} = values %$links;
    }
    else
    {
      die Protocol::ACME::Exception->new( $self->{content} );
    }
  }
  elsif ( $resp->code() == 201 )
  {
    my $links = _link_to_hash( $resp->header( 'link' ) );

    @{$self->{links}}{keys %$links} = values %$links;

    $self->{links}->{'reg'} = $resp->header( 'location' );
    $log->debug( "New key used" );
  }
  else
  {
    die Protocol::ACME::Exception->new( $self->{content} );
  }

  $self->{reg} = $self->{content};
}

sub recovery_key
{
  # LE does not yet support the key recovery resource
  # the below can be considered debug code

  die "Let's Encrypt does not yet support key recovery";

  my $self = shift;

  my $keyfile = shift;


  my $pem = _slurp( $keyfile );
  croak( Protocol::ACME::Exception->new( { detail => "$keyfile: $!" } ) ) if ! $pem;

  my $url = "https://acme-staging.api.letsencrypt.org/acme/reg/101834";

  my $der = Protocol::ACME::Utils::pem2der( $pem );

  my $pub = Crypt::PK::ECC->new( \$der );

  my $public_json_text = $pub->export_key_jwk('public');

  my $hash = $pub->export_key_jwk( 'public', 1 );

  my $msg = { "resource"     => "reg",
              "recoveryToken" => {
                "client"      => { "kty" => "EC",
                                   "crv" => "P-256",
                                   "x"   => $hash->{x},
                                   "y"   => $hash->{y}
                                 }
              }
            };

  my $json = $self->_create_jws( _hash_to_json($msg) );

  my $resp = $self->_request_post( $url, $json );

  # TODO: This is not complete
}

sub accept_tos
{
  my $self = shift;

  if ( exists $self->{reg}->{agreement} )
  {
    $log->debug( "TOS already accepted. Skipping" );
    return;
  }

  $log->debug( "Accepting TOS" );
  # TODO: check for existance of terms-of-service link
  # TODO: assert on reg url being present

  my $msg = _hash_to_json( { "resource"  => "reg",
                             "agreement" => $self->{links}->{'terms-of-service'},
                             "key"       => { "e"   => $self->{key}->{e},
                                             "kty" => "RSA",
                                             "n"   => $self->{key}->{n} } } );


  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'reg'}, $json );

  if ( $resp->code() == 202 )
  {
    $log->debug( "Accepted TOS" );
  }
  else
  {
    die Protocol::ACME::Exception->new( $self->{content} );
  }
}

sub revoke
{
  my $self = shift;
  my $certfile = shift;

  $log->debug( "Revoking Cert" );

  my $cert = _slurp( $certfile );

  if ( ! $cert )
  {
    # TODO: should be an ACME exception
    die "Could not load cert form $certfile";
  }


  my $msg = _hash_to_json( { "resource"    => "revoke-cert",
                            "certificate" => encode_base64url( $cert ) } );


  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'revoke-cert'}, $json );

  if ( $resp->code() != 200 )
  {
    die Protocol::ACME::Exception->new( $self->{content} );
  }

}

sub authz
{
  my $self   = shift;
  my $domain = shift;

  $log->debug( "Sending authz message for $domain" );
  # TODO: check for 'next' URL and that is it authz

  my $msg = _hash_to_json( { "identifier" => { "type" => "dns", "value" => $domain },
                            "resource"   => "new-authz" } );

  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{next}, $json );

  if ( $resp->code() == 201 )
  {
    $self->{challenges} = $self->{content}->{challenges};
  }
  else
  {
    die Protocol::ACME::Exception->new( $self->{content} );
  }
}

sub handle_challenge
{
  my $self      = shift;
  my $challenge = shift;
  my @args = @_;

  my $key = $self->{key};

  my $jwk = _hash_to_json( { "e" => $key->{e}, "kty" => "RSA", "n" => $key->{n} } );
  my $token;
  my $challenge_url;

  # TODO: this is feeling hardcoded and messy - and fragile
  #       how do we handle other auth challenges?
  #       This is hardcoded for http-01
  for ( @{$self->{challenges}} )
  {
    if ( $_->{type} eq "http-01" )
    {
      $token = $_->{token};
      $challenge_url = $_->{uri};
    }
  }


  my $fingerprint = encode_base64url( sha256( $jwk ) );

  $log->debug( "Handing challenge for token: $token.$fingerprint" );

  my $ret = $challenge->handle( $token, $fingerprint, @args );

  if ( $ret == 0 )
  {
    $self->{fingerprint} = $fingerprint;
    $self->{token} = $token;
    $self->{links}->{challenge} = $challenge_url;
  }
  else
  {
    die Protocol::ACME::Exception->new( { status => 0, detail => $ret, type => "challenge_exec" } );
  }
}


sub check_challenge
{
  my $self = shift;

  my $msg = _hash_to_json( { "resource" => "challenge", "keyAuthorization" => $self->{token} . '.' . $self->{fingerprint} } );

  my $json = $self->_create_jws( $msg );


  my $resp = $self->_request_post( $self->{links}->{challenge}, $json );

  my $status_url = $self->{content}->{uri};

  # TODO: check for failure of challenge check
  # TODO: check for other HTTP failures

  $log->debug( "Polling for challenge fulfillment" );
  while( 1 )
  {
    $log->debug( "Status: $self->{content}->{status}" );
    if ( $self->{content}->{status} eq "pending" )
    {
      sleep(2);
      $resp = $self->_request_get( $status_url );
    }
    else
    {
      last;
    }
  }
}

sub sign
{
  my $self = shift;
  my $csr = shift;

  my $fh = IO::File->new( $csr ) || die $!;
  my $der;
  while( <$fh> )
  {
    $der .= $_;
  }
  $fh->close();


  my $msg = _hash_to_json( { "resource" => "new-cert", "csr" => encode_base64url( $der ) } );

  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'new-cert'}, $json );

  if ( $resp->code() != 201 )
  {
    die Protocol::ACME::Exception->new( $self->{content} );
  }

  my $cert = $resp->content();

  return $cert;
}

#############################################################
### "Private" functions

sub _request_get
{
  my $self = shift;
  my $url  = shift;

  my $resp = $self->{ua}->get( $url );

  $self->{nonce} = $resp->header( $NONCE_HEADER );
  $self->{json} = $resp->content();

    eval {
$self->{content} = decode_json( $resp->content() );
};
  return $resp;
}

sub _request_post
{
  my $self    = shift;
  my $url     = shift;
  my $content = shift;

  my $resp = $self->{ua}->post( $url, Content => $content );

  $self->{nonce} = $resp->header( $NONCE_HEADER );
  $self->{json} = $resp->content();

  eval {
    $self->{content} = decode_json( $resp->content() );
  };

  return $resp;
}

sub _create_jws
{
  my $self = shift;
  my $msg = shift;
  return _create_jws_internal( $self->{key}, $msg, $self->{nonce} );
}


#############################################################
### Helper functions - not class methods

sub _slurp
{
  my $filename = shift;

  my $fh = IO::File->new( $filename );
  if ( ! $fh )
  {
    return;
  }

  my $content;

  while( <$fh> )
  {
    $content .= $_;
  }

  return $content;
}


sub _link_to_hash
{
  my $links;

  for my $link ( @_ )
  {
    my ( $value, $key ) = split( ';', $link );
    my ($url) = $value =~ /<([^>]*)>/;
    my ($rel) = $key =~ /rel=\"([^"]*)"/;

    if ( $url && $rel )
    {
      $links->{$rel} = $url;
    }
    else
    {
      # TODO: Something wonderful
    }
  }

  return $links;
}

sub _hash_to_json
{
  my $hash = shift;
  my $json = "{";
  my $quote = '"';
  my $colon = ':';
  my $comma = ',';

  for ( sort keys %$hash )
  {
    # die "hash_to_json does not handle nested references yet" if ref $hash->{$_};
    if ( ref $hash->{$_} eq "HASH" )
    {
      $json .= $quote . $_ . $quote . $colon . _hash_to_json($hash->{$_}) . $comma;
    }
    else
    {
      $json .= $quote . $_ . $quote . $colon . $quote . $hash->{$_} . $quote . $comma;
    }
  }

  $json =~ s/,$//;

  $json .= '}';
}

sub _bigint_to_binary {
    my ($bigint) = @_;

    my $hex = substr( $bigint->as_hex(), 2 );

    #Prefix a 0 as needed to get an even number of digits.
    if (length($hex) % 2) {
        substr( $hex, 0, 0, 0 );
    }

    return pack 'H*', $hex;
}

sub _create_jws_internal
{
  my $key = shift;
  my $msg = shift;
  my $nonce = shift;

  my $protected_header = '{"nonce": "' . $nonce . '"}';

  my $sig = encode_base64url( $key->{key}->sign( encode_base64url($protected_header) . "." . encode_base64url($msg) ) );

  my $jws = { header    => { alg => "RS256", jwk => { "e" => $key->{e}, "kty" => "RSA", "n" => $key->{n} } },
              protected => encode_base64url( $protected_header ),
              payload   => encode_base64url( $msg ),
              signature => $sig };

  my $json = _hash_to_json( $jws );

  return $json;

}


=head1 AUTHOR

Stephen Ludin, C<< <sludin at ludin.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-protocol-acme at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Protocol-ACME>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 REPOSITORY

https://github.com/sludin/Protocol-ACME

=head1 REPOSITORY

https://github.com/sludin/Protocol-ACME


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Protocol::ACME


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Protocol-ACME>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Protocol-ACME>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Protocol-ACME>

=item * Search CPAN

L<http://search.cpan.org/dist/Protocol-ACME/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 Stephen Ludin.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Protocol::ACME
