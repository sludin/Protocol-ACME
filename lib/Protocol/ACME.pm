package Protocol::ACME;

use 5.007003;
use strict;
use warnings;


our $VERSION = '0.12';

=head1 NAME

Protocol::ACME - Interface to the Let's Encrypt ACME API

=head1 VERSION

Version 0.11

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
     $acme->cleanup_challenge( $challenges->{$domain} );
   }

   my $cert = $acme->sign( $csr_file );
 };
 if ( $@ )
 {
   die if !UNIVERSAL::isa($@, 'Protocol::ACME::Exception');
   die "Error occured: Status: $@->{status},
                       Detail: $@->{detail},
                       Type:   $@->{type}\n";
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
   openssl                 undef
   ua                      HTTP::Tiny->new()
   loglevel                error
   debug                   0
   mailto                  undef

B<host>: The API end point to connect to.  This will generally be acme-staging.api.letsencrypt.org
or acme-v01.api.letsencrypt.org

B<account_key>: The account private key in a scalar ref or filename.  See C<$self->account_key>
for details on this arguemtn.

B<openssl>: The path to openssl.  If this option is used a local version of the openssl binary will
be used for crypto operations rather than C<Crypt::OpenSSL::RSA>.

B<ua>: An HTTP::Tiny object customized as you see fit

B<loglevel>: Set the loglevel to one of the C<Log::Any> values.

B<debug>: If set to non-zero this is a shortcut for C<loglevel => debug>

B<mailto>: This should be the email address that you want associated with your account.  This is used
my Let's Encrypt for expiration notification.

=back

=head2 METHODS

=over

=item account_key( $key_filename )

=item account_key( \$buffer )

=item account_key( \%explicit_args )


C<account_key> will load a the private account key if it was not already loaded
when the C<pProtocol::ACME> object was constructed.  There are three ways to call this:

If the arg is a B<SCALAR> it is assumed to be the filename of the
key.  C<account_key> will throw an error if there are problems reading the file.

If the arg is a B<SCALAR> reference it is assumed to be a buffer that
contains the KEY.

If the arg is a B<HASH> reference it contains named arguments.  The arguments
are:

   KEY          DEFAUL        DESC
   -----------  -----------   -------------------
   filename     undef         The key Filename
   buffer       undef         Buffer containing the key
   format       undef         Explicitly state the format ( DER | PEM )

If both C<filename> and C<buffer> are set the C<buffer> argument will be ignored.

If the format is not explcitly set C<Protocol::ACME> will look at the key and
try and determine what the format it.


=item load_key_from_disk( $key_path )

B<DEPRECATED>

Load a key from disk.  Currently the key needs to be unencrypted.
Callbacks for handling password protected keys are still to come.

=item directory()

Loads the directory from the ACME host.  This call must be made first
before any other calls to the API in order the bootstrap the API
resource list.

=item register( %args )

Call the new-reg resource and create an account associated with the
loaded account key.  If that key has already been registered this method
will gracefully and silently handle that.

Arguments that can be passed in:

   KEY                     DEFAULT
   -----------             --------------------
   mailto                  undef

B<mailto>: See C<new> for a desciption.  This will override the value passed to new
if any.


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

=item cleanup_challenge()

Called after C<check_challenge> to remove the challenge files.

=item $cert = sign( $csr_filename )

=item $cert = sign( \$buffer )

=item $cert = sign( \%explicit_args )


Call C<sign> after the challenge for each domain ( itentifier ) has
been fulfilled.  There are three ways to call this:

If the arg is a B<SCALAR> it is assumed to be the filename of the
CSR.  C<sign> will throw an error if there are problems reading the file.

If the arg is a B<SCALAR> reference it is assumed to be a buffer that
contains the CSR.

If the arg is a B<HASH> reference it contains named arguments.  The arguments
are:

   KEY          DEFAUL        DESC
   -----------  -----------   -------------------
   filename     undef         The CSR Filename
   buffer       undef         Buffer containing the CSR
   format       undef         Explicitly state the format ( DER | PEM )

If both C<filename> and C<buffer> are set the C<buffer> argument will be ignored.

If the format is not explcitly set Protocol::ACME will look at the CSR and
try and determine what the format it.

On success C<Protocol::ACME> will return the DER encoded signed certificate.

=item $cert_chain = chain()

After C<sign> has been called and a cert successfully created, C<chain> will
fetch and return the DER encoded certificate issuer.

=item revoke( $certfile )

Call C<revoke> to revoke an already issued certificate. C<$certfile>
must point the a DER encoded form of the certificate.

=item recovery_key()

LE does not yet support recovery keys.  This method will die when
called.


=back

=cut

package Protocol::ACME;

use strict;
use warnings;

use Protocol::ACME::Exception;
use Protocol::ACME::Utils;

use Crypt::Format;
use Crypt::RSA::Parse ();

use MIME::Base64 qw( encode_base64url decode_base64url decode_base64 encode_base64 );

use HTTP::Tiny;
use JSON;
use Digest::SHA qw( sha256 );
use Carp;


my $USERAGENT = "Protocol::ACME v$VERSION";
my $NONCE_HEADER = "replay-nonce";

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

  # TODO: There are more elegant and well baked ways to take care of the
  #       parameter handling that I am doing here
  $self->{host}     = $args->{host}    if exists $args->{host};
  $self->{ua}       = $args->{ua}      if exists $args->{ua};
  $self->{openssl}  = $args->{openssl} if exists $args->{openssl};
  $self->{debug}    = $args->{debug}   if exists $args->{debug};
  $self->{loglevel} = exists $args->{loglevel} ? $args->{loglevel} : "error";
  $self->{contact}->{mailto} = $args->{mailto} if exists $args->{mailto};

  if ( $self->{debug} )
  {
    $self->{loglevel} = "debug";
  }

  if ( ! exists $self->{ua} )
  {
    $self->{ua} = HTTP::Tiny->new( agent => $USERAGENT, verify_SSL => 1 );
  }

  if ( ! exists $self->{host} )
  {
    _throw( detail => "host parameter is required for Protocol::ACME::new" );
  }

  $self->{log} = $args->{'logger'} || do
  {
      require Log::Any::Adapter;
      Log::Any::Adapter->set('+Protocol::ACME::Logger', log_level => $self->{loglevel});
      Log::Any->get_logger;
  };

  if ( exists $args->{account_key} )
  {
    $self->account_key( $args->{account_key} );
  }

  $self->{links}->{directory} = "https://" . $self->{host} . '/directory';

  $self->{nonce} = undef;


}

sub _throw
{
  my (@args) = @_;
  if ( scalar(@_) == 1 )
  {
    @args = ( detail => $_[0] );
  }
  croak ( Protocol::ACME::Exception->new( { @args } ) );
}

sub load_key
{
  my ($self, $keystring) = @_;
  return $self->account_key( \$keystring );
}

sub load_key_from_disk
{
  my $self   = shift;
  my $path   = shift;

  return $self->account_key($path);
}

sub account_key
{
  my $self = shift;
  my $key = shift;

  my %args = ( filename => undef,
               buffer   => undef,
               format   => undef );

  if ( ! ref $key )
  {
    $args{filename} = $key;
  }
  elsif( ref $key eq "SCALAR" )
  {
    $args{buffer} = $$key;
  }
  else
  {
    @args{ keys %$key } = values %$key;
  }

  if ( $args{filename} )
  {
    $args{buffer} = _slurp( $args{filename} );
    if ( ! $args{buffer} )
    {
      _throw( "Could not load key from file $args{filename}: $!" );
    }
  }

  if ( ! $args{buffer} )
  {
    _throw( "Either a buffer or filename must be passed" );
  }

  if ( ! $args{format} )
  {
    $args{format} = Protocol::ACME::Utils::looks_like_pem( $args{buffer} ) ? "PEM" : "DER";
  }

  my $keystring = $args{buffer};
  # TODO: This should detect/handle PKCS8-formatted private keys as well.
  if ( $args{format} eq "DER" )
  {
    $keystring = Crypt::Format::der2pem( $keystring, "RSA PRIVATE KEY" );
  }

  if ( exists $self->{openssl} )
  {
    require Protocol::ACME::Key;
    $key = Protocol::ACME::Key->new( keystring => $keystring,
                                     openssl   => $self->{openssl} );
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

    $key = Crypt::OpenSSL::RSA->new_private_key($keystring);
  }

  if ( ! $key )
  {
    _throw( "Could not load key into key structure" );
  }

  $key->use_sha256_hash();

  $self->{key}->{key} = $key;

  my ( $n_b64, $e_b64 ) = map { encode_base64url(_bigint_to_binary($_)) } $key->get_key_parameters();
  $self->{key}->{n} = $n_b64;
  $self->{key}->{e} = $e_b64;

  $self->{log}->debug( "Private key loaded" );

}




sub directory
{
  my $self = shift;

  my $resp = $self->_request_get( $self->{links}->{directory} );



  if ( $resp->{status} != 200 )
  {
    _throw( detail => "Failed to fetch the directory for $self->{host}", resp => $resp );
  }

  my $data = _decode_json( $resp->{content} );

  @{$self->{links}}{keys %$data} = values %$data;


  $self->{log}->debug( "Let's Encrypt Directories loaded." );
}

#
# Register the account or load the reg url for an existing account ( new-reg or reg )
#
sub register
{
  my $self = shift;
  my %args = @_;

  my $obj = {};
  $obj->{resource} = 'new-reg';

  if ( exists $args{mailto} )
  {
    push @{$obj->{contact}}, "mailto:$args{mailto}";
  }
  elsif ( exists $self->{contact}->{mailto} )
  {
    push @{$obj->{contact}}, "mailto:$self->{contact}->{mailto}";
  }

  my $msg = _encode_json( $obj );

  my $json = $self->_create_jws( $msg );

  $self->{log}->debug( "Sending registration message" );

  my $resp = $self->_request_post( $self->{links}->{'new-reg'}, $json );

  if ( $resp->{status} == 409 )
  {
    $self->{links}->{'reg'} = $resp->{headers}->{'location'};

    $self->{log}->debug( "Known key used" );
    $self->{log}->debug( "Refetching with location URL" );

    my $json = $self->_create_jws( _encode_json( { "resource" => 'reg' } ) );

    $resp = $self->_request_post( $self->{links}->{'reg'}, $json );

    if ( $resp->{status} == 202 )
    {
      my $links = _link_to_hash( $resp->{headers}->{'link'} );

      @{$self->{links}}{keys %$links} = values %$links;
    }
    else
    {
      _throw( @{ $self->{content} } );
    }
  }
  elsif ( $resp->{status} == 201 )
  {
    my $links = _link_to_hash( $resp->{headers}->{'link'} );

    @{$self->{links}}{keys %$links} = values %$links;

    $self->{links}->{'reg'} = $resp->{headers}->{'location'};
    $self->{log}->debug( "New key used" );
  }
  else
  {
    _throw( @{ $self->{content} } );
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
  _throw( "$keyfile: $!" ) if ! $pem;

  my $url = "https://acme-staging.api.letsencrypt.org/acme/reg/101834";

  my $der = Crypt::Format::pem2der( $pem );

  my $pub = Crypt::PK::ECC->new( \$der );

  my $public_json_text = $pub->export_key_jwk('public');

  my $hash = $pub->export_key_jwk( 'public', 1 );

  my $msg = { "resource"     => "reg",
              "recoveryToken" => {
                "client"       => { "kty" => "EC",
                                    "crv" => "P-256",
                                    "x"   => $hash->{x},
                                    "y"   => $hash->{y}
                                  }
              }
            };

  my $json = $self->_create_jws( _encode_json($msg) );

  my $resp = $self->_request_post( $url, $json );

  # TODO: This is not complete
}

sub accept_tos
{
  my $self = shift;

  if ( exists $self->{reg}->{agreement} )
  {
    $self->{log}->debug( "TOS already accepted. Skipping" );
    return;
  }

  $self->{log}->debug( "Accepting TOS" );
  # TODO: check for existance of terms-of-service link
  # TODO: assert on reg url being present

  my $msg = _encode_json( { "resource"  => "reg",
                             "agreement" => $self->{links}->{'terms-of-service'},
                             "key"       => { "e"   => $self->{key}->{e},
                                             "kty" => "RSA",
                                             "n"   => $self->{key}->{n} } } );


  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'reg'}, $json );

  if ( $resp->{status} == 202 )
  {
    $self->{log}->debug( "Accepted TOS" );
  }
  else
  {
    _throw( @{ $self->{content} } );
  }
}

sub revoke
{
  my $self = shift;
  my $certfile = shift;

  $self->{log}->debug( "Revoking Cert" );

  my $cert = _slurp( $certfile );

  if ( ! $cert )
  {
    _throw("Could not load cert from $certfile: $!");
  }


  my $msg = _encode_json( { "resource"    => "revoke-cert",
                            "certificate" => encode_base64url( $cert ) } );


  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'revoke-cert'}, $json );

  if ( $resp->{status} != 200 )
  {
    _throw( @{ $self->{content} } );
  }

}

sub authz
{
  my $self   = shift;
  my $domain = shift;

  $self->{log}->debug( "Sending authz message for $domain" );
  # TODO: check for 'next' URL and that is it authz

  my $msg = _encode_json( { "identifier" => { "type" => "dns", "value" => $domain },
                            "resource"   => "new-authz" } );

  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{next}, $json );

  if ( $resp->{status} == 201 )
  {
    $self->{challenges} = $self->{content}->{challenges};
  }
  else
  {
    _throw( @{ $self->{content} } );
  }
}

sub handle_challenge
{
  my $self      = shift;
  my $challenge = shift;
  my @args = @_;

  my $key = $self->{key};

  my $jwk = _encode_json( { "e" => $key->{e}, "kty" => "RSA", "n" => $key->{n} } );
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

  $self->{log}->debug( "Handing challenge for token: $token.$fingerprint" );

  my $ret = $challenge->handle( $token, $fingerprint, @args );

  if ( $ret == 0 )
  {
    $self->{fingerprint} = $fingerprint;
    $self->{token} = $token;
    $self->{links}->{challenge} = $challenge_url;
  }
  else
  {
    _throw( status => 0, detail => $ret, type => "challenge_exec" );
  }
}


sub check_challenge
{
  my $self = shift;

  my $msg = _encode_json( { "resource" => "challenge", "keyAuthorization" => $self->{token} . '.' . $self->{fingerprint} } );

  my $json = $self->_create_jws( $msg );


  my $resp = $self->_request_post( $self->{links}->{challenge}, $json );

  my $status_url = $self->{content}->{uri};

  # TODO: check for failure of challenge check
  # TODO: check for other HTTP failures

  $self->{log}->debug( "Polling for challenge fulfillment" );
  while( 1 )
  {
    $self->{log}->debug( "Status: $self->{content}->{status}" );
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

sub cleanup_challenge
{
  my $self = shift;
  my $challenge = shift;
  return $challenge->cleanup();
}

sub sign
{
  my $self = shift;
  my $csr = shift;

  $self->{log}->debug( "Signing" );

  my %args = ( filename => undef,
               buffer   => undef,
               format   => undef );

  if ( ! ref $csr )
  {
    $args{filename} = $csr;
  }
  elsif( ref $csr eq "SCALAR" )
  {
    $args{buffer} = $$csr;
  }
  else
  {
    @args{keys %$csr} = values %$csr;
  }

  if ( $args{filename} )
  {
    $args{buffer} = _slurp( $args{filename} );
    if ( ! $args{buffer} )
    {
      _throw( "Could not load CSR from file $args{filename}" );
    }
  }

  if ( ! $args{buffer} )
  {
    _throw( "Either a buffer or filename must be passed to sign" );
  }

  if ( ! $args{format} )
  {
    $args{format} = Protocol::ACME::Utils::looks_like_pem( $args{buffer} ) ? "PEM" : "DER";
  }

  my $der = $args{format} eq "DER" ? $args{buffer} : Crypt::Format::pem2der( $args{buffer} );

  my $msg = _encode_json( { "resource" => "new-cert", "csr" => encode_base64url( $der ) } );

  my $json = $self->_create_jws( $msg );

  my $resp = $self->_request_post( $self->{links}->{'new-cert'}, $json, 1 );

  if ( $resp->{status} != 201 )
  {
    _throw( %{_decode_json($resp->{content}) } );
  }

  my $links = _link_to_hash( $resp->{headers}->{'link'} );

  $self->{links}->{chain} = $links->{up} if exists $links->{up};
  $self->{links}->{cert}  = $resp->{headers}->{location} if exists $resp->{headers}->{location};

  $self->{cert} = $resp->{content};

  return $self->{cert};
}

sub chain
{
  my $self = shift;

  if ( ! exists $self->{links}->{chain} )
  {
    _throw( "URL for the cert chain missing.  Has sign() been called yet?" );
  }

  my $resp = $self->_request_get( $self->{links}->{chain}, 1 );

  if ( $resp->{status} != 200 )
  {
    _throw( detail => "Error received fetching the certificate chain",
            status => $resp->{status}  );
  }

  $self->{chain} = $resp->{content};

  return $self->{chain};
}

#############################################################
### "Private" functions

sub _request_get
{
  my $self = shift;
  my $url  = shift;
  my $nodecode = shift || 0;

  my $resp = $self->{ua}->get( $url );

  $self->{nonce} = $resp->{headers}->{$NONCE_HEADER};
  $self->{json} = $resp->{content};

  #Exception here should be fatal.
  $self->{content} = undef;
  $self->{content} = _decode_json( $resp->{content} ) unless $nodecode;

  $self->{response} = $resp;

  return $resp;
}

sub _request_post
{
  my $self     = shift;
  my $url      = shift;
  my $content  = shift;
  my $nodecode = shift || 0;

  my $resp = $self->{ua}->post( $url, { content => $content } );

  $self->{nonce} = $resp->{headers}->{$NONCE_HEADER};

  $self->{json} = $resp->{content};

  #Let exception from decode_json() propagate:
  #if we failed to decode the JSON, that’s a show-stopper.
  $self->{content} = undef;
  $self->{content} = _decode_json( $resp->{content} ) unless $nodecode;

  $self->{response} = $resp;

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

  open my $fh, '<', $filename or return undef;

  sysread( $fh, my $content, -s $fh ) or return undef;

  return $content;
}


sub _link_to_hash
{
  my $arrayref = shift;
  my $links;

  return {} unless $arrayref;

  if ( ! ref $arrayref )
  {
    $arrayref = [ $arrayref ];
  }

  for my $link ( @$arrayref )
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

sub _bigint_to_binary {
    my ( $bigint ) = @_;

    # TODO: Inelegant hack to deal with different Bignum implementations
    my $hex;
    if ( UNIVERSAL::isa( $bigint, "Math::BigInt" ) )
    {
      $hex = substr( $bigint->as_hex(), 2 );
      #Prefix a 0 as needed to get an even number of digits.
      if (length($hex) % 2) {
        substr( $hex, 0, 0, 0 );
      }

      return pack 'H*', $hex;
    }
    else
    {
      $bigint->to_bin();
    }

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

  my $json = _encode_json( $jws );

  return $json;

}

sub _decode_json
{
  my $ref = shift;
  return JSON->new->allow_nonref->decode($ref);
}

sub _encode_json
{
  my $ref = shift;
#  my $json = JSON->new();
#  $json->canonical();
  #  return $json->encode($ref);
  return JSON->new->canonical->encode($ref);
}


=head1 AUTHOR

Stephen Ludin, C<< <sludin at ludin.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-protocol-acme at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Protocol-ACME>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

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


=head1 CONTRIBUTORS

Felipe Gasper, C<< <felipe at felipegasper.com> >>

=head1 ACKNOWLEDGEMENTS



=head1 LICENSE AND COPYRIGHT

Copyright 2015 Stephen Ludin.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Version 0.11
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
