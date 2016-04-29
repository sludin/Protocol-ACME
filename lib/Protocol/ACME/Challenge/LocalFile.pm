package Protocol::ACME::Challenge::LocalFile;

=head1 NAME

Protocol::ACME::Challenge::LocalFile - Challenge handler for simpleHttp via a local file

=head1 SYNOPSIS

 use Protocol::ACME::Challenge::LocalFile;

 my $args = { 'www_root' => "/path/to/htdocs/or/equivalent" };
 my $challenge = Protocol::ACME::Challenge::LocalFile->new( $args );

...

 $acme->handle_challenge( $challenges->{$domain} );

=head1 DESCRIPTION

The C<Protocol::ACME::Challenge::LocalFile> class is a handler intended
to be run when the ACME script is run on the same local machine as the
web server.  This is a logical choice to use for self contained web
server / Let's Encypt integration.

=head1 CONSTRUCTOR METHODS

The following constructor methods are available:

=over 4

=item $acme = Protcol::ACME::Challenge::LocalFile->new( %options )

This method constructs a new C<Protocol::ACME::Challenge::LocalFile> object
and returns it. Key/value pair arguments may be provided to set up the
initial state. The may be passed in as a hash or a hashref. The following
options correspond to attribute methods described below. Items markes with
a * are required.

   KEY                     DEFAULT
   -----------             --------------------
   *www_root               path to web root that will handle the HTTP
                           challenge

=back

=head2 METHODS

=over

=item handle( $challenge, $fingerprint )

This is intended to be called indirectly via the ACME driver class.
C<handle> will take care of all of the conditions necessary to satisfy
the challenge sent by Let's Encrypt.

=item cleanup

C<cleanup> will remove the challenge file.

=back

=cut

use strict;
use warnings;

use parent qw ( Protocol::ACME::Challenge );
use Carp;
use IO::File;

our $VERSION = '0.12';

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

  $self->{filename} = undef;

}


sub handle
{
  my $self          = shift;
  my $challenge     = shift;
  my $fingerprint   = shift;

  # TODO: put the 'well known path' in a global variable somewhere
  if (not -d $self->{www_root}){
      carp "$self->{www_root} does not exist\n";
  }
  # if we are root this will make us into the correct user for the site
  my ($uid,$gid) = (stat $self->{www_root})[4,5];
  local $) = $gid;local $> = $uid;
  umask 022;
  my $dir = "$self->{www_root}/.well-known/acme-challenge";
  system "mkdir","-p",$dir;
  my $filename = "$dir/$challenge";
  my $content = "$challenge.$fingerprint";

  my $fh = IO::File->new( $filename, "w" );
  if ( ! $fh )
  {
    carp "Could not open $filename for write";
    return 1;
  }

  print $fh $content;
  $fh->close();

  $self->{filename} = $filename;

  return 0;
}

sub cleanup
{
  my $self = shift;
  unlink $self->{filename} if defined $self->{filename};
}

=head1 AUTHOR

Stephen Ludin, C<< <sludin at ludin.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-protocol-acme at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Protocol-ACME-Challenge-LocalFile>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




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

1;
