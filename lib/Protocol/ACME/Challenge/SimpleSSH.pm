package Protocol::ACME::Challenge::SimpleSSH;

=head1 NAME

Protocol::ACME::Challenge::SimpleSSH - Challenge handler for simpleHttp via SSH

=head1 SYNOPSIS

 use Protocol::ACME::Challenge::SimpleSSH;

 my $args = { 'www_root' => "/path/to/htdocs/or/equivalent",
              'ssh_host' => "ssh.example.com" };
 my $challenge = Protocol::ACME::Challenge::SimpleSSH->new( $args );

...

 $acme->handle_challenge( $challenges->{$domain} );

=head1 DESCRIPTION

The C<Protocol::ACME::Challenge::SimpleSSH> class is a handler intended
to be run when the ACME script is run on a different machine than the
web server.  It will create the challenge file in the designated location
via SSH.  Note that there is no attempt to escalate privleges so the
location will need to be writabel by the ssh user.

=head1 CONSTRUCTOR METHODS

The following constructor methods are available:

=over 4

=item $acme = Protcol::ACME::Challenge::SimpleSSH->new( %options )

This method constructs a new C<Protocol::ACME::Challenge::SimpleSSH> object
and returns it.  Key/value pair arguments may be provided to set up the
initial state. The may be passed in as a hash or a hashref. The following options
correspond to attribute methods described below. Items markes with
a * are required.

   KEY                     DEFAULT
   -----------             --------------------
   *www_root               Path to web root that will handle the HTTP
                           challenge
   *ssh_host               Hostname of the web server for ssh access

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

  $self->{filename} = undef;
}


sub handle
{
  my $self          = shift;
  my $challenge     = shift;
  my $fingerprint   = shift;
  my $dir = "$self->{www_root}/.well-known/acme-challenge";

  my $filename = "$dir/$challenge";

  my @cmd = ('ssh', '-q', $self->{ssh_host}, "mkdir -p '$dir' && echo '$challenge.$fingerprint' > '$filename'");
  system @cmd;

  my $ret = $?;

  $self->{filename} = $filename;

  return $ret == 0 ? 0 : 1;
}

sub cleanup
{
  my $self = shift;

  my @cmd = ('ssh', '-q',  $self->{ssh_host}, "rm -f '$self->{filename}'");
  system @cmd;
}


=head1 AUTHOR

Stephen Ludin, C<< <sludin at ludin.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-protocol-acme at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Protocol-ACME-Challenge-SimpleSSH>.  I will be notified, and then you'll
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
