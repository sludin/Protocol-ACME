package Protocol::ACME::Challenge::Manual;

=head1 NAME

Protocol::ACME::Challenge::Manual - Challenge handler for simpleHttp via manual setup

=head1 SYNOPSIS

 use Protocol::ACME::Challenge::Manual;

 my $challenge = Protocol::ACME::Challenge::Manual->new();

...

 $acme->handle_challenge( $challenge );

=head1 DESCRIPTION

The C<Protocol::ACME::Challenge::Manual> class is a handler intended
to be run interactively.  It will return the challenge and fingerprint
to the user and wait until the user has taken care of the required
conditions.

=head1 CONSTRUCTOR METHODS

The following constructor methods are available:

=over 4

=item $acme = Protcol::ACME::Challenge::Manual->new()

This method constructs a new C<Protocol::ACME::Challenge::Manual> object
and returns it.

=back

=head2 METHODS

=over

=item handle( $challenge, $fingerprint )

This is intended to be called indirectly via the ACME driver class.
C<handle> will prompt the user with the challenge and fingerprint and
wait for the user to indicate that challenge conditions are met.

=back

=cut

use strict;
use warnings;

use parent qw ( Protocol::ACME::Challenge );
use Carp;
use IO::File;

our $VERSION = '1.01';

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
  print "Create a file with the above filename and content under <WWW>/.well-known/acme-challenge\n";
  print "where <WWW> is your web server's document root.  Let's Encrypt will make an HTTP request\n";
  print "for this file and confirm that it has the correct content.";
  print "\n";
  print "Hit return when the file is in place: ";

  my $x = <STDIN>;

  return 0;
}

=head1 AUTHOR

Stephen Ludin, C<< <sludin at ludin.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-protocol-acme at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Protocol-ACME-Challenge-Manual>.  I will be notified, and then you'll
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
