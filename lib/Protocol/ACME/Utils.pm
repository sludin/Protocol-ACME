package Protocol::ACME::Utils;

use strict;
use warnings;

use MIME::Base64;

sub pem2der
{
  my $pem = shift;
  $pem =~ s/^\-\-\-[^\n]*\n//mg;
  return decode_base64( $pem );
}

sub der2pem
{
  my $der = shift;
  my $tag = shift;

  my $pem = encode_base64( $der );
  $pem = "-----BEGIN $tag-----\n" . $pem . "-----END $tag-----\n";

  return $pem;
}

sub looks_like_pem
{
  my ($str) = @_;
  return (substr($str, 0, 4) eq '----') ? 1 : 0;
}

1;
