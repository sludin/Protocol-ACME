package Protocol::ACME::Utils;

use strict;
use warnings;

sub looks_like_pem
{
  my ($str) = @_;
  return (substr($str, 0, 4) eq '----') ? 1 : 0;
}

1;
