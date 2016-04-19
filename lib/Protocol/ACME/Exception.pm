package Protocol::ACME::Exception;

use strict;
use warnings;

our $VERSION = '0.12';

# very simple stringification ... make this
# more elaborate according to taste
use overload ('""' => \&stringify);
sub stringify
{
    my $self = shift;

    require Data::Dumper;
    return ref($self).' error: '.Data::Dumper::Dumper($self);
}

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
    $self->{detail} = "double error: bad arg ($error) passed to exception constructor";
  }
  else
  {
    $self->{detail} = $error;
  }

  return bless $self, $class;
}

1;
