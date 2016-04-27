package Protocol::ACME::Logger;

use strict;
use warnings;

use Log::Any::Adapter;
use base qw/Log::Any::Adapter::Base/;
use Time::HiRes qw( gettimeofday );

our $VERSION = '0.12';

my %LOG_LEVELS = (
                  emergency => 0,
                  alert     => 1,
                  critical  => 2,
                  fatal     => 2,
                  crit      => 2,
                  err       => 2,
                  error     => 3,
                  warn      => 4,
                  warning   => 4,
                  notice    => 5,
                  inform    => 6,
                  info      => 6,
                  debug     => 7,
                  trace     => 8,
                 );

sub init {
    my ($self) = @_;
    if ( exists $self->{log_level} ) {
        $self->{log_level} = $LOG_LEVELS{lc($self->{log_level})}
          unless $self->{log_level} =~ /^\d+$/;
    }
    else {
        $self->{log_level} = $LOG_LEVELS{trace};
    }
}

foreach my $method (keys %LOG_LEVELS) {
    no strict 'refs';
    my $method_level = $LOG_LEVELS{$method};
    *{$method} = sub {
        my ( $self, $text ) = @_;
        return if $method_level > $self->{log_level};
        my ( $sec, $usec ) = gettimeofday();
        printf STDOUT "# %d.%06d %s\n", $sec, $usec, $text;
    };
    my $detection_method = 'is_' . $method;
    *{$detection_method} = sub {
        return !!( $method_level <= $_[0]->{log_level} );
    };
}

1;
