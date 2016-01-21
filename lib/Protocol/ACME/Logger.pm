package Protocol::ACME::Logger;

use strict;
use warnings;

use Log::Any;

sub new {
    my ($class, $loglevel) = @_;

    my $log = Log::Any->get_logger();

    return bless { _log => $log, _level => $loglevel }, $class;
}

sub debug {
    my $self = shift;

    Log::Any::Adapter->set(
        { lexically => \my $set },
        'AcmeLocal',
        log_level => $self->{_level},
    );

    return $self->{_log}->debug(@_);
}

package Log::Any::Adapter::AcmeLocal;

use strict;
use warnings;

use Log::Any::Adapter;
use Log::Any::Adapter::Util ();

use Time::HiRes qw( gettimeofday );

use base qw/Log::Any::Adapter::Base/;

my $trace_level;

sub init {
    my ($self) = @_;
    if ( exists $self->{log_level} ) {
        $self->{log_level} =
          Log::Any::Adapter::Util::numeric_level( $self->{log_level} )
          unless $self->{log_level} =~ /^\d+$/;
    }
    else {
        $trace_level ||= Log::Any::Adapter::Util::numeric_level('trace');
        $self->{log_level} = $trace_level;
    }
}

BEGIN {
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
}

1;
