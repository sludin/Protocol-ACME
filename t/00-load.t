#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Protocol::ACME' ) || print "Bail out!\n";
}

diag( "Testing Protocol::ACME $Protocol::ACME::VERSION, Perl $], $^X" );
