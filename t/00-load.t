#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 8;

BEGIN {
    use_ok( 'Protocol::ACME' )                       || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Challenge' )            || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Challenge::SimpleSSH' ) || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Challenge::LocalFile' ) || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Challenge::Manual' )    || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Key' )                  || print "Bail out!\n";
    use_ok( 'Protocol::ACME::OpenSSL' )              || print "Bail out!\n";
    use_ok( 'Protocol::ACME::Utils' )                || print "Bail out!\n";
}

#diag( "Testing Protocol::ACME $Protocol::ACME::VERSION, Perl $], $^X" );
