#!perl 
use 5.006;
use strict;
use warnings;
use Test::More;

use lib 't/lib';

use Protocol::ACME::Test;

Protocol::ACME::Test::_write_key_files();

