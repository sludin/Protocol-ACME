use Test::More;
BEGIN {
  plan skip_all => 'these tests are for release candidate testing'
  unless $ENV{RELEASE_TESTING};
}

use Test::Kwalitee 'kwalitee_ok';
kwalitee_ok();
done_testing;
