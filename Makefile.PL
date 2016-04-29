use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Protocol::ACME',
    AUTHOR           => q{Stephen Ludin <sludin@ludin.org>},
    VERSION_FROM     => 'lib/Protocol/ACME.pm',
    ABSTRACT_FROM    => 'lib/Protocol/ACME.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.007003,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    TEST_REQUIRES => {
        'Test::More' => 0,
        'Test::Exception' => 0,
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
         resources => {
             repository => {
                 type => 'git',
                 url  => 'https://github.com/sludin/Protocol-ACME.git',
                 web  => 'https://github.com/sludin/Protocol-ACME',
             },
         },
    },
    PREREQ_PM => {
                  # here the prerequisites are aligned with Debian
                  # stable, if they exists, otherwise to stretch (and
                  # they need backporting: libcrypt-rsa-parse-perl and
                  # libcrypt-format-perl
          'Log::Any' => '0.15',
          'Log::Any::Adapter' => '0.11',
          'Crypt::Format' => '0.04',
          'Crypt::OpenSSL::RSA' => '0.28',
          'Crypt::RSA::Parse' => '0.02',
          'Crypt::OpenSSL::Bignum' => '0.04',
          'JSON' => '2.61',
          'Digest::SHA' => '5.88',
          'HTTP::Tiny' => '0.050',
          'Test::Exception' => '0.35',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Protocol-ACME-*' },
    x_contributors => [ 'Felipe Gasper <felipe@felipegasper.com>' ],
);

sub MY::c_o {
  return <<'MAKE_FRAG';
readme:
	podselect lib/Protocol/ACME.pm > README.pod
MAKE_FRAG
}


