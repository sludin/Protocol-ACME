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
    BUILD_REQUIRES => {
        'Test::More' => 0,
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
          'Log::Any::Adapter::Base' => '1.032',
          'Log::Any' => '1.032',
          'Log::Any::Adapter' => '1.032',
          'Log::Any::Adapter::Util' => '1.032',
          'Crypt::Format' => 0.04,
          'Crypt::OpenSSL::RSA' => '0.28',
          'Crypt::RSA::Parse' => '0.02',
          'LWP::UserAgent' => '6.13',
          'Crypt::OpenSSL::Bignum' => '0.06',
          'JSON' => '2.90',
          'Digest::SHA' => '5.9.5'
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Protocol-ACME-*' },
);

sub MY::c_o {
  return <<'MAKE_FRAG';
readme:
	podselect lib/Protocol/ACME.pm > README.pod
MAKE_FRAG
}

#sub MY::c_o { "new literal text" }
