use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Heda',
    VERSION_FROM  => 'lib/Heda.pm',
    PREREQ_PM     => {
        'Plack::Builder::Conditionals' => 0,
        'Plack::Middleware::Scope::Container' => 0,
        'HTTP::Session::Store::DBI' => 0,
        'HTTP::Session::State::Cookie' => 0,
        'Starman' => 0,
        'Kossy' => 0,
        'URI' => 0,
        'Log::Minimal' => 0,
        'File::Stamped' => 0,
        'Try::Tiny' => 0,
        'JSON::XS' => 0,
        'Time::Piece' => 0,
        'Time::Seconds' => 0,
        'Time::Piece::MySQL' => 0,
        'DBI' => 0,
        'DBD::mysql' => 0,
        'DBIx::Sunny' => 0,
        'Net::LDAP::Filter' => 0,
    },
    MIN_PERL_VERSION => '5.014001'
);
