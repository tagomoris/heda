use 5.014;
use utf8;

use Test::More;

use_ok "Heda::SlapdHandler";

my $h = Heda::SlapdHandler->new();
$h->{suffix} = "dc=tagomor,dc=is";

subtest 'entry' => sub {
    my $user = +{
        username => 'tagomoris',
        subid => 'XXXX11',
        fullname => 'TAGOMORI Satoshi',
        mailaddress => 'tagomoris@tagomor.is'
    };
    my $entry = $h->entry($user);
    my %r = map { split(/: /, $_, 2) } split(/\n/, $entry);

    is ($r{objectClass}, 'top');
    is ($r{dn}, 'cn=tagomoris,dc=tagomor,dc=is');
    is ($r{distinguishedName}, 'cn=tagomoris,dc=tagomor,dc=is');
    is ($r{cn}, 'tagomoris');
    is ($r{name}, 'tagomoris');
    is ($r{givenName}, 'tagomoris');
    is ($r{sAMAccountName}, 'tagomoris');
    is ($r{displayName}, 'TAGOMORI Satoshi');
    is ($r{uid}, 'XXXX11');
    is ($r{description}, 'XXXX11');
    is ($r{mail}, 'tagomoris@tagomor.is');
};

subtest 'parse' => sub {
    my $r1 = $h->parse('cn=tagomoris,dc=tagomor,dc=is', '(objectClass=*)');
    is( $r1->[0], 'username' );
    is( $r1->[1], 'tagomoris' );

    my $r2 = $h->parse('dc=tagomor,dc=is', '(cn=tagomoris)');
    is( $r2->[0], 'username' );
    is( $r2->[1], 'tagomoris' );

    my $r3 = $h->parse('dc=tagomor,dc=is', '(&(objectClass=*)(cn=tagomoris))');
    is( $r3->[0], 'username' );
    is( $r3->[1], 'tagomoris' );

};

done_testing;
