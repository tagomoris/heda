#!/usr/bin/env perl

use 5.014;
use utf8;
binmode STDOUT, ":encoding(utf8)";

use FindBin;
use lib "$FindBin::Bin/../extlib/lib/perl5";
use lib "$FindBin::Bin/../lib";

use List::Util qw//;

use Log::Minimal;
use Try::Tiny;

use Heda::Util;
use Heda::Config;
use Heda::Users;

use Text::CSV;
use JSON::XS;

my $csvpath = shift @ARGV;
unless ( $csvpath and -f $csvpath ) {
    print STDERR "Cannot read CSV file:", $csvpath, "\n";
    exit 1;
}

my $config = Heda::Config->new( "$FindBin::Bin/../" );

$config->{loglevel} = 'WARN';
$config->configure_logger();

my $users = Heda::Users->new( $config->{database} );

my @fields = qw( username fullname mailaddress subid );
my @required = qw( username fullname mailaddress subid );

my $csv = Text::CSV->new ( { binary => 1 } )  # should set binary attribute.
    or croakf "Cannot use CSV: %s", Text::CSV->error_diag ();

open my $fh, "<:encoding(utf8)", $csvpath
    or croakf "Cannot open CSV file %s : %s", $csvpath, $!;

my @user_list;
my $head = 1;
my $has_error = 0;

while ( my $row = $csv->getline( $fh ) ) {
    if ($head == 1 and (List::Util::reduce {$a and $b =~ m!^[-_A-Z]+$!} (1, @$row)) ) {
        @fields = map { lc($_) } @$row;
        $head = 0;
        next;
    }
    $head = 0;

    my $user_row = +{};
    for ( my $i = 0 ; $i < scalar(@$row) ; $i++ ) {
        $user_row->{$fields[$i]} = $row->[$i];
    }
    $has_error ||= List::Util::reduce {$a or not defined($user_row->{$b})} (0, @required);
    push @user_list, $user_row;
}
close $fh;

if ( $has_error ) {
    foreach my $u (@user_list) {
        print join(", ", map { $_ . ":" . ($u->{$_} || 'NULL') } @fields), "\n";
    }
    print "\n";
    print "Input file contains error values, exit!\n";
    exit 1;
}

foreach my $user (@user_list) {
    my $password = Heda::Util::gen_password();
    my ($id, $error);
    try {
        $id = $users->create($user->{username}, $password, $user->{fullname}, $user->{mailaddress}, $user->{subid});
    } catch {
        $error = $_;
    };
    unless ($id) {
        croakf "Failed to create record for user: %s, error: %s", $user, $error;
    }

    my @ext_fields = grep { $_ ne 'username' and $_ ne 'fullname' and $_ ne 'mailaddress' and $_ ne 'subid' } keys(%$user);
    my $accounts = encode_json({ map { ($_ => $user->{$_}) } @ext_fields });

    $user->{password} = $password;

    $users->overwrite(
        $id,
        $user->{username}, $user->{fullname}, $user->{mailaddress}, $user->{subid},
        0, # superuser
        $accounts,
        '', # memo
    );
    print "Username: '", $user->{username}, "', Password: '", $password, "', MailAddress: '", $user->{mailaddress}, "'\n";
}
