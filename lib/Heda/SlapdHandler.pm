package Heda::SlapdHandler;

# use 5.014;
use strict;
use warnings;
use English;
use utf8;

use File::Basename qw//;
use lib File::Basename::dirname(__FILE__) . "/../../extlib/lib/perl5";

use File::Stamped;
use Log::Minimal;

use Net::LDAP::Filter;

use JSON::XS;

use Heda::Users;

sub new {
    my $klass = shift;
    return bless +{
        suffix => undef,
        database => +{ dsn => undef, username => undef, password => '' },
        log => +{ path => '/var/log/heda.%Y%m' },
        # loglevel => 'WARN';
        loglevel => 'INFO',
    }, $klass;
}

sub users { (shift)->{users}; }

sub entry {
    my ($self, $user) = @_;
    my $suffix = $self->{suffix};
    my ($username,$fullname,$subid,$mailaddress) = map { $user->{$_} } qw(username fullname subid mailaddress);
    my $dn = 'cn=' . $username . ',' . $suffix;
    my $entry = <<"EOT";
objectClass: top
dn: $dn
distinguishedName: $dn
cn: $username
name: $username
givenName: $username
sAMAccountName: $username
displayName: $fullname
uid: $subid
description: $subid
mail: $mailaddress
EOT
    return $entry;
}

sub parse {
    my ($self, $baseStr, $filterStr) = @_;

    my $conv = sub {
        my ($attr,$val) = @_;
        return ['username', $val] if $attr =~ m!^(cn|name|givenName|sAMAccountName)$!i;
        return ['subid', $val] if $attr =~ m!^(uid)$!i;
        return ['mail', $val] if $attr =~ m!^(mail)$!i;
        return undef;
    };

    if ($baseStr ne $self->{suffix}) {
        my $baseSuffix = $self->{suffix};
        my $base = $baseStr =~ s/$baseSuffix$//r;
        foreach my $part (grep { length($_) > 0 } split(/,/, $base)) {
            my ($attr,$val) = split(/=/, $part, 2);
            my $pair = $conv->($attr, $val);
            return $pair if $pair;
        }
    }

    my $filter = Net::LDAP::Filter->new($filterStr);
    my $drill = sub {
        my ($d,$node) = @_;
        if ($node->{equalityMatch}) {
            my $eq = $node->{equalityMatch};
            my $pair = $conv->($eq->{attributeDesc}, $eq->{assertionValue});
            return $pair if $pair;
        }
        my $children = $node->{and} || $node->{or} || [];
        foreach my $node (@$children) {
            my $r = $d->($d,$node);
            return $r if $r;
        }
        return ();
    };
    my $result = $drill->($drill,$filter);
    return $result if $result;

    warnf "Parsed base/filter doesn't contain any valid queries: %s", +{base => $baseStr, filter => $filterStr};
    return undef;
}

sub config {
    my ($self, $param, $value) = @_;

    if ($param eq 'hedaSuffix') { $self->{suffix} = $value; }
    elsif ($param eq 'hedaDsn') { $self->{database}->{dsn} = $value; }
    elsif ($param eq 'hedaDatabaseUsername') { $self->{database}->{username} = $value; }
    elsif ($param eq 'hedaDatabasePassword') { $self->{database}->{password} = $value; }
    elsif ($param eq 'hedaLogPath') {           $self->{log}->{path} = $value; }
    elsif ($param eq 'hedaLogLevel') { $self->{loglevel} = uc($value); }
    else {
        die "unknown config parameter name $param, value $value";
    }

    return 0;
}

sub init {
    my $self = shift;

    die "'hedaLogPath' not configured" unless defined $self->{log}->{path};

    my $fh = File::Stamped->new(pattern => $self->{log}->{path});
    $self->{logfh} = $fh;

    $Log::Minimal::LOG_LEVEL = $self->{loglevel};
    $ENV{LM_DEBUG} = 1 if $self->{loglevel} eq 'DEBUG';

    $Log::Minimal::AUTODUMP = 1;
    $Log::Minimal::PRINT = sub {
        my ( $time, $type, $message, $trace, $raw_message) = @_;
        if ( $type eq 'INFO' ) {
            print {$fh} "$time [$type] ($PID) $message";
        }
        else {
            print {$fh} "$time [$type] ($PID) $message at $trace\n";
        }
    };
    $Log::Minimal::DIE = sub {
        my ( $time, $type, $message, $trace, $raw_message) = @_;
        print {$fh} "$time [$type] ($PID) $message at $trace\n";
        die "$time [$type] ($PID) $message at $trace\n";
    };

    infof "Initializing Heda::SlapdHandler...";

    croakf "'hedaSuffix' not configured" unless defined $self->{suffix};

    croakf "'hedaDsn' not configured" unless defined $self->{database}->{dsn};
    croakf "'hedaDatabaseUsername' not configured" unless defined $self->{database}->{username};
    infof "Database configured '%s', username '%s'", $self->{database}->{dsn}, $self->{database}->{username};

    debugf "Database configured password '%s'", $self->{database}->{password};

    $self->{users} = Heda::Users->new($self->{database});

    return 0;
}

sub search {
    my $self = shift;
    my ($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs ) = @_;

    my $search_pair = $self->parse($base, $filterStr);
    return (0) unless $search_pair; # invalid base+filter

    my $user = $self->users->search(@$search_pair);
    return (0) unless $user;

    return (0, $self->entry($user));
}

sub bind {
    my ($self, $dn, $cred) = @_;
    debugf "Called method 'bind': %s", {dn => $dn, cred => $cred};
    my $bind_pair = $self->parse($dn, '(thi=is dummy)');
    if ($bind_pair->[0] ne 'username') {
        return (1); # invalid dn for bind
    }
    return (0) if $self->users->authenticate(username => $bind_pair->[1], password => $cred);
    return (1); # failed
}

sub compare {
    my $self = shift;
    # 5: LDAP_COMPARE_FALSE
    # 6: LDAP_COMPARE_TRUE
    warnf "Unsupported method 'compare' called: %s", {args => [@_]};
    return 5; # LDAP_COMPARE_FALSE
}

sub modify {
    my ($self, $dn, @list) = @_;
    warnf "Unsupported method 'modify' called: %s", {dn => $dn, list => [@list]};
    return 0;
}

sub add {
    my ($self, $entryStr) = @_;
    warnf "Unsupported method 'add' called";
    return 0;
}

sub modrdn {
    my ($self, $dn, $newdn, $delFlag) = @_;
    warnf "Unsupported method 'modrdn' called: %s", {dn => $dn, newdn => $newdn, delFlag => $delFlag};
    return 0;
}

sub delete {
    my ($self, $dn) = @_;
    warnf "Unsupported method 'delete' called: %s", {dn => $dn};
    return 0;
}

1;
