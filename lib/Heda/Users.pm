package Heda::Users;

use 5.014;
use utf8;
use Carp;
use Log::Minimal;

use DBIx::Sunny;
use Scope::Container::DBI;

use Digest::SHA qw//;

sub new {
    my $klass = shift;
    my $conf = shift;
    # dsn, db_username, db_password
    critf "'dsn' missing in database configuration" unless $conf->{dsn};
    critf "'username' missing in database configuration" unless $conf->{username};
    warnf "'password' missing in database configuration" unless $conf->{password};

    infof("Heda::Data initialized: %s", +{dsn => $conf->{dsn}, username => $conf->{username}});
    return bless +{dsn => $conf->{dsn}, username => $conf->{username}, password => $conf->{password}}, $klass;
}

sub dbh {
    my $self = shift;
    local $Scope::Container::DBI::DBI_CLASS = 'DBIx::Sunny';
    Scope::Container::DBI->connect( $self->{dsn}, $self->{username}, $self->{password} );
}

# our @FULL_COLUMNS = qw(id subid username passhash fullname mailaddress salt valid superuser created_at modified_at);
our $COLUMNS_VIEW = 'id,subid,username,fullname,mailaddress,valid,superuser';
our $COLUMNS_AUTH = 'id,subid,username,fullname,mailaddress,valid,superuser,salt,passhash';

sub all {
    my ($self) = @_;
    my $sql = <<"EOQ";
SELECT $COLUMNS_VIEW FROM users
EOQ
    $self->dbh->select_all($sql);
}

sub search {
    my ($self, %args) = @_;
    my $col;
    my $value;
    # id/username/subid are with 'UNIQUE' restriction
    if (defined($args{id})) { $col = 'id';       $value = $args{id}; }
    elsif ($args{username}) { $col = 'username'; $value = $args{username}; }
    elsif ($args{subid}) {    $col = 'subid';    $value = $args{subid}; }
    else {
        croak 'Heda::Users search key missing id/subid/username';
    }
    my $sql = <<"EOQ";
SELECT $COLUMNS_VIEW FROM users WHERE $col=?
EOQ
    if ($args{auth}) {
        $sql = <<"EOQ";
SELECT $COLUMNS_AUTH FROM users WHERE $col=?
EOQ
    }
    $self->dbh->select_row($sql, $value);
}

sub authenticate_by_username {
    my ($self, $username, $password) = @_;
    my $user = $self->search(username => $username, auth => 1);
    unless ($user) {
        # do dummy authentication to defend from process time inspection
        my $dummypasshash = Digest::SHA::sha256_hex('dummysalt' . $password);
        return undef;
    }
    my $passhash = Digest::SHA::sha256_hex($user->{salt} . $password);
    return $user->{passhash} eq $passhash;
}

sub authenticate_by_subid {
    my ($self, $subid, $password) = @_;
    my $user = $self->search(subid => $subid, auth => 1);
    unless ($user) {
        # do dummy authentication to defend from process time inspection
        my $dummypasshash = Digest::SHA::sha256_hex('dummysalt' . $password);
        return undef;
    }
    my $passhash = Digest::SHA::sha256_hex($user->{salt} . $password);
    return $user->{passhash} eq $passhash;
}

sub get {
    my ($self, $id) = @_;
    $self->search(id => $id);
}

sub create {
    my ($self, $username, $password, $fullname, $mailaddress, $subid) = @_;
    my $salt = Digest::SHA::sha1_hex(scalar(localtime) . rand());
    my $passhash = Digest::SHA::sha256_hex($salt . $password);
    my $sql = <<EOQ;
INSERT INTO users (subid,username,passhash,fullname,mailaddress,salt) VALUES (?,?,?,?,?,?)
EOQ
    my $dbh = $self->dbh;
    $dbh->query($sql, $subid, $username, $passhash, $fullname, $mailaddress, $salt);
    $self->dbh->last_insert_id;
}

sub update { # update password by itself
    my ($self, $id, $username, $salt, $old_password, $new_password) = @_;
    my $old_passhash = Digest::SHA::sha256_hex($salt . $old_password);
    my $new_salt = Digest::SHA::sha1_hex(scalar(localtime) . rand());
    my $new_passhash = Digest::SHA::sha256_hex($new_salt . $new_password);
    my $sql = <<EOQ;
UPDATE users SET passhash=?,salt=?,valid=1,modified_at=NOW() WHERE id=? AND username=? AND passhash=?
EOQ
    $self->dbh->query($sql, $new_passhash, $new_salt, $id, $username, $old_passhash);
}

sub overwrite { # update informations by superuser, without password
    my ($self, $id, $username, $fullname, $mailaddress, $subid, $superuser) = @_;
    my $sql = <<EOQ;
UPDATE users SET username=?,fullname=?,mailaddress=?,subid=?,superuser=? WHERE id=?
EOQ
    $self->dbh->query($sql, $username, $fullname, $mailaddress, $subid, ($superuser ? 1 : 0), $id);
}

sub delete {
    my ($self, $id) = @_;
    my $sql = <<EOQ;
DELETE FROM users WHERE id=?
EOQ
    $self->dbh->query($sql, $id);
}

1;
