package Heda::Users;

use 5.014;
use utf8;
use Log::Minimal;

use DBI;
use DBIx::Sunny;

use Digest::SHA qw//;

sub new {
    my $klass = shift;
    my $conf = shift;
    # dsn, db_username, db_password
    critf "'dsn' missing in database configuration" unless $conf->{dsn};
    critf "'username' missing in database configuration" unless $conf->{username};
    infof "'password' missing in database configuration" unless $conf->{password};

    infof("Heda::Data initialized: %s", +{dsn => $conf->{dsn}, username => $conf->{username}});
    return bless +{dsn => $conf->{dsn}, username => $conf->{username}, password => $conf->{password}}, $klass;
}

sub dbh {
    my $self = shift;
    # local $Scope::Container::DBI::DBI_CLASS = 'DBIx::Sunny';
    # Scope::Container::DBI->connect( $self->{dsn}, $self->{username}, $self->{password} );
    DBI->connect_cached( $self->{dsn}, $self->{username}, $self->{password}, {
        RootClass => 'DBIx::Sunny',
        PrintError => 0,
        RaiseError => 1,
    } );
}

sub salt {
    Digest::SHA::sha1_hex(scalar(localtime) . rand());
}

# our @FULL_COLUMNS = qw(id subid username passhash fullname mailaddress salt valid superuser accounts memo created_at modified_at);
our $COLUMNS_VIEW = 'id,subid,username,fullname,mailaddress,valid,superuser,accounts,memo,salt,modified_at';
our $COLUMNS_VIEW_FULL = 'id,subid,username,fullname,mailaddress,valid,superuser,accounts,memo,created_at,modified_at';
our $COLUMNS_AUTH = 'id,subid,username,fullname,mailaddress,valid,superuser,accounts,memo,salt,passhash,modified_at';

our @COLUMNS_VIEW_FULL = split(/,/, $COLUMNS_VIEW_FULL);

sub all {
    my ($self,%opts) = @_;
    my $columns = $COLUMNS_VIEW;
    $columns = $COLUMNS_VIEW_FULL if $opts{full};
    my $sql = <<"EOQ";
SELECT $columns FROM users
EOQ
    $self->dbh->select_all($sql);
}

sub search {
    my ($self, %args) = @_;
    my $col;
    my $value;
    # id/username/subid are with 'UNIQUE' restriction
    if (defined($args{id})) { $col = 'id';          $value = $args{id}; }
    elsif ($args{username}) { $col = 'username';    $value = $args{username}; }
    elsif ($args{subid}) {    $col = 'subid';       $value = $args{subid}; }
    elsif ($args{mail}) {     $col = 'mailaddress'; $value = $args{mail}; }
    else {
        croakf 'Heda::Users search key missing id/subid/username';
    }
    my $columns = $COLUMNS_VIEW;
    $columns = $COLUMNS_AUTH if $args{auth};

    my $sql = <<"EOQ";
SELECT $columns FROM users WHERE $col=?
EOQ
    $self->dbh->select_row($sql, $value);
}

sub memo_search { # heavy call: DON'T USE FROM slapd handler
    my ($self, $word) = @_;
    my $columns = $COLUMNS_VIEW;
    my $sql = <<"EOQ";
SELECT $columns FROM users WHERE memo LIKE ?
EOQ
    $self->dbh->select_all($sql, '%' . $word . '%');
}

sub authenticate { # authenticate( fieldname => $value, password => $password_value, bypass_validation => $bool )
    my ($self, %args) = @_;
    my %param;
    if (defined $args{username}) { %param = ( username => $args{username}, auth => 1); }
    elsif (defined $args{subid}) { %param = ( subid => $args{subid}, auth => 1); }
    elsif (defined $args{mail}) {  %param = ( mail => $args{mail}, auth => 1); }
    else {
       croakf "valid field name to authenticate not specified: %s", \%args;
    }
    my $user = $self->search(%param);
    unless ($user) {
        # do dummy authentication to defend from process time inspection
        my $dummypasshash = Digest::SHA::sha256_hex('dummysalt' . $args{password});
        return undef;
    }
    my $passhash = Digest::SHA::sha256_hex($user->{salt} . $args{password});
    if ($user->{passhash} eq $passhash and ($args{bypass_validation} or $user->{valid})) {
        delete $user->{passhash};
        return $user;
    }
    return undef;
}

sub get {
    my ($self, $id) = @_;
    $self->search(id => $id, full => 1);
}

sub create {
    my ($self, $username, $password, $fullname, $mailaddress, $subid) = @_;
    my $salt = $self->salt;
    my $passhash = Digest::SHA::sha256_hex($salt . $password);
    my $sql = <<EOQ;
INSERT INTO users (subid,username,passhash,fullname,mailaddress,salt,modified_at) VALUES (?,?,?,?,?,?,NOW())
EOQ
    my $dbh = $self->dbh;
    $dbh->query($sql, $subid, $username, $passhash, $fullname, $mailaddress, $salt);
    $dbh->last_insert_id;
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
    my ($self, $id, $username, $fullname, $mailaddress, $subid, $superuser, $accounts, $memo) = @_;
    my $sql = <<EOQ;
UPDATE users SET username=?,fullname=?,mailaddress=?,subid=?,superuser=?,accounts=?,memo=? WHERE id=?
EOQ
    $self->dbh->query($sql, $username, $fullname, $mailaddress, $subid, ($superuser ? 1 : 0), $accounts, $memo, $id);
}

sub reset_password {
    my ($self, $id, $password) = @_;
    my $salt = Digest::SHA::sha1_hex(scalar(localtime) . rand());
    my $passhash = Digest::SHA::sha256_hex($salt . $password);
    my $sql = <<EOQ;
UPDATE users SET passhash=?,salt=?,valid=0,modified_at=NOW() WHERE id=?
EOQ
    $self->dbh->query($sql, $passhash, $salt, $id);
}

sub force_envalidate {
    my ($self, $id) = @_;
    my $sql = <<EOQ;
UPDATE users SET valid=1,modified_at=NOW() WHERE id=?
EOQ
    $self->dbh->query($sql, $id);
}

sub delete {
    my ($self, $id) = @_;
    my $sql = <<EOQ;
DELETE FROM users WHERE id=?
EOQ
    $self->dbh->query($sql, $id);
}

1;
