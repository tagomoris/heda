package Heda::Web;

use 5.014;
use utf8;
use Log::Minimal;

use Try::Tiny;
use List::Util;
use Time::Piece;
use Encode;

use Heda::Util;
use Heda::Config;
use Heda::Users;

use Kossy;

use DBI;
use HTTP::Session;
use HTTP::Session::Store::DBI;
use HTTP::Session::State::Cookie;

use JSON::XS;
use Text::CSV::Encoded;

sub config {
    my $self = shift;
    $self->{config} //= Heda::Config->new($self->root_dir);
    return $self->{config};
}

sub links {
    my $self = shift;
    {
        package Heda::Web::Links;
        sub new {
            my ($this, %mapping) = @_;
            my $self = +{%mapping};
            return bless $self, $this;
        }
        sub username { my ($self,$v) = @_; return ($self->{username} || '') =~ s/\%s/$v/gr; };
        sub fullname { my ($self,$v) = @_; return ($self->{fullname} || '') =~ s/\%s/$v/gr; };
        sub mailaddress { my ($self,$v) = @_; return ($self->{mailaddress} || '') =~ s/\%s/$v/gr; };
        sub subid { my ($self,$v) = @_; return ($self->{subid} || '') =~ s/\%s/$v/gr; };
    }
    $self->{links} //= Heda::Web::Links->new(%{$self->config->{links}});
    return $self->{links};
}

sub password_validate {
    my ($self, $password) = @_;
    my $result = 1;
    foreach my $pattern (@{$self->config->{password_patterns}}) {
        $result = ($result and $password =~ m!$pattern!);
    }
    $result;
}

sub parse_accounts {
    my ($self, $accounts) = @_;
    return {} if length($accounts) < 1;
    my @lines = split(/ *\r?\n/, $accounts);
    chomp @lines;
    my $r = +{};
    foreach my $line (@lines) {
        my ($key, $val) = split(/: */, $line, 2);
        return undef unless $key =~ m!^[-_.a-zA-Z0-9]+$!;
        return undef unless defined $val;
        $val =~ s/^ +//;
        $val =~ s/ +$//;
        $r->{$key} = $val if length($key) > 0 and length($val) > 0;
    }
    return $r;
}

sub users {
    my $self = shift;
    $self->{users} //= Heda::Users->new($self->config->{database});
    return $self->{users};
}

sub session {
    my ($self, $req) = @_;
    my $sessiondb = $self->config->{sessiondb};

    HTTP::Session->new(
        store => HTTP::Session::Store::DBI->new({
            dbh => DBI->connect_cached( $sessiondb->{dsn}, $sessiondb->{username}, $sessiondb->{password} ),
            # expires => ($sessiondb->{expires} || 1800),
            expires => ($sessiondb->{expires} || 1800),
        }),
        state => HTTP::Session::State::Cookie->new(cookie_key => 'hedaweb'),
        request => $req,
    );
}

filter 'check_supervisor_login' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = $self->session($c->req);

        if ($session->get('authenticated') and $session->get('supervisor')) {
            $c->stash->{supervisor} = $session->get('supervisor');
            $c->stash->{username} = $session->get('username');
        }
        $c->stash->{session} = $session;
        $session->response_filter($c->res);

        $app->($self, $c);
    }
};

filter 'require_supervisor_login' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = $self->session($c->req);

        unless ($session->get('authenticated') and $session->get('supervisor')) {
            $session->set('show_path', $c->req->uri->path_query);
            return $c->redirect('/login');
        }
        $c->stash->{supervisor} = $session->get('supervisor');
        $c->stash->{username} = $session->get('username');
        $c->stash->{session} = $session;
        $session->response_filter($c->res);

        $app->($self, $c);
    }
};

get '/' => [qw/check_supervisor_login/] => sub {
    my ( $self, $c )  = @_;

    my $autherrors = $c->stash->{session}->remove('autherrors');
    my $inputvalues = $c->stash->{session}->remove('inputvalues');
    my $errors = $c->stash->{session}->remove('errors');

    $autherrors ||= +{ password => { flag => 0, message => '' } };
    $inputvalues ||= +{};
    $errors ||= +{
        password => { flag => 0, message => '' },
        mismatch => { flag => 0, message => '' },
    };

    my $username = $c->req->param('u');

    $c->render('index.tx', {
        username => $username,
        autherrors => $autherrors, inputvalues => $inputvalues, errors => $errors
    });
};

post '/update' => [qw/check_supervisor_login/] => sub { # update accounts password by itself
    my ( $self, $c ) = @_;
    my ($username,$password,$new1,$new2) = map { $c->req->param($_); } qw/username current_password new_password1 new_password2/;
    my $user = $self->users->authenticate( username => $username, password => $password, bypass_validation => 1 );
    my $errors = {};
    unless ($user) {
        $errors->{password} = +{ flag => 1, message => 'Incorrect password' };
    }
    if ($username eq $new1) {
        $errors->{mismatch} = +{ flag => 1, message => 'Invalid password, cannot use username string as password' };
    }
    elsif (not $self->password_validate($new1)) {
        $errors->{mismatch} = +{ flag => 1, message => 'Password too weak, for pattern: ' . $self->config->{password_patterns}->[0] };
    }
    elsif ($new1 ne $new2) {
        $errors->{mismatch} = +{ flag => 1, message => 'Password mismatch between 1st and 2nd' };
    }

    if ($errors->{password} or $errors->{mismatch}) {
        $c->stash->{session}->set('inputvalues', { username => $username });
        $c->stash->{session}->set('errors', $errors);
        return $c->redirect('/');
    }

    $self->users->update($user->{id}, $username, $user->{salt}, $password, $new1);
    $c->stash->{session}->set('inputvalues', { username => $username });
    $c->stash->{session}->set('notice', { update_success => 'Password successfully updated' });

    $user = $self->users->get($user->{id});
    my $accounts = decode_json($user->{accounts});
    $user->{account_list} = [
        (map { +{ key => $_, val => $accounts->{$_} } } keys(%$accounts))
    ];

    $c->render('userinfo.tx', { subject => 'Password successfully updated', user => $user });
};

post '/authenticate' => [qw/check_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my ($username,$password) = map { $c->req->param($_); } qw/username password/;
    my $user = $self->users->authenticate( username => $username, password => $password );
    my $errors = {};
    unless ($user) {
        $errors->{password} = +{ flag => 1, message => 'Incorrect password' };
        $c->stash->{session}->set('autherrors', $errors);
        return $c->redirect('/');
    }
    my $accounts = decode_json($user->{accounts});
    $user->{account_list} = [
        (map { +{ key => $_, val => $accounts->{$_} } } keys(%$accounts))
    ];

    $c->render('userinfo.tx', { subject => 'Test success', user => $user });
};

get '/login' => [qw/check_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    if ($c->stash->{supervisor}) { # already logged in as supervisor
        return $c->redirect('/list');
    }

    my $errors = $c->stash->{session}->get('autherrors');
    $errors ||= +{
        username => +{ flag => 0 },
        password => +{ flag => 0 },
    };
    $c->render('login.tx', { autherrors => $errors });
};

post '/login' => [qw/check_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my $username = $c->req->param('username');
    my $password = $c->req->param('password');

    my $user = $self->users->authenticate( username => $username, password => $password );
    my $errors = {};
    unless ($user and $user->{superuser}) {
        $errors->{password} = +{ flag => 1, message => 'Incorrect password' } unless $user;
        $errors->{username} = +{ flag => 1, message => 'You are NOT supervisor' } unless $user and $user->{supervisor};
        $c->stash->{session}->set('autherrors', $errors);
        return $c->redirect('/login');
    }

    $c->stash->{session}->set('authenticated', 1);
    $c->stash->{session}->set('supervisor', 1);

    my $path = $c->stash->{session}->remove('show_path');
    $path ||= '/list';
    $c->redirect($path);
};

get '/logout' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    $c->stash->{session}->remove('authenticated');
    $c->stash->{session}->remove('supervisor');
    $c->redirect('/');
};

get '/list' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my $sort = $c->req->param('s') || 'u';
    my $order = $c->req->param('o') || 'a';
    my $search_memo = $c->req->param('sm') || undef;
    my $show_memo = $c->req->param('m') || defined($search_memo);

    my $list;
    if ($search_memo) {
        $list = $self->users->memo_search($search_memo);
    } else { # all
        $list = $self->users->all();
    }

    if ($sort eq 'u') { #username
        $list = [sort { $a->{username} cmp $b->{username} } @$list];
    } elsif ($sort eq 's') { #subid
        $list = [sort { $a->{subid} cmp $b->{subid} } @$list];
    } elsif ($sort eq 'e') { #email address
        $list = [sort { $a->{mailaddress} cmp $b->{mailaddress} } @$list];
    } elsif ($sort eq 'm') { #modified-at
        $list = [sort { $a->{modified_at} cmp $b->{modified_at} } @$list];
    }

    if ($order eq 'd') { #desc
        $list = [reverse @$list];
    } else { # 'a' or blank: asc
        # nothing to do
    }

    foreach my $user (@$list) {
        my $account = decode_json($user->{accounts});
        $user->{account_list} = [map { [$_, $account->{$_}] } sort(keys %$account)];
    }

    my $notification = $c->stash->{session}->remove('notification');

    $c->render('list.tx', +{
        list => $list,
        search => $search_memo,
        search_memo => $search_memo,
        memo => $show_memo,
        notification => $notification,
        sort => $sort,
        order => $order,
        links => $self->links(),
    });
};

get '/list/csv' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my $list = $self->users->all(full => 1);

    my $csv = Text::CSV::Encoded->new ({
        encoding_in => "utf8", encoding_out => "shiftjis",
        always_quote => 1
    })
        or die "Cannot use Text::CSV, " . Text::CSV->error_diag();

    my @csv_cols = @Heda::Users::COLUMNS_VIEW_FULL;
    shift @csv_cols; # delete 'id' column

    $csv->combine(@csv_cols);
    my $head = $csv->string();

    my $to_arrayref = sub {
        my %user = @_;
        [map { Encode::decode_utf8($user{$_}) } @csv_cols ];
    };
    my $data = join("\r\n", $head, map { $csv->combine(@$_); $csv->string(); } map { $to_arrayref->(%$_) } @$list);
    my $today = Time::Piece->new()->strftime('%Y%m%d');
    [200, { 'Content-Disposition' => "attachment; filename=\"heda_users.$today.sjis.csv\"", 'Content-Type' => 'text/csv' }, $data];
};

get '/create' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $inputvalues = $c->stash->{session}->remove('inputvalues');
    my $errors = $c->stash->{session}->remove('createerrors');

    $inputvalues ||= +{};
    $errors ||= +{
        username => { flag => 0, message => '' },
        fullname => { flag => 0, message => '' },
        mailaddress => { flag => 0, message => '' },
        subid => { flag => 0, message => '' },
        accounts => { flag => 0, message => '' },
    };

    $inputvalues->{accounts} ||= join(": \n", @{$self->config->{accounts}}) . ": ";

    $c->render('create.tx', { inputvalues => $inputvalues, errors => $errors });
};

post '/create' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my $result = $c->req->validator([
        'username' => {'rule' => [
            [sub{$_[1] =~ m!^[-_.a-zA-Z0-9]{1,32}$!}, 'Username format invalid'],
        ]},
        'fullname' => {'rule' => [
            ['NOT_NULL', 'Fullname is missing'],
            [sub{ length($_[1]) <= 32 }, 'Fullname is too long, max length: 32'],
        ]},
        'mailaddress' => {'rule' => [
            # simple (strictly, partly wrong) mailaddress regexp...
            [sub{$_[1] =~ m!^[-_.a-zA-Z0-9]+\@[-a-z0-9]+\.[-.a-z0-9]+$!}, 'Mailaddress format invalid'],
            [sub{ length($_[1]) <= 256 }, 'Mailaddress is too long, max length: 256'],
        ]},
        'subid' => {'rule' => [
            ['NOT_NULL', 'Subid is missing'],
            [sub{$_[1] =~ m!^.{1,32}$!}, 'Subid is too long, max length: 32'],
        ]},
        'accounts' => {'rule' => [
            [sub{ $self->parse_accounts($_[1]) }, 'Accounts lines MUST be "key: value" format'],
        ]},
    ]);
    my $inputvalues = +{
        (map { ( $_ => ($c->req->param($_) || "") ) } qw( username fullname mailaddress subid accounts superuser ))
    };
    if ($result->has_error) {
        my $errors = +{};
        my $raw_errors = $result->errors;
        foreach my $field (keys(%$raw_errors)) {
            $errors->{$field} = +{ flag => 1, message => $raw_errors->{$field} };
        }
        $c->stash->{session}->set('inputvalues', $inputvalues);
        $c->stash->{session}->set('createerrors', $errors);
        return $c->redirect('/create');
    }

    my $password = Heda::Util::gen_password();

    my $username = $inputvalues->{username};
    my $fullname = $inputvalues->{fullname};
    my $mailaddress = $inputvalues->{mailaddress};
    my $subid = $inputvalues->{subid};
    my $superuser = $inputvalues->{superuser};
    my $accounts = encode_json($self->parse_accounts($inputvalues->{accounts}));

    my $exists_username = $self->users->search( username => $username );
    my $exists_subid = $self->users->search( subid => $subid );
    my $exists_mail = $self->users->search( mail => $mailaddress);

    if ($exists_username or $exists_subid or $exists_mail) {
        my $unique_errors = +{};
        $unique_errors->{username} = +{ flag => 1, message => "Username '$username' already exists" } if $exists_username;
        $unique_errors->{subid} = +{ flag => 1, message => "SubID '$subid' already exists" } if $exists_subid;
        $unique_errors->{mailaddress} = +{ flag => 1, message => "Mail Address '$mailaddress' already exists" } if $exists_mail;

        $c->stash->{session}->set('inputvalues', $inputvalues);
        $c->stash->{session}->set('createerrors', $unique_errors);
        return $c->redirect('/create');
    }

    my $id;
    try {
        my $uid = $self->users->create($username, $password, $fullname, $mailaddress, $subid);
        $self->users->overwrite( $uid, $username, $fullname, $mailaddress, $subid, $superuser, $accounts, ''); # memo is blank
        $id = $uid;
    } catch {
        warnf "Failed to insert user '%s' record: %s", $username, $_;
    };
    unless ($id) {
        $c->stash->{session}->set('inputvalues', $inputvalues);
        $c->stash->{session}->set('createerrors', {username => { flag => 1, message => 'Failed to create data...'}});
        return $c->redirect('/create');
    }
    my $user = $self->users->get($id);
    $user->{password} = $password;
    my $accounts_obj = decode_json($user->{accounts});
    $user->{account_list} = [
        (map { +{ key => $_, val => $accounts_obj->{$_} } } keys(%$accounts_obj))
    ];

    $c->render('created.tx', { user => $user });
};

get '/edit/:username' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $user = $self->users->search( username => $c->args->{username} );
    unless ($user) {
        return $c->halt(404, 'specified username not found.');
    }

    my $inputvalues = $c->stash->{session}->remove('inputvalues');
    my $errors = $c->stash->{session}->remove('createerrors');

    $inputvalues->{fullname} ||= $user->{fullname};
    $inputvalues->{mailaddress} ||= $user->{mailaddress};
    $inputvalues->{subid} ||= $user->{subid};
    $inputvalues->{superuser} ||= $user->{superuser};
    $inputvalues->{memo} ||= $user->{memo};

    unless ($inputvalues->{accounts}) {
        my $accounts_obj = decode_json($user->{accounts});
        if (scalar(keys %$accounts_obj) > 0) {
            $inputvalues->{accounts} = join("\n", (map { join(": ", $_, $accounts_obj->{$_}) } keys(%$accounts_obj)));
        } else {
            $inputvalues->{accounts} ||= join(": \n", @{$self->config->{accounts}}) . ": ";
        }
    }
    $errors ||= +{
        username => { flag => 0, message => '' },
        fullname => { flag => 0, message => '' },
        mailaddress => { flag => 0, message => '' },
        subid => { flag => 0, message => '' },
        accounts => { flag => 0, message => '' },
        memo => { flag => 0, message => '' },
    };

    $c->render('overwrite.tx', { user => $user, inputvalues => $inputvalues, errors => $errors });
};

post '/edit/:username' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $user = $self->users->search( username => $c->args->{username} );
    unless ($user) {
        return $c->halt(404, 'specified username not found.');
    }

    my $result = $c->req->validator([
        'fullname' => {'rule' => [
            ['NOT_NULL', 'Fullname is missing'],
            [sub{ length($_[1]) <= 32 }, 'Fullname is too long, max length: 32'],
        ]},
        'mailaddress' => {'rule' => [
            # simple (strictly, partly wrong) mailaddress regexp...
            [sub{$_[1] =~ m!^[-_.a-zA-Z0-9]+\@[-a-z0-9]+\.[-.a-z0-9]+$!}, 'Mailaddress format invalid'],
            [sub{ length($_[1]) <= 256 }, 'Mailaddress is too long, max length: 256'],
        ]},
        'subid' => {'rule' => [
            ['NOT_NULL', 'Subid is missing'],
            [sub{$_[1] =~ m!^.{1,32}$!}, 'Subid is too long, max length: 32'],
        ]},
        'accounts' => {'rule' => [
            [sub{ $self->parse_accounts($_[1]) }, 'Accounts lines MUST be "key: value" format'],
        ]},
    ]);
    warnf "PARAM: %s", [map { ( "$_" => ($c->req->param("$_") || "") ) } qw( fullname mailaddress subid accounts superuser memo )];

    my $inputvalues = +{
        (map { ( "$_" => ($c->req->param("$_") || "") ) } qw( fullname mailaddress subid accounts superuser memo ))
    };
    if ($result->has_error) {
        my $errors = +{};
        my $raw_errors = $result->errors;
        foreach my $field (keys(%$raw_errors)) {
            $errors->{$field} = +{ flag => 1, message => $raw_errors->{$field} };
        }
        $c->stash->{session}->set('inputvalues', $inputvalues);
        $c->stash->{session}->set('createerrors', $errors);
        return $c->redirect('/overwrite/' . $user->{username});
    }

    warnf "inputvalues: %s", $inputvalues;
    my $fullname = $inputvalues->{fullname};
    my $mailaddress = $inputvalues->{mailaddress};
    my $subid = $inputvalues->{subid};
    my $superuser = $inputvalues->{superuser};
    my $accounts = encode_json($self->parse_accounts($inputvalues->{accounts}));
    my $memo = $inputvalues->{memo};

    my $success = 0;
    try {
        $self->users->overwrite( $user->{id}, $user->{username}, $fullname, $mailaddress, $subid, $superuser, $accounts, $memo);
        $success = 1;
    } catch {
        warnf "Failed to overwrite user '%s' record: %s", $user->{username}, $_;
    };
    unless ($success) {
        $c->stash->{session}->set('inputvalues', $inputvalues);
        $c->stash->{session}->set('createerrors', {username => { flag => 1, message => 'Failed to update data...'}});
        return $c->redirect('/overwrite/' . $user->{username});
    }
    my $notification = +{
        type => 'success',
        subject => 'Success!',
        message => 'to update ' . $user->{username},
    };
    $c->stash->{session}->set('notification', $notification);
    $c->redirect('/list');
};

get '/reset/:username' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $user = $self->users->search( username => $c->args->{username} );
    return $c->halt(404, 'specified username not found.') unless $user;

    my ($pin, $hidden, $hash) = Heda::Util::gen_pincode();
    $c->stash->{session}->set('danger_op_key', $hash);

    $c->render('dialog.tx', { op => 'reset', username => $user->{username}, pin => $pin, hidden => $hidden });
};

post '/reset' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my ($pin, $hidden) = ($c->req->param('pin'), $c->req->param('hidden'));
    my $user = $self->users->search( username => $c->req->param('username') );
    return $c->halt(404, 'specified username not found.') unless $user;

    my $hash = $c->stash->{session}->remove('danger_op_key');
    unless ($hash and Heda::Util::check_pincode($pin, $hidden, $hash)) {
        return $c->halt(400, 'not operated correctly.');
    }
    my $password = Heda::Util::gen_password();
    $self->users->reset_password($user->{id}, $password);

    $user->{password} = $password;
    my $accounts_obj = decode_json($user->{accounts});
    $user->{account_list} = [
        (map { +{ key => $_, val => $accounts_obj->{$_} } } keys(%$accounts_obj))
    ];

    $c->render('created.tx', { reset => 1, user => $user });
};

get '/envalidate/:username' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $user = $self->users->search( username => $c->args->{username} );
    return $c->halt(404, 'specified username not found.') unless $user;

    my ($pin, $hidden, $hash) = Heda::Util::gen_pincode();
    $c->stash->{session}->set('danger_op_key', $hash);

    $c->render('dialog.tx', { op => 'envalidate', username => $user->{username}, pin => $pin, hidden => $hidden });
};

post '/envalidate' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my ($pin, $hidden) = ($c->req->param('pin'), $c->req->param('hidden'));
    my $user = $self->users->search( username => $c->req->param('username') );
    return $c->halt(404, 'specified username not found.') unless $user;

    my $hash = $c->stash->{session}->remove('danger_op_key');
    unless ($hash and Heda::Util::check_pincode($pin, $hidden, $hash)) {
        return $c->halt(400, 'not operated correctly.');
    }
    $self->users->force_envalidate($user->{id});

    my $notification = +{
        subject => 'Success!',
        message => 'to envalidate user ' . $user->{username} . ' forcely',
    };
    $c->stash->{session}->set('notification', $notification);
    $c->redirect('/list');
};

get '/remove/:username' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my $user = $self->users->search( username => $c->args->{username} );
    return $c->halt(404, 'specified username not found.') unless $user;

    my ($pin, $hidden, $hash) = Heda::Util::gen_pincode();
    $c->stash->{session}->set('danger_op_key', $hash);

    $c->render('dialog.tx', { op => 'remove', username => $user->{username}, pin => $pin, hidden => $hidden });
};

post '/remove' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;

    my ($pin, $hidden) = ($c->req->param('pin'), $c->req->param('hidden'));
    my $user = $self->users->search( username => $c->req->param('username') );
    return $c->halt(404, 'specified username not found.') unless $user;

    my $hash = $c->stash->{session}->remove('danger_op_key');
    unless ($hash and Heda::Util::check_pincode($pin, $hidden, $hash)) {
        return $c->halt(400, 'not operated correctly.');
    }
    $self->users->delete($user->{id});

    my $notification = +{
        # type => 'success', # warning
        subject => 'Success!',
        message => 'to remove user ' . $user->{username},
    };
    $c->stash->{session}->set('notification', $notification);
    $c->redirect('/list');
};

1;
