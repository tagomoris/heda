package Heda::Web;

use 5.014;
use utf8;
use Log::Minimal;

use Heda::Config;
use Heda::Users;

use Kossy;

use DBI;
use HTTP::Session;
use HTTP::Session::Store::DBI;
use HTTP::Session::State::Cookie;

use JSON::XS;

sub config {
    my $self = shift;
    $self->{config} //= Heda::Config->new($self->root_dir);
    return $self->{config};
}

sub password_validate {
    my ($self, $password) = @_;
    my $result = 1;
    foreach my $pattern (@{$self->config->{password_patterns}}) {
        $result = ($result and $password =~ m!$pattern!);
    }
    $result;
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
            return $c->halt(401, 'specified operations requires login, see /.');
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
    my ($autherrors);
    my ($inputvalues, $errors);
    if ($c->req->referer) {
        if ($autherrors = $c->stash->{session}->get('autherrors')) {
            $c->stash->{session}->remove('autherrors');
        }
        if ($inputvalues = $c->stash->{session}->get('inputvalues')) {
            $c->stash->{session}->remove('inputvalues');
        }
        if ($errors = $c->stash->{session}->get('errors')) {
            $c->stash->{session}->remove('errors');
        }
    }
    else {
        $c->stash->{session}->remove('autherrors');
        $c->stash->{session}->remove('inputvalues');
        $c->stash->{session}->remove('errors');
    }
    $autherrors ||= +{ password => { flag => 0, message => '' } };
    $inputvalues ||= +{};
    $errors ||= +{
        password => { flag => 0, message => '' },
        mismatch => { flag => 0, message => '' },
    };
    $c->render('index.tx', { autherrors => $autherrors, inputvalues => $inputvalues, errors => $errors });
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
    $c->redirect('/list');
};

get '/logout' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    $c->stash->{session}->remove('authenticated');
    $c->stash->{session}->remove('supervisor');
    $c->redirect('/');
};

get '/list' => [qw/require_supervisor_login/] => sub {
    my ( $self, $c ) = @_;
    my $list = $self->users->all();

    my $sort = $c->req->param('s') || 'u';
    my $order = $c->req->param('o') || 'a';

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

    $c->render('list.tx', { list => $list, sort => $sort, order => $order });
};

get '/create' => [qw/require_supervisor_login/] => sub {
};

post '/post' => [qw/require_supervisor_login/] => sub {
};

get '/overwrite' => [qw/require_supervisor_login/] => sub {
};

post '/overwrite' => [qw/require_supervisor_login/] => sub {
};

post '/initalize' => [qw/require_supervisor_login/] => sub {
    # password initialization
};

post '/remove' => [qw/require_supervisor_login/] => sub {
};

1;
