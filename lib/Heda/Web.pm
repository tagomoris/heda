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
            return;
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
            $c->halt(401, 'specified operations requires login, see /.');
            return;
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
    my $errors;
    if ($errors = $c->stash->{session}->get('errors')) {
        $session->remove('errors');
    }
    #TODO set input values
    $errors ||= +{
        password => { flag => 0, message => '' },
        mismatch => { flag => 0, message => '' },
    };
    $c->render('index.tx', { errors => $errors });
};

post '/update' => [qw/check_supervisor_login/] => sub { # update accounts password by itself
    my ( $self, $c ) = @_;
    my ($username,$password,$new1,$new2) = map { $c->req->param($_); } qw/username password new_password1 new_password2/;
    my $r = $self->users->authenticate( username => $username, password => $password, bypass_validation => 1 );
    my $errors = {};
    unless ($r) {
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
        $c->stash->session->set('errors', $errors);
        #TODO store username input value into session
        return $c->redirect('/');
    }

    my $user = $self->users->search(username => $username);
    $self->update($user->{id}, $username, $user->{salt}, $password, $new1);
    #TODO store username input value into session
    #TODO store success flag into session

    $self->redirect('/');
};

get '/login' => [qw/check_supervisor_login/] => sub {
    
};

post '/login' => [qw/check_supervisor_login/] => sub {
    
};

get '/logout' => [qw/require_supervisor_login/] => sub {
};

get '/list' => [qw/require_supervisor_login/] => sub {
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
