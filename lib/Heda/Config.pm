package Heda::Config;

use 5.014;
use utf8;
use English;
use Log::Minimal;

use JSON::XS;

sub new {
    my ($this, $root_dir) = @_;

    my $filename = 'config.json';
    if ($ENV{PLACK_ENV} eq 'production') {
        $filename = 'config.production.json';
    }
    my $path = $root_dir . '/' . $filename;
    my $default = default_config();
    my $self = {};
    if ( -f $path ) {
        $self = load_config( $path );
    }
    foreach my $key (keys(%$default)) {
        $self->{$key} ||= $default->{$key};
    }

    bless $self, $this;

    $self->configure_logger();
    return $self;
}

sub default_config {
    return +{
        database => {
            dsn => "DBI:mysql:database=heda;host=localhost",
            username => 'root',
            password => '',
        },
        password_patterns => [
            '^[-_ .,/?<>\[\]{}|=+()*&^%$#@!~a-zA-Z0-9]{8,}$',
            '[a-zA-Z]',
            '[0-9]',
            '[-_ .,/?<>\[\]{}|=+()*&^%$#@!~]'
        ],
        sessiondb => {
            dsn => "DBI:mysql:database=hedasession;host=localhost",
            username => 'root',
            password => '',
            expires => 1800,
        },
        accounts => ['login', 'git'],
        loglevel => 'INFO',
    };
}

sub load_config {
    my $path = shift;
    my $json_obj = try {
        open( my $fh, '<', $path) or die $!;
        my $json_string = join('', <$fh>);
        close($fh);
        decode_json($json_string);
    } catch {
        warnf "configuration file %s load error: %s", $path, $_;
        undef;
    };
    return $json_obj;
}

sub configure_logger {
    my $self = shift;

    $Log::Minimal::LOG_LEVEL = uc($self->{loglevel});
    $ENV{LM_DEBUG} = 1 if $self->{loglevel} eq 'DEBUG';

    $Log::Minimal::AUTODUMP = 1;
    $Log::Minimal::PRINT = sub {
        my ( $time, $type, $message, $trace, $raw_message) = @_;
        if ( $type eq 'INFO' ) {
            print "$time [$type] ($PID) $message\n";
        }
        else {
            print "$time [$type] ($PID) $message at $trace\n";
        }
    };
    $Log::Minimal::DIE = sub {
        my ( $time, $type, $message, $trace, $raw_message) = @_;
        die "$time [$type] ($PID) $message at $trace\n";
    };
}

1;
