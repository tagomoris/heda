package Heda::Util;

use 5.014;
use English;
use Log::Minimal;

use List::Util;
use Digest::SHA qw//;

sub get_char { my ($chars) = @_; substr($chars, int(rand(length($chars))), 1); }

sub get_alphabet {
    # misleading small-L, small-o, large-I, large-O are omitted
    get_char('abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
}

sub get_num {
    # misleading Zero, One is omitted
    get_char('23456789');
}

sub get_symbol {
    get_char('-_.,/=+^!~]');
}

sub gen_password {
    my @chars = ();
    push @chars, (get_alphabet(), get_alphabet(), get_alphabet(), get_alphabet(), get_alphabet());
    push @chars, (get_num(), get_num());
    push @chars, get_symbol();
    return join('', List::Util::shuffle(@chars));
}

sub gen_pincode {
    my $pin = int(rand(1000));
    my $hidden = gen_password();
    my $hash = Digest::SHA::sha256_hex("$pin" . $hidden);
    return ($pin, $hidden, $hash);
}

sub check_pincode {
    my ($pin, $hidden, $hash) = @_;
    return Digest::SHA::sha256_hex("$pin" . $hidden) eq $hash;
}

1;
