#!/usr/bin/perl

# Copyright (c) 2015 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use IO::Socket::INET;

use strict;
use warnings;

my %otps = (
  'vvincredibletrerdegkkrkkneieultcjdghrejjbckh' => 'OK',
  'vvincrediblltrerdegkkrkkneieultcjdghrejjbckh' => 'OK',
  'ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj' => 'OK',
);

my $port = shift;
die "no port specified" unless $port;

my $socket = new IO::Socket::INET (
  LocalHost => '127.0.0.1',
  LocalPort => $port,
  Proto => 'tcp',
  Listen => 10,
  Reuse => 1
) or die "Oops: $! \n";

warn "YKVAL mockup started on $port";

while(1) {
  my $clientsocket = $socket->accept();
  my $clientdata = <$clientsocket>;
  my $ret = "h=ZrU7UfjwazJVf5ay1P/oC3XCQlI=\n";

  if($clientdata =~ m/nonce=([a-zA-Z0-9]+).*otp=([cbdefghijklnrtuv]+)/) {
    my $nonce = $1;
    my $otp = $2;
    warn "validation for $otp (on port $port)";
    if($otps{$otp}) {
      my $status = $otps{$otp};
      $ret .= "nonce=$nonce\n";
      $ret .= "otp=$otp\n";
      $ret .= "status=$status";
    } else {
      $ret .= "status=BAD_OTP";
    }
  } else {
    $ret .= "status=MISSING_PARAMETER";
  }
  print $clientsocket "\n$ret\n";
  close $clientsocket;
}
