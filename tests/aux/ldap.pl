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

use strict;
use warnings;

package PamServer;
use Net::LDAP::Server;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

use base 'Net::LDAP::Server';

use constant RESULT_OK => {
  'matchedDN' => '',
  'errorMessage' => '',
  'resultCode' => LDAP_SUCCESS
};

my %objects = (
  'base=uid=foo,ou=users,dc=example,dc=com' => {keys => ['vvincredible']},
  'base=uid=test,ou=users,dc=example,dc=com' => {keys => ['cccccccfhcbe', 'ccccccbchvth']},
  'sub:base=:(uid=test)' => {keys => ['cccccccfhcbe', 'ccccccbchvth'], dn => 'uid=test,out=users,dc=example,dc=com'},
);

sub bind {
  my $self = shift;
  my $reqData = shift;
  return RESULT_OK;
}

sub search {
  my $self = shift;
  my $reqData = shift;
  my $id;
  my $base;
  if($reqData->{'scope'} == 0) {
    $base = $reqData->{'baseObject'};
    $id = $objects{'base=' . $base};
  } elsif($reqData->{'scope'} == 2) {
    my $match = $reqData->{'filter'}->{'equalityMatch'};
    $id = $objects{'sub:base=' . $reqData->{'baseObject'} . ':(' . $match->{'attributeDesc'} . '=' . $match->{'assertionValue'} . ')'};
    $base = $id->{'dn'};
  }
  warn "ldap search with " . $reqData->{'scope'};
  my @entries;
  if($id) {
    my $entry = Net::LDAP::Entry->new;
    $entry->dn($base);
    $entry->add(objectClass => [ "person" ]);
    $entry->add(yubiKeyId => $id->{'keys'});
    push @entries, $entry;
  }
  return RESULT_OK, @entries;
}

package main;

use IO::Socket::INET;
use IO::Select;

my $port = shift;
die "no port specified" unless $port;

my $sock = IO::Socket::INET->new(
  Proto     => 'tcp',
  LocalAddr => "localhost:$port",
  Reuse     => 1
) or die "$!";
$sock->listen();

my $sel = IO::Select->new($sock);
my %handlers;

warn "LDAP mockup started";

while (my @ready = $sel->can_read) {
  foreach my $fh (@ready) {
    if ($fh == $sock) {
      my $psock = $sock->accept;
      $sel->add($psock);
      $handlers{*$psock} = PamServer->new($psock);
    } else {
      my $result = $handlers{*$fh}->handle;
      if ($result) {
        $sel->remove($fh);
        $fh->close;
        delete $handlers{*$fh};
      }
    }
  }
}
