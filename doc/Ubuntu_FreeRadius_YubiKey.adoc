Ubuntu FreeRadius YubiKey
-------------------------

Create and login to a fresh Ubuntu 10.04 LTS machine:

------
vmbuilder kvm ubuntu \
  --dest /var/lib/libvirt/images/freeradius \
  --proxy http://192.168.1.2/ubuntu \
  --rootsize 10000 \
  --mem 600 \
  --suite lucid \
  --flavour virtual \
  --addpkg unattended-upgrades \
  --addpkg openssh-server \
  --addpkg avahi-daemon \
  --addpkg acpid \
  --ssh-key /root/.ssh/authorized_keys \
  --libvirt qemu:///system \
  --hostname freeradius \
  --bridge br0 \
  --debug
ssh -l root freeradius.local
------

Install and configure software :
--------------------------------

------
   apt-get install build-essential wget
   apt-get install libpam0g-dev libykclient3 libykclient-dev
------

Install PAM module:

------
   wget http://yubico-pam.googlecode.com/files/pam_yubico-2.4.tar.gz
   tar xfz pam_yubico-2.4.tar.gz 
   cd pam_yubico-2.4
   ./configure 
   make check install
   ln -s /usr/local/lib/security/pam_yubico.so /lib/security/
------

Setup PAM debug log file:

------
   touch /var/run/pam-debug.log 
   chmod go+w /var/run/pam-debug.log 
   tail -F /var/run/pam-debug.log &
------

Install FreeRadius:

------
   apt-get install freeradius
   /etc/init.d/freeradius stop
------

Next we configure FreeRadius.  First add this to /etc/freeradius/users:

------
   DEFAULT Auth-Type = pam
------

Then comment out 'pap' and uncomment 'pam' from
/etc/freeradius/sites-available/default.

Add to the top of /etc/pam.d/radiusd:

------
   auth sufficient pam_yubico.so id=1 debug authfile=/etc/yubikey_mapping
------

If you want to use HMAC signing, specify the 'key=' field too, like this:

------
   auth sufficient pam_yubico.so id=1 key=b64foo debug authfile=/etc/yubikey_mapping
------

Create a file /etc/yubikey_mapping (ccccccccltnc is Alice's YubiKey's public ID) :

------
   alice:ccccccccltnc
------

Create a Unix account 'alice':   XXX should not be necessary?

------
   adduser --disabled-password alice
------

Just press RET and finally 'y RET' on the prompts.

Start radiusd:

------
   LD_PRELOAD=/lib/libpam.so.0 freeradius -X
------


Testing authentication :
------------------------

Confirm that it works with radtest (use a real OTP from Alice's YubiKey) :

------
   radtest alice ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef 127.0.0.1 0 testing123
------

Output should be like this:

------
Sending Access-Request of id 69 to 127.0.0.1 port 1812
	User-Name = "alice"
	User-Password = "ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef"
	NAS-IP-Address = 127.0.1.1
	NAS-Port = 0
rad_recv: Access-Accept packet from host 127.0.0.1 port 1812, id=69, length=20
------

PAM debug output should be like this:

------
[pam_yubico.c:parse_cfg(404)] called.
[pam_yubico.c:parse_cfg(405)] flags 0 argc 3
[pam_yubico.c:parse_cfg(407)] argv[0]=id=1
[pam_yubico.c:parse_cfg(407)] argv[1]=debug
[pam_yubico.c:parse_cfg(407)] argv[2]=authfile=/etc/yubikey_mapping
[pam_yubico.c:parse_cfg(408)] id=1
[pam_yubico.c:parse_cfg(409)] key=(null)
[pam_yubico.c:parse_cfg(410)] debug=1
[pam_yubico.c:parse_cfg(411)] alwaysok=0
[pam_yubico.c:parse_cfg(412)] verbose_otp=0
[pam_yubico.c:parse_cfg(413)] try_first_pass=0
[pam_yubico.c:parse_cfg(414)] use_first_pass=0
[pam_yubico.c:parse_cfg(415)] authfile=/etc/yubikey_mapping
[pam_yubico.c:parse_cfg(416)] ldapserver=(null)
[pam_yubico.c:parse_cfg(417)] ldap_uri=(null)
[pam_yubico.c:parse_cfg(418)] ldapdn=(null)
[pam_yubico.c:parse_cfg(419)] user_attr=(null)
[pam_yubico.c:parse_cfg(420)] yubi_attr=(null)
[pam_yubico.c:pam_sm_authenticate(452)] get user returned: alice
[pam_yubico.c:pam_sm_authenticate(542)] conv returned: ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef
[pam_yubico.c:pam_sm_authenticate(558)] OTP: ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef ID: ccccccccltnc 
[pam_yubico.c:pam_sm_authenticate(583)] ykclient return value (0): Success
[pam_yubico.c:check_user_token(117)] Authorization line: alice:ccccccccltnc
[pam_yubico.c:check_user_token(121)] Matched user: alice
[pam_yubico.c:check_user_token(125)] Authorization token: ccccccccltnc
[pam_yubico.c:check_user_token(128)] Match user/token as alice/ccccccccltnc
[pam_yubico.c:pam_sm_authenticate(625)] done. [Success]
------

FreeRadius debug output should be like this:

------
rad_recv: Access-Request packet from host 127.0.0.1 port 38575, id=69, length=89
	User-Name = "alice"
	User-Password = "ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef"
	NAS-IP-Address = 127.0.1.1
	NAS-Port = 0
+- entering group authorize {...}
++[preprocess] returns ok
++[chap] returns noop
++[mschap] returns noop
[suffix] No '@' in User-Name = "alice", looking up realm NULL
[suffix] No such realm "NULL"
++[suffix] returns noop
[eap] No EAP-Message, not doing EAP
++[eap] returns noop
[files] users: Matched entry DEFAULT at line 204
++[files] returns ok
++[expiration] returns noop
++[logintime] returns noop
Found Auth-Type = PAM
+- entering group authenticate {...}
pam_pass: using pamauth string <radiusd> for pam.conf lookup
pam_pass: authentication succeeded for <alice>
++[pam] returns ok
+- entering group post-auth {...}
++[exec] returns noop
Sending Access-Accept of id 69 to 127.0.0.1 port 38575
Finished request 0.
Going to the next request
Waking up in 4.9 seconds.
Cleaning up request 0 ID 69 with timestamp +17
Ready to process requests.
------

Testing a OTP replay :
----------------------

Run the command again, with the _same_ OTP :

------
radtest alice ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef 127.0.0.1 0 testing123
------

Then output should be like this, since the OTP was replayed:

------
Sending Access-Request of id 32 to 127.0.0.1 port 1812
	User-Name = "alice"
	User-Password = "ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef"
	NAS-IP-Address = 127.0.1.1
	NAS-Port = 0
rad_recv: Access-Reject packet from host 127.0.0.1 port 1812, id=32, length=20
------

PAM debug log:

------
[pam_yubico.c:parse_cfg(404)] called.
[pam_yubico.c:parse_cfg(405)] flags 0 argc 3
[pam_yubico.c:parse_cfg(407)] argv[0]=id=1
[pam_yubico.c:parse_cfg(407)] argv[1]=debug
[pam_yubico.c:parse_cfg(407)] argv[2]=authfile=/etc/yubikey_mapping
[pam_yubico.c:parse_cfg(408)] id=1
[pam_yubico.c:parse_cfg(409)] key=(null)
[pam_yubico.c:parse_cfg(410)] debug=1
[pam_yubico.c:parse_cfg(411)] alwaysok=0
[pam_yubico.c:parse_cfg(412)] verbose_otp=0
[pam_yubico.c:parse_cfg(413)] try_first_pass=0
[pam_yubico.c:parse_cfg(414)] use_first_pass=0
[pam_yubico.c:parse_cfg(415)] authfile=/etc/yubikey_mapping
[pam_yubico.c:parse_cfg(416)] ldapserver=(null)
[pam_yubico.c:parse_cfg(417)] ldap_uri=(null)
[pam_yubico.c:parse_cfg(418)] ldapdn=(null)
[pam_yubico.c:parse_cfg(419)] user_attr=(null)
[pam_yubico.c:parse_cfg(420)] yubi_attr=(null)
[pam_yubico.c:pam_sm_authenticate(452)] get user returned: alice
[pam_yubico.c:pam_sm_authenticate(542)] conv returned: ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef
[pam_yubico.c:pam_sm_authenticate(558)] OTP: ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef ID: ccccccccltnc 
[pam_yubico.c:pam_sm_authenticate(583)] ykclient return value (2): Yubikey OTP was replayed (REPLAYED_OTP)
[pam_yubico.c:pam_sm_authenticate(625)] done. [Authentication failure]
------

FreeRadius debug log:

------
rad_recv: Access-Request packet from host 127.0.0.1 port 55170, id=32, length=89
	User-Name = "alice"
	User-Password = "ccccccccltncdjjifceergtnukivgiujhgehgnkrfcef"
	NAS-IP-Address = 127.0.1.1
	NAS-Port = 0
+- entering group authorize {...}
++[preprocess] returns ok
++[chap] returns noop
++[mschap] returns noop
[suffix] No '@' in User-Name = "alice", looking up realm NULL
[suffix] No such realm "NULL"
++[suffix] returns noop
[eap] No EAP-Message, not doing EAP
++[eap] returns noop
[files] users: Matched entry DEFAULT at line 204
++[files] returns ok
++[expiration] returns noop
++[logintime] returns noop
Found Auth-Type = PAM
+- entering group authenticate {...}
pam_pass: using pamauth string <radiusd> for pam.conf lookup
pam_pass: function pam_authenticate FAILED for <alice>. Reason: Permission denied
++[pam] returns reject
Failed to authenticate the user.
Using Post-Auth-Type Reject
+- entering group REJECT {...}
[attr_filter.access_reject] 	expand: %{User-Name} -> alice
 attr_filter: Matched entry DEFAULT at line 11
++[attr_filter.access_reject] returns updated
Delaying reject of request 1 for 1 seconds
Going to the next request
Waking up in 0.5 seconds.
Sending delayed reject for request 1
Sending Access-Reject of id 32 to 127.0.0.1 port 55170
Waking up in 4.9 seconds.
Cleaning up request 1 ID 32 with timestamp +66
Ready to process requests.
------
