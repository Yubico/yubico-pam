== Setting up your YubiKey for challenge response authentication on Max OS X ==

This article explains the process to get the challenge-response
authentication possible with newer YubiKeys working on Mac OS X. Since
Mac OS X uses PAM like most other Unix/POSIX systems do, most of this
should apply to other operating systems, too.

=== Getting yubico-pam ===

First you will have to install yubico-pam and its dependencies
required for challenge-response authentication. Use your
distribution's package manager to get it, or build from source. If
you're on OS X you can use http://www.macports.org[MacPorts] to
install yubico-pam:

     sudo port install yubico-pam

NOTE: This will probably not work in non-superuser installations
  of MacPorts, because it needs to place the yubico PAM module into
  `/usr/lib/pam`.

=== Configuring your YubiKey ===

The next step would be to set up your YubiKey for challenge-response
authentication, if you haven't done so already. Although this is
possible with the command line `ykpersonalize` tool, the GUI "YubiKey
Personalization Tool" is a more comfortable way to do this.

1. Plug in your YubiKey and start the YubiKey Personalization Tool
+
NOTE: YubiKey Personalization Tool shows whether your YubiKey supports challenge-response in the lower right.
2. Click 'Challenge-Response'
3. Select HMAC-SHA1 mode. Apparently Yubico-OTP mode doesn't work with yubico-pam at the moment.
4. Select the configuration slot you want to use  
(this text assumes slot two, but it should be easy enough to adapt the instructions if you prefer slot 1)
5. Select whether you want to require pressing the button for authentication  
+
NOTE: If you enable this, you will have to press the button twice for each authentication with yubico-pam. This is because the PAM module does not only send the challenge on file and checks whether the response matches, but also generates a new challenge-response pair on success.
6. Use 'Variable input' as HMAC-SHA1 mode  
+
WARNING: Using 'Fixed 64 byte input' for this value made my YubiKey always return the same response regardless of what the challenge was. Since this defies the purpose of challenge-response think twice and test before you use this!
7. Generate a secret key  
You won't need this key again, it's sufficient to have it on your YubiKey. Note that the YubiKey Personalization Tool by default logs the key to configuration_log.csv in your home directory. Consider turning this off in the settings before writing or shredding the file after writing.
8. Click 'Write Configuration'

=== Configuring your user account to accept the YubiKey ===

After setting up your YubiKey you need to configure your account to
accept this YubiKey for authentication. To do this, open a terminal
and run

    # create the directory where ykpamcfg will store the initial challenge
    mkdir -m0700 -p ~/.yubico
    # get the initial challenge from the YubiKey
    ykpamcfg -2

If you used slot 1 above, replace -2 with -1. If you configured your
YubiKey to require a button press the LED on the YubiKey will start
blinking; press the button to send a challenge-response
response. `ykpamcfg` should finish successfully telling you that it
stored the initial challenge somewhere inside your home directory:

----
Stored initial challenge and expected response in '/path/to/your/home/.yubico/challenge-KEYID'.
----

This step will create a file with a challenge and the expected
response (that can only be generated with the secret
key footnote:[This is also the reason why you should avoid having copies of the key in other places than your YubiKey!] )
in your home directory. The PAM module will later open this file, read the
challenge, send it to the connected YubiKey and check whether its
answer matches the one on file. If it does, it generates a new
challenge, asks the YubiKey for the correct response for this
challenge and writes both into the file. This also means that you need
to keep this file secure from other users (which is why we created the
.yubico directory in your home with mode 0700).

=== Configuring your system to use Yubico PAM for authentication ===

Linux, Solaris, OS X and most BSD variants use the 
http://en.wikipedia.org/wiki/Pluggable_Authentication_Modules[Pluggable
Authentication Modules] (PAM) framework to handle authentication.
Using PAM you can specify which
modules are used for authentication of users and which of them are
required, optional and/or sufficient to authenticate a user. Using PAM
you can for example set up multiple-factor authentication, by chaining
multiple required modules.

PAM is configured through files in `/etc/pam.d` on most systems. Each
file in this directory is used for a specific service, i.e. the file
`/etc/pam.d/sudo` is used to authenticate users for the `sudo`
program. Debian, for example, uses include directives in these files
to have a central place to configure authentication; in this case we
are not using this on purpose, because challenge-response
authentication doesn't work remotely (e.g. via SSH), so we only want
to configure it for services we use when on site.

The file format in these files is documented in `man 5 pam.conf`; it
looks like this:

    function-class control-flag module-path arguments

where

[horizontal]
*function-class*:: is one of `auth`, `account`, `session`, and
  `password`. Since we only care about authentication with the YubiKey
  and yubico-pam only handles authentication, we will always be using
  `auth` here.

*control-flag*:: is one of `required`, `sufficient`, `optional` and
  some other values depending on your PAM implementation. If we want
  to make YubiKey challenge-response mandatory but combined with other
  methods (e.g. password), we can use `required`, if we want
  successful challenge-response to be enough to authenticate a user,
  we can use `sufficient`. `optional` is not of any use for us
  in this case.

*module-path*:: selects the module to be used for this authentication
  step. This is used as filename in a directory where pam libraries
  are expected, on OS X e.g. `/usr/lib/pam`, `/usr/lib/security` on
  some other systems. We want `pam_yubico.so` in this case, which will
  load `/usr/lib/pam/pam_yubico.so`.

*arguments*:: are passed to the pam module and can be used to
  configure its behavior. See 'Supported PAM module parameters' in
  https://github.com/Yubico/yubico-pam/blob/master/README[README]
  for a list of possible values. Since we want to use
  challenge-response, we add `mode=challenge-response` and to debug
  the setup initially also `debug`, separated by spaces. `debug` can
  safely be removed later.


WARNING: If you misconfigure your PAM modules here you might lose
  your ability to sudo! Always keep a root shell open to be able to
  revert your changes in case something goes wrong!

So, if we wanted to use the YubiKey to allow us to sudo without typing
a password, we would add

----
auth       sufficient     pam_yubico.so mode=challenge-response debug
----

To get this working on the loginwindow for local interactive login add
the `pam_yubico.so` to the `pam.d` file authorization as the first
line. The whole file might look something like this (example taken
from OS X):

----
# sudo: auth account password session
auth       sufficient     pam_yubico.so mode=challenge-response debug
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
----

If we wanted to require successful challenge-response authentication
in addition to the usual password, we can change the `sufficient` in
the line we added to `required`.

NOTE: In theory you can configure pretty much any service you use
  locally to use challenge-response authentication. In practice, I had
  problems configuring challenge-response into the login window of OS
  X. Keep a rescue disk or a remote root terminal available when
  attempting such configurations, just in case something goes wrong
  and you need to restore the PAM configuration to an old state.

NOTE: On Debian it started working for me after accidentally
  getting the file-rights correctly. `755` for `~/.yubico` & `600` for
  the files therein. Otherwise the module can't find, read and/or
  write to the appropriate files. Your clue is the following debug
  messages.

----
[drop_privs.c:restore_privileges(128)] pam_modutil_drop_priv: -1
[pam_yubico.c:do_challenge_response(542)] could not restore privileges
[pam_yubico.c:do_challenge_response(664)] Challenge response failed: No such file or directory
----
