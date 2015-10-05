== Yubico PAM Two-factor configuration guide ==

Step by Step Guide for Configuration of Yubico PAM module to provide Two-factor
legacy Username + password + YubiKey OTP authentication for RADIUS server.

=== Introduction ===
The purpose of this document is to guide readers through the configuration
steps to enable two factor authentication using YubiKey and RADIUS server on
Linux platform. This document assumes that the reader has advance knowledge
and experience in Linux system administration, particularly how to configure
PAM authentication mechanism on a Linux platform.

Although this configuration guide focuses on configuration of radiusd daemon for
local authentication using the custom database (we have used /etc/passwd),
radiusd can be configured easily to use centralized LDAP database for
authentication or any popular directory service by configuring appropriate PAM
modules in radiusd PAM configuration file.


=== Prerequisites ===
Successful configuration of the Yubico PAM module to support two factor
authentication for RADIUS requires following prerequisites:

Operating System::
Any Unix operating system which supports http://www.kernel.org/pub/linux/libs/pam[PAM]
(Pluggable Authentication Module)

Complier:: http://gcc.gnu.org[GNU GCC complier]

http://freeradius.org/download.html[FreeRADIUS]:: Version: 1.1.7 or later

https://developers.yubico.com/yubico-pam[Yubico PAM Module]:: Version 1.8

=== Configuration ===
We assume that FreeRADIUS is already installed on the server.

==== Configuration of FreeRADIUS server to support PAM authentication ====

* Edit the radiusd configuration file `/etc/raddb/radiusd.conf` to make
  following changes:

  - Change user and group to “root” to provide the root privileges to
    radiusd daemon so that it can call and use pam modules for authentication.
    
  - In “authenticate” section uncomment pam to direct radiusd daemon to use PAM
    module for authentication
    
NOTE: Generally, it is not a good security practice to assign root
privileges to a user for a daemon. However, since use of PAM requires root
privileges, this is a mandatory step here.
    
* Add sample client for testing in the client configuration
  file `/etc/raddb/clients.conf`.

* Edit the user configuration file `/etc/raddb/users`, changing
  `DEFAULT Auth-Type = System` to `DEFAULT Auth-Type = pam` for using
  PAM modules for user authentication.


=== Installation of pam_yubico module ===

Build instructions for pam_yubico are available in the README.
(https://developers.yubico.com/yubico-pam/)


=== Configuration of pam_yubico module === 

Configuration instructions for pam_yubico are also available in the README.
(https://developers.yubico.com/yubico-pam/)

NOTE: Make sure you set your system up for either central authorization mapping,
or user level mapping, as this will control which users can connect to the
system using RADIUS.


=== Configuration of modified pam_yubico.so module at administrative level ===

Append the following line to the beginning of /etc/pam.d/radiusd file:

 auth required pam_yubico.so id=16 debug authfile=/etc/yubikey_mappings

After the above configuration changes, whenever a user connects to the
server using any RADIUS client, the PAM authentication interface will pass
the control to Yubico PAM module.

The Yubico PAM module first checks the presence of authfile argument in PAM
configuration. If authfile argument is present, it parses the corresponding
mapping file and verifies the username with corresponding YubiKey PublicID
as configured in the mapping file.

If valid, the Yubico PAM module extracts the OTP string and sends it to the
Yubico authentication server or else it reports failure. If authfile argument
is present but the mapping file is not present at the provided path PAM
module reports failure. After successful verification of OTP Yubico PAM module
from the Yubico authentication server, a success code is returned.


==== User Level ====

Although, user level configuration of pam_yubico is possible, this might not
be a desired configuration option in case of radisud daemon in most enterprise.


=== Configuration of SElinux policy to create exception for radiusd daemon ===
Local effective SElinux policy must be updated to provide sufficient
privileges to radiusd daemon on system resources. Please follow the steps below
to configure effective selinux policy for radiusd daemon:

* Start the radiusd daemon
* Test the RADIUS authentication with the test case provided in “Testing the
  configuration” section below
* As radiusd daemon doesn’t have sufficient selinux privileges to access the
  system resources required for using pam modules, the RADIUS authentication
  will fail.
* This will create the logs in either “/var/log/messages” or in
  “/var/log/audit/audit.log” depending on the selinux configuration.
* We can use audit2allow utility to provide selinux privileges to radiusd by
  using following sequence of commands:

----
[root@testsrv ~]# audit2allow -m local -l -i /var/log/messages > local.te

[root@testsrv ~]# checkmodule -M -m -o local.mod local.te

[root@testsrv ~]# semodule_package -o local.pp -m local.mod

[root@testsrv ~]# semodule -i local.pp
----

For more selinux policy updating information and explanation of above commands
please visit the following website:

 http://fedora.redhat.com/docs/selinux-faq-fc5/#id2961385


=== Test Setup ===

Our test environment is as follows:

[horizontal]
*Operating System*:: Fedora release 8 (Werewolf)
*FreeRADIUS Server*:: Version 1.1.7
*Yubico PAM*:: Version 1.8
*/etc/pam.d/radiusd file*::
+
----
auth      	 required     	pam_yubico.so authfile=/etc/yubikeyid id=16 debug
auth       	 include     	system-auth
account   	 required  	pam_nologin.so
account    	 include      	system-auth
password  	 include     	system-auth
session    	 include     	system-auth
----


=== Testing the configuration ===

We have tested the pam_yubico configuration on following Linux sever platforms:

Fedora 8:

* Operating system: Fedora release 8 (Werewolf)
* FreeRADIUS Server : FreeRADIUS Version 1.1.7
* Yubico PAM: pam_yubico  Version 1.8

Fedora 6:

* Operating system: Fedora Core release 6 (Zod)
* FreeRADIUS Server : FreeRADIUS Version 1.1.7
* Yubico PAM: pam_yubico  Version 1.8

To test the RADIUS two factor authentication with YubiKey, we can use
'radtest' radius client. The command is as follows:

----
[root@testsrv ~]# radtest {username} \
  	    	    {password followed by YubiKey generated OTP} \
  		    {radius-server}:{radius server port} \
		    {nas-port-number} \
		    {secret/ppphint/nasname}

[root@testsrv ~]# radtest test test123vrkvit...bekkjc 127.0.0.1 0 testing123
----


NOTE:
The FreeRADIUS server version 1.1.3 seems to have problems regarding memory
management and it may result in Segmentation Fault if configured with Yubico
PAM module. We recommend using FreeRADIUS server version 1.1.7 or above.
