Introduction
------------

The purpose of this page is to collect all information needed to set up a Radius server that can use the pam_yubico module to provide user authentication via Radius.

Details
-------

We currently use FreeRadius.  The paths below may be specific to Debian's packages, please update this if you have paths for other systems.

Build pam_yubico and install FreeRadius
---------------------------------------

Build instructions for pam_yubico are found in the pam_yubico ReadMe.

Install FreeRadius from your OS vendor packages:

Debian/Ubuntu:

 $ sudo apt-get install freeradius


== Add a Radius client stanza to /etc/freeradius/clients.conf

For testing, add something like:

------
client 0.0.0.0/0 {
	secret          = pencil
	shortname       = radius.yubico.com
}
------

Configure FreeRadius so that it uses PAM
----------------------------------------

In /etc/freeradius/radiusd.conf, check that 'pam' is uncommented in the 'authenticate' section.

Configure PAM for the Radius server
-----------------------------------

The PAM service is 'radiusd', and the configuration file is stored in /etc/pam.d/radiusd.  Add something like:

 auth sufficient pam_yubico.so id=16 debug


Start FreeRadius in debug mode and test it
------------------------------------------

As root, run:

 # /usr/sbin/freeradiusd -X

Then invoke a test client as follows:

 $ radtest yubico vlrlcingbbkrctguicnijbegfjhrdhccefdthcuifkgr 127.0.0.1 0 pencil

If you get errors about non-existing user, you may need to create a Unix user 'yubico'.  Whether this should be needed or not depends on PAM configuration.
