# Cisco ASA plugin for Let's Encrypt client

This is a plugin for the [Certbot](https://github.com/certbot/certbot) client from [Let's Encrypt](https://letsencrypt.org).

It answers TLSSNI01 challenges using Cisco ASA boxes and installs the resulting certificates onto the ASAs. Both operations leverage the [Cisco ASA REST API](http://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html).

Neither the plugin nor the Certbot client run *on* the ASA. They run on a management host which speaks ACME to the Let's Encrypt service and talks to the REST API on the ASA boxes over HTTPS. The process looks something like this:

1. Certbot talks to Let's Encrypt, does it's usual account and key management stuff.
2. Certbot learns from the certbot-asa plugin that the plugin prefers TLSSNI01 challenges.
3. Certbot requests a certificate for the specified domain(s), receives challenge info from Let's Encrypt.
4. Certbot creates the certificates (local self-signed nonsense, one per domain) which are used to satisfy the challenge.
5. Certbot asks the plugin to install the challenge certificates.
6. The certbot-asa plugin converts the challenge certs/keys to PKCS12 format, imports into the ASA.
7. The certbot-asa plugin configures the ASA to use these certificates to satisfy challenges with: `ssl trust-point <something> domain <whatever>`
8. Certbot tells Let's Encrypt to please validate our control of the domain by checkign the installation of these new certificates.
9. The certbot-asa plugin removes the challenge certificates/keys from the ASA.
10. Certbot generates a CSR, submits it to Let's Encrypt.
11. Let's Encrypt delivers a new server certificate and chain to Certbot.
12. The certbot-asa plugin installs the new server certificate and any required chain elements onto the ASA.
13. The certbot-asa plugin configures the ASA to use the new certificate with one or more `ssl trust-point <something> domain <whatever>` lines.

## Requirements

* One or more Cisco ASA boxes with the REST API installed and configured. [Compatibility info](http://www.cisco.com/c/en/us/td/docs/security/asa/compatibility/asamatrx.html#pgfId-131643).
* A Linux host on which to run the Let's Encrypt client (certbot).
* ASA credentials for use by the Linux host.
* Accurate-ish clocks on both the Linux host and the ASA(s).
* DNS records for the `asa.company.com` published on the Internet, where the Let's Encrypt validator can see it.
* A *management name* by which the Linux host knows the ASAs. This must be different than the name end users use. Something like **asa-mgmt.company.com** or even just **asa-mgmt** is probably appropriate here. It does not need to use the physical management interface on the ASA. We just need a name by which we'll refer to the ASA.
* A TLS certificate used for management access to the ASA(s). This certificate will be for the management name above, and must be trusted by the Linux host. It's how the Linux host ensures it's not sending credentials to an attacker. Options here include:
  * A self-signed certificate generated right on the ASA (that's what I do.)
  * A real certificate from a well known CA (kind of defeats the purpose of trying to use Let's Encrypt.)
  * A certificate signed by your internal CA.

## Setup

### Install / Configure CentOS 7

I used CentOS 7, so these examples will go smoothly if you do too. But you can use whatever. It'd probably run on Windows.

Freshen up and install some packages we'll need:

```
$ sudo yum -y update
$ sudo yum -y install git openssl-perl
```

By default, python doesn't validate TLS certificates. Madness! Probably not
necessary with the `requests` module, but there's some `urllib2` stuff still
knocking around in there. Don't want to send credentials to a bad guy!

```
$ sudo sed -i 's/^verify=.*$/verify=enable/' /etc/python/cert-verification.cfg
```

Create pointers to the ASA management interface in `/etc/hosts` or use DNS.
This is the name we'll use for *management access* to the ASA (via TLS) so it
must be different from the name on the certificates we want from Let's Encrypt
(chickens, eggs, etc...) Do this for every ASA you'll be managing.

```
$ echo "192.168.100.11 asa-mgmt" | sudo tee -a /etc/hosts
```

### Install / Enable the REST API

Not much to it:

* Download the API bundle from Cisco, copy it to the ASA.
* Specify to the image with: `rest-api image disk0:/asa-restapi-etc-etc-etc`
* Enable the API with `rest-api agent`
* The API takes a few minutes to become available. I like to watch it with `debug rest-api agent`
* If your ASA is configured with `aaa authorization command` check out [bug](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv80223) and [bug](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw60598). You can work around the issues by either:
  * Adding ENABLE_1 and ENABLE_15 to you AAA server (nobody needs to know the password - it's for command authorization only)
  * Temporarily removing `aaa authorization command` while the REST API starts up. Not great at reboot time.
* Allow API access from your Linux host on the ASA with `http <address> <mask> <interface>` on the ASA(s).

### Test the REST API

Now we'll be putting some of those building blocks together. We're testing:

* Our credentials
* The hostname resolution
* Whether HTTPS access is allowed to the ASA
* The API configuration

```
$ curl -ksu <username>:<password> https://asa-mgmt/api/monitoring/serialnumber | sed 'a\'
{"kind":"object#QuerySerialNumber","serialNumber":"XXXXXXXXXX"}
```

If you got back the JSON blob with your ASA's serial number, then the API is working!

### Enable TLS for the management connection

The objective here is for your Linux host to trust the certificate presented by the when we're talking to the REST API. Generating a self-signed certificate on the ASA is pretty straightforward:

```
crypto key generate rsa label mgmt-tls-2048-bit-key modulus 2048
crypto ca trustpoint mgmt-selfsigned-cert
 enrollment self
 fqdn none
 subject-name CN=asa-mgmt
 keypair mgmt-tls-2048-bit-key
 crl configure
crypto ca enroll mgmt-selfsigned-cert noconfirm
ssl trust-point mgmt-selfsigned-cert domain asa-mgmt
```

Now we need to collect that certificate on the Linux host. Do this for each ASA.
Change the filename argument to the `tee` command so that different ASA certs
wind up in different files:

```
$ :| openssl s_client -showcerts -connect asa-mgmt:443 -servername vpnlab1 | openssl x509 | sudo tee -a /etc/pki/tls/certs/asa-mgmt.pem
```

Now we have a local copy of the ASA's self signed certificate. You can take a peek at it with
```
$ openssl x509 -in /etc/pki/tls/certs/asa-mgmt.pem -noout -text
```

Test the API again, but this time with certificate validation:

```
$ curl -su <username>:<password> --cacert /etc/pki/tls/certs/asa-mgmt.pem https://asa-mgmt/api/monitoring/serialnumber | sed 'a\'
{"kind":"object#QuerySerialNumber","serialNumber":"XXXXXXXXXX"}
```

If we got the serial number back *without* using the `-k` (don't verify certificates) option, then TLS validation checks out. Let's move on to installing certbot.

### Install Certbot

```
$ sudo yum install epel-release
$ sudo yum-config-manager --disable epel
$ sudo yum -y --enablerepo=epel install python-certbot-apache
```



## Command Line Options
Command line usage

## Caveats
* Removal of keys
* TLSSNI01 may be deprecated

