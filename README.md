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
$ set +o history
$ curl -ksu <username>:<password> https://asa-mgmt/api/monitoring/serialnumber | sed 'a\'
{"kind":"object#QuerySerialNumber","serialNumber":"XXXXXXXXXX"}
$ set -o history
```

If you got back the JSON blob with your ASA's serial number, then the API is working!

### Enable TLS for the management connection

The objective here is for your Linux host to trust the certificate presented by the ASA when we're talking to the REST API. Generating a self-signed certificate on the ASA is pretty straightforward:

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
Change the `tee` command's filename argument so that different ASA certs
wind up in different files:

```
$ :| openssl s_client -showcerts -connect asa-mgmt:443 -servername asa-mgmt | openssl x509 | sudo tee -a /etc/pki/tls/certs/asa-mgmt.pem
```

Now we have a local copy of the ASA's self signed certificate. You can take a peek at it with:

```
$ openssl x509 -in /etc/pki/tls/certs/asa-mgmt.pem -noout -text
```

Test the API again, but this time with certificate validation:

```
$ set +o history
$ curl -su <username>:<password> --cacert /etc/pki/tls/certs/asa-mgmt.pem https://asa-mgmt/api/monitoring/serialnumber | sed 'a\'
{"kind":"object#QuerySerialNumber","serialNumber":"XXXXXXXXXX"}
$ set -o history
```

If we got the serial number back *without* using the `-k` (don't verify certificates) option, then TLS validation checks out. Let's move on to installing certbot.

### Install Certbot

```
$ sudo yum -y install epel-release yum-utils
$ sudo yum-config-manager --disable epel
$ sudo yum -y --enablerepo=epel install python-certbot-apache
```

### Optional: Test Certbot

If the test machine is internet-facing, has a DNS record pointing at it and has
TCP/443 exposed, then we can test `certbot` alone (without the ASA plugin.)
While the `certbot-asa` plugin doesn't require any privilege on the Linux host,
running `certbot` in standalone mode requires root access because the `boulder`
(Let's Encrypt's CA component) validation bits connect to us on a privileged
port.  Here's how to test `certbot` as root (provided that it's interesting and
possible to do so):

```
# Open up incoming connections in iptables:
$ sudo firewall-cmd --add-port=443/tcp

# Test certbot:
$ sudo certbot certonly \
  --text \
  --standalone \
  --register-unsafely-without-email \
  --agree-tos \
  --test-cert \
  --config-dir /tmp/certbot-conf \
  --work-dir /tmp/certbot-work \
  --logs-dir /tmp/certbot-logs \
  -d <linux host's name in internet-facing DNS>

# Cleanup
$ sudo firewall-cmd --remove-port=443/tcp
$ sudo rm -rf /tmp/certbot-conf /tmp/certbot-work /tmp/certbot-logs
```

### Install The Certbot-ASA Plugin

#### Plugin Prerequisites

We need requests [2.9.0](https://github.com/kennethreitz/requests/blob/master/HISTORY.rst#290-2015-12-15)
or later for sensible certificate validation. We'll use `pip` to get it.

```
$ sudo yum -y --enablerepo=epel install python-pip
$ sudo pip install 'requests>=2.9.0'
```

We previously dumped the ASA's self-signed certificate into a file in `/etc/pki/tls/certs`.
The python `requests` module only allows us to specify a single pointer for trusted root
certificates. We could point at the file, but it's nice to point at the directory instead.
`c_rehash` makes that possible by filling the directory with symlink pointers which help
the requests module find its way:

```
$ sudo c_rehash /etc/pki/tls/certs
```

The plugin can run without any privilege, so I like to create a non-root user for that purpose:

```
$ sudo useradd -r certbot-asa
```

Next, give the letsencrypt `config`, `work` and `log` directories to the new user.

```
$ sudo mkdir -pm 0700 /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
$ sudo chown certbot-asa:certbot-asa /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
```

#### Download and install the plugin:

```
$ git clone https://github.com/chrismarget/certbot-asa /tmp/certbot-asa
$ (cd /tmp/certbot-asa; sudo python /tmp/certbot-asa/setup.py install)
```

#### Configure the plugin

The plugin needs your ASA credentials. It expects to find them in a file
named asa_creds.txt in certbot's config-dir. The file must be `chmod go-rwx` for the plugin to accept it.
One line per ASA with the following fields, delimited by ';' characters.

```
hostname;username;password
```

The hostname must match the *management name* we used when setting up the
management TLS certificate. It's okay if there's a ';' character embedded in
the password. Create the credentials file:

```
$ sudo su certbot-asa -c '(umask 0077; touch /etc/letsencrypt/asa_creds.txt)'
$ set +o history
$ echo "asa-mgmt;username;password" | sudo tee -a /etc/letsencrypt/asa_creds.txt
$ set -o history
```

Create a certbot configuration file:

```
$ sudo su certbot-asa -c '(umask 0077; touch /etc/letsencrypt/cli.ini)'
$ sudo tee -a /etc/letsencrypt/cli.ini <<< "$(cat << EOF
server = https://acme-staging.api.letsencrypt.org/directory
email = somebody@somewhere.com
text = True
agree-tos = True
debug = True
verbose = True
EOF
)"
```

## Run the plugin!

We're going to get a certificate for `asa.company.com` installed onto the box we call `asa-mgmt`. Run this as the `certbot-asa` user:

```
certbot -a certbot-asa:asa -d asa.company.com --certbot-asa:asa-host asa-mgmt --certbot-asa:asa-castore /etc/pki/tls/certs
```

If everything went well, there should be at least one new trustpoint on the ASA named `LE_cert_<hash>_<date>_to_<date>`.
That's the new certificate. It should have a matching RSA keypair. There's also probably at least one chain certificate named
`LE_Chain_<hash>_expires_<date>`. Note that these are *test certificates* issued by the `acme-staging` server referenced in
the configuration file. Comment out that line in the config file to hit the production service that issues trusted certificates.


## Command Line Options

There are a number of command line options supported by the plugin. They all take the form:
--`plugin_name`:`entry_point`-`option`. Yes, it's a little clunky on the command line. So the
*host* option (specifies ASA box(es) that should do challenges and receive certificates) is specified as: `--certbot-asa:asa-host <somehost>`

```
  --certbot-asa:asa-host <host>
           Mandatory.
           Specify an ASA to be used for both domain validation (TLS challenges)
           and for installation of the resulting certificate. Can be specified
           multiple times.
  --certbot-asa:asa-chost <host>
           Optional.
           Specify an ASA to be used as a Challenge-only host. This box will not
           receive a live certificate, but will participate in domain validation
           challenges. Useful for a load-balanced ASA pool where you want ASA#1
           to have a certificate for "vpn" and "vpn1", ASA#2 to have a
           certificate for "vpn" and "vpn2", etc...
  --certbot-asa:asa-credfile <file>
           Optional.
           Specify the location of the ASA credentials file. Defaults to
           <config-dir>/asa_creds.txt
  --certbot-asa:asa-creddelim <string>
           Optional.
           ASA credentials file delimiter (default: ';')
           Useful if your username has ';' embedded in it.
  --certbot-asa:asa-ignore_cert
           Optional.
           Just don't use this. Seriously.
  --certbot-asa:asa-castore <path>
           Optional.
           Path to a bundle of PEM-formatted trusted certificates (one file) or
           a c_rehash'ed directory of those files. Pretty much a required option
           because the 'requests' module carries its own trust store, disregards
           the system provided CAs.
```

## Caveats

### What Gets Installed Will Get Removed

The plugin will install trustpoints, RSA keypairs and `ssl trust-point <something> domain <whatever>` configurations onto your ASA.
It will also remove them as they expire. Don't do something silly like use one of these keypairs for your SSH service or a handcrafted
trustpoint because they're subject to removal.

### TLSSNI01 May Be Deprecated Soon

There's a problem with the TLSSNI01 challenge. It's not one that will affect the
 security or quality of your certificates, nor put your machine at risk. Rather, 
the problem is that some other device (not your ASA) could be tricked into 
satisfying an unwanted challenge, which might lead to Let's Encrypt erroneously issuing
certificates for that device's domain. The only thing to worry about here is
whether Let's Encrypt sunsets TLSSNI01 for TLSSNI02 before I get around to
updating the plugin.
