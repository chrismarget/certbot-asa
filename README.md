# Cisco ASA plugin for Let's Encrypt client

This is a plugin for the Let's Encrypt client: [Certbot](https://github.com/certbot/certbot).

It answers TLSSNI01 challenges with Cisco ASA boxes and installs the resulting certificates using the [Cisco ASA REST API](http://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html).

Neither the plugin nor the Certbot client run *on* the ASA. Both run on a management station which speaks ACME to the Let's Encrypt service and HTTPS to the ASA boxes. The process looks something like this:

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

* One or more Cisco ASA boxes with [hardware and software revisions that support the REST API](http://www.cisco.com/c/en/us/td/docs/security/asa/compatibility/asamatrx.html#pgfId-131643).
* The REST API installed and configured ([bug](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv80223) and [bug](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw60598) relevant to ASAs configured with `aaa authorization command`) on the ASA(s).
* A Linux host on which to run the Let's Encrypt client (certbot).
* ASA credentials.
* HTTPS access to the ASA from the Linux host.
* Permission to manage the ASA from the Linux host: `http <address> <mask> <interface>` on the ASA(s).
* Accurate clocks on both the Linux host and the ASA(s).
* A *management name* by which the Linux host knows the ASAs. This must be different than the name end users use. Something like asa-mgmt.company.com is probably appropriate here. It does not need to use the *management interface* on the ASA. We just need a different name.
* A TLS certificate used for management access to the ASA(s). This certificate will be for the management name above. Options here include:
..* xyz
..* 123
