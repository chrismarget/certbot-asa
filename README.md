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
