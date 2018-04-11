OQS-OpenSSL-1\_0\_2-stable snapshot 2018-04
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSL aims to provide integration of post-quantum algorithms from liboqs into OpenSSL 1.0.2.

Release notes
=============

This snapshot of the OQS fork of OpenSSL 1.0.2 (`OQS-OpenSSL-1_0_2-stable`) was released on April 10, 2018.  Its release page on Github is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL-1_0_2-stable-snapshot-2018-04.

What's New
----------

This is the first snapshot release of OQS-OpenSSL-1\_0\_2-stable.

This release uses the new key encapsulation mechanism (KEM) API in liboqs nist-branch, which will soon also be present on liboqs master branch.

### `openssl speed`

- The `openssl speed` command can do performance testing of all enabled key encapsulation mechanisms provided by liboqs.

### Key exchange in TLS 1.2

- `DEFAULT`: The "default" KEM from liboqs is available for use in post-quantum and hybrid ciphersuites in TLS 1.2.  See README.md for a list of ciphersuites.

Note that our integration strategy is that key encapsulation mechanisms from liboqs nist-branch will only be surfaced in OpenSSL via the "default" KEM (which can be changed at compile time in liboqs).  Key encapsulations from our updated liboqs master branch (coming in May 2018) will all be surfaced in OpenSSL via their own names.

Algorithm datasheets for all supported algorithms are available in the [liboqs documentation](https://github.com/open-quantum-safe/liboqs/tree/nist-branch/docs/algorithms).

Comparison to OQS' other OpenSSL branches
-----------------------------------------

Modifications to OpenSSL also exist on our fork's OpenSSL-1\_0\_2-stable branch.  This snapshot release of OQS-OpenSSL-1\_0\_2-stable ("OQS-102") contains the following differences compared to our OpenSSL-1\_0\_2-stable ("102") branch:

- "OQS-102" uses the new key encapsulation mechanism API available in the liboqs nist-branch, and which will be coming to liboqs master branch by May 2018.  "102" uses the key exchange API available in earlier liboqs development.
- "102" includes support for liboqs-based signature schemes.  "OQS-102" does not at present, since the current release of liboqs nist-branch does not contain signatures.  We aim to change this by June 2018.

Future work
-----------

Snapshot releases of OQS-OpenSSL-1\_0\_2-stable will be made bi-monthly.  These will include syncing the branch with upstream modifications made in the original OpenSSL repository, and syncing with new releases of liboqs.  snapshot releases in intermittent months may be made when merited.

By June 2018, we intend to have OQS-OpenSSL-1\_0\_2-stable building against both liboqs nist-branch and liboqs master branch, and including support for liboqs-based signature schemes.
