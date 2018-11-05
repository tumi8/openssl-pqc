OQS-OpenSSL-1\_0\_2-stable snapshot 2018-11
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSL aims to provide integration of post-quantum algorithms from liboqs into TLS 1.2 in OpenSSL 1.0.2.

This branch of our fork of OpenSSL can be used with the following versions of liboqs:

- **liboqs master branch** 0.1.0
- **liboqs nist-branch** 2018-11 snapshot

Release notes
=============

**This is a release candidate for liboqs master, not a final release.**. 
This snapshot of the OQS fork of OpenSSL 1.0.2 (`OQS-OpenSSL-1_0_2-stable`) was released on TODO.  Its release page on Github is TODO.

What's New
----------

This is the third snapshot release of OQS-OpenSSL-1\_0\_2-stable.

It syncs the fork with the upstream OpenSSL 1.0.2p release.

There are no additional changes in this repository.  However, since the last snapshot release, OQS-OpenSSL-1\_0\_2-stable now builds against the liboqs master branch.

Future work
-----------

Snapshot releases of OQS-OpenSSL-1\_0\_2-stable will be made approximately bi-monthly.  These will include syncing the branch with upstream releases of OpenSSL, and changes required to sync with new releases of liboqs.
