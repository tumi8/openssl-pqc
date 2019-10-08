OQS-OpenSSL\_1\_0\_2-stable snapshot 2019-10
============================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSL aims to provide integration of post-quantum algorithms from liboqs into TLS 1.2 in OpenSSL 1.0.2.

This branch of our fork of OpenSSL can be used with the following versions of liboqs:

- **liboqs master branch** 0.2.0

Release notes
=============

This snapshot of the OQS fork of OpenSSL 1.0.2t (`OQS-OpenSSL_1_0_2-stable`) was released on October 8, 2019.  Its release page on Github is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_0_2-stable-snapshot-2019-10.

What's New
----------

This is the fourth snapshot release of OQS-OpenSSL\_1\_0\_2-stable.

This release syncs the fork with the upstream OpenSSL 1.0.2t release.

This release updates algorithms based on liboqs master 0.2.0, which has added and updated post-quantum KEMs based on NIST Round 2 submissions.

Future work
-----------

This is intended to be the last release of OQS-OpenSSL\_1\_0\_2-stable.  The OpenSSL project will stop supporting the OpenSSL 1.0.2 series as of January 1, 2020, so we will plan to discontinue releases of our fork of OpenSSL 1.0.2.  Projects relying on post-quantum key exchange in TLS should switch to the OQS-OpenSSL\_1\_1\_1-stable branch.
