open-quantum-safe/openssl - 1.0.2-new-api
=========================================

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/OpenSSL_1_0_2-stable/README).)

This repository contains a fork of OpenSSL that adds quantum-safe cryptographic algorithms and ciphersuites.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  liboqs initially focuses on key exchange algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Limitations and security
------------------------

liboqs is designed for prototyping and evaluating quantum-resistant cryptography.  Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.  

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms.  liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.  

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project.  We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/ds-nist-branch/LICENSE.txt) for the full disclaimer.

In addition, implementations that we have included on nist-branch of liboqs have received no quality control or vetting by OQS.  **THE NIST-BRANCH OF LIBOQS SHOULD BE USED EXCLUSIVELY FOR EXPERIMENTATION AND PROTOTYPING, AND SHOULD NEVER BE USED IN ANY PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.**

The integration of liboqs into our fork of OpenSSL is currently at an experimental stage, and has not received significant review.  At this stage, we do not recommend relying on it in any production environment or to protect any sensitive data.

The OQS fork of OpenSSL is not endorsed by with the OpenSSL project.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.  Most basic post-quantum key exchange mechanisms do not achieve active security, and would need to have an IND-CPA to IND-CCA KEM transform applied or be protected from active attacks using a signature scheme.  The `DEFAULT` KEM built in liboqs may not necessarily provide active security, in which case existing proofs of security of TLS against active attackers do not apply.

Contents
--------

open-quantum-safe/openssl currently contains:

- Integration of post-quantum key exchange primitives from liboqs into OpenSSL's `speed` command
- Ciphersuites using post-quantum key exchange based on primitives from liboqs, including hybrid ciphersuites which also use ECDHE key exchange

Our modifications are currently **only** for OpenSSL v1.0.2 (and correspondingly TLS 1.2).

### liboqs version

An earlier version of liboqs exposed a key exchange (KEX) API, while a newer version exposes a key encapsulation mechanism (KEM) API.  This branch of our OpenSSL fork works with the KEM version of liboqs.

Currently, the KEM API of liboqs is only available on liboqs' [nist-branch](https://github.com/open-quantum-safe/liboqs/tree/nist-branch).  Thus, this branch of liboqs' OpenSSL fork must be compiled against liboqs' nist-branch.

### Ciphersuites

For each post-quantum KEM exposed `X`, there are the following ciphersuites:

- `OQSKEM-X-RSA-AES128-GCM-SHA256`
- `OQSKEM-X-ECDSA-AES128-GCM-SHA256`
- `OQSKEM-X-RSA-AES256-GCM-SHA384`
- `OQSKEM-X-ECDSA-AES256-GCM-SHA384`
- `OQSKEM-X-ECDHE-RSA-AES128-GCM-SHA256`
- `OQSKEM-X-ECDHE-ECDSA-AES128-GCM-SHA256`
- `OQSKEM-X-ECDHE-RSA-AES256-GCM-SHA384`
- `OQSKEM-X-ECDHE-ECDSA-AES256-GCM-SHA384`

Currently, only one KEM from liboqs is exposed:

- `X` = `DEFAULT`: this uses whichever key exchange primitive is configured as the default key exchange primitive in liboqs.

Note that when liboqs' master branch is ported to the new liboqs API, we intend that all KEMs present in liboqs master branch will be exposed in our OpenSSL fork.  However, we intend that any algorithms in liboqs nist-branch that are not present in liboqs master branch will only be accessible via recompiling liboqs with that algorithm set to `DEFAULT`.

Building on Linux and macOS
---------------------------

Builds have been tested on macOS 10.13.3 (clang), Ubuntu 14.04.5 (gcc-7).

### Step 1: Build liboqs

First, you must download and build liboqs.  You must use a version of liboqs that uses the new KEM API.  Currently, the only version that does so is [nist-branch](https://github.com/open-quantum-safe/liboqs/tree/ds-nist-branch).  

Follow the instructions there to download and build that branch of liboqs.

### Step 2: Download fork of OpenSSL

Clone or download the source from Github:

	git clone --branch OpenSSL_1_0_2-stable-new-api https://github.com/open-quantum-safe/openssl.git
	cd openssl

### Step 3: Install liboqs into OpenSSL director

Go back to the directory where you built liboqs.  

	make install PREFIX=<path-to-openssl-dir>/oqs

This will create a directory `oqs` in your newly download OpenSSL directory, with subdirectories `include` and `lib` containing the headers and library files of liboqs.

### Step 4: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL.

To configure OpenSSL, on Linux type:

	./config

and on macOS type:

	./Configure darwin64-x86_64-cc

Then type:

	make depend
	make

Running
-------

See the [liboqs documentation](https://github.com/open-quantum-safe/liboqs/blob/ds-nist-branch/README.md) for information on test programs in liboqs.

### openssl speed

OpenSSL's `speed` command performs basic benchmarking of cryptographic primitives.  You can see results for primitives from liboqs by typing

	apps/openssl speed oqskem

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To see the list of supported ciphersuites from OQS, type:

	apps/openssl ciphers OQSKEM-DEFAULT:OQSKEM-DEFAULT-ECDHE

To run a server, we first need to generate a self-signed X.509 certificate.  Run the following command:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout server.key -nodes -out server.cer -sha256 -days 365 -config apps/openssl.cnf

Hit enter in response to all the prompts to accept the defaults.  

When done, type to combine the key and certificate (as required by `s_server`):

	cat server.key server.cer > server.pem

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cipher OQSKEM-DEFAULT:OQSKEM-DEFAULT-ECDHE

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites, for example:

	apps/openssl s_client -cipher OQSKEM-DEFAULT
	apps/openssl s_client -cipher OQSKEM-DEFAULT-ECDHE

License
-------

All modifications in the open-quantum-safe/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OpenSSL_1_0_2-stable/LICENSE).  

Team
----

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Contributors

Contributors to the liboqs fork of OpenSSL include:

- Kevin Kane (Microsoft)
- Tancrède Lepoint (SRI)
- Shravan Mishra (University of Waterloo)
- Christian Paquin (Microsoft Research)

See the liboqs documentation for a list of contributors to liboqs.

### Support

Development of Open Quantum Safe has been supported in part by the Tutte Institute for Mathematics and Computing.  Research projects which developed specific components of Open Quantum Safe have been supported by various research grants; see the source papers for funding acknowledgements.

