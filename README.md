OQS-OpenSSL\_1\_0\_2-stable
==========================

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/README).)

This branch (OQS-OpenSSL\_1\_0\_2-stable) is a fork of OpenSSL 1.0.2 that adds the following:

- post-quantum key exchange in TLS 1.2
- hybrid (post-quantum + elliptic curve) key exchange in TLS 1.2
- post-quantum key exchange primitives from liboqs in OpenSSL's `speed` command

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms. OpenSSL can use either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs; the former is recommended for normal uses of OpenSSL as included mechanisms follow a stricter set of requirements, the latter contains more algorithms and is better suited for experimentation.

**OQS-OpenSSL\_1\_0\_2-stable** is an integration of liboqs into (a fork of) OpenSSL 1.0.2.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in the TLS 1.2 protocol.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents of branch OQS-OpenSSL\_1\_0\_2-stable
----------------------------------------------

This branch ([OQS-OpenSSL\_1\_0\_2-stable branch](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_0_2-stable)) integrates post-quantum key exchange from liboqs in TLS 1.2 in OpenSSL v1.0.2.  

(For TLS 1.3, see the [OQS-OpenSSL\_1\_1\_1-stable](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable) branch.)

### Key exchange mechanisms

The following key exchange / key encapsulation mechanisms from liboqs are supported (assuming they have been enabled in liboqs):

- `DEFAULT`: This special mechanism uses the liboqs's default configured scheme.  This can be changed by editing `src/kem/kem.c` (for liboqs master branch) or `Makefile` (for liboqs nist-branch).
- `DEFAULT-ECDHE`: liboqs's default configured scheme, in hybrid mode with elliptic curve Diffie–Hellman.

For each post-quantum KEM `X` listed above, the following TLS 1.2 ciphersuites are available:

- `OQSKEM-X-RSA-AES128-GCM-SHA256`
- `OQSKEM-X-ECDSA-AES128-GCM-SHA256`
- `OQSKEM-X-RSA-AES256-GCM-SHA384`
- `OQSKEM-X-ECDSA-AES256-GCM-SHA384`

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

Lifecycle for OQS-OpenSSL\_1\_0\_2-stable
-----------------------------------------

**Release cycle:** We aim to make releases of OQS-OpenSSL\_1\_0\_2-stable on a bi-monthly basis, either when there has been a new release of OpenSSL 1.0.2 or when we have made changes to our fork.

See the README.md files of [liboqs master branch](https://github.com/open-quantum-safe/liboqs/blob/master/README.md) and [liboqs nist-branch](https://github.com/open-quantum-safe/liboqs/blob/nist-branch/README.md) for information about the algorithm lifecycle within the corresponding libraries.

**TLS compatibility:** The ciphersuite numbers and message formats used for post-quantum and hybrid key exchange are experimental, and may change between releases of OQS-OpenSSL\_1\_0\_2-stable.

Building on Linux and macOS
---------------------------

Builds have been tested manually on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), and Ubuntu 18.04.1 (gcc-7).

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc

For **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake libtool openssl wget

### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

    git clone --branch OQS-OpenSSL_1_0_2-stable https://github.com/open-quantum-safe/openssl.git

### Step 2: Build liboqs

You can use the either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs with the OQS-OpenSSL\_1\_0\_2-stable branch. Each branch support a different set of KEX/KEM mechanisnms (see above).

The following instructions will download and build liboqs, then install it into a subdirectory inside the OpenSSL folder.

For the **master branch**:

    git clone --branch master https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    autoreconf -i
    ./configure --prefix=<path-to-openssl-dir>/oqs --enable-shared=no --enable-openssl --with-openssl-dir=<path-to-system-openssl-dir>
    make -j
    make install

On **Ubuntu**, `<path-to-system-openssl-dir>` is probably `/usr`.  On **macOS** with brew, `<path-to-system-openssl-dir>` is probably `/usr/local/opt/openssl`.

For the **nist branch**:

    git clone --branch nist-branch https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    make -j
    make install-noshared PREFIX=<path-to-openssl-dir>/oqs

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL 1.0.2.

For **Ubuntu**:

    cd <path-to-openssl-dir>
    ./Configure no-shared linux-x86_64 -lm
    make -j
    
For **macOS**:

    cd <path-to-openssl-dir>
    ./Configure no-shared darwin64-x86_64-cc
    make -j
    
The OQS fork of OpenSSL can also be built with shared libraries, but we have used `no-shared` in the instructions above to avoid having to get the shared libraries in the right place for the runtime linker.

Building on Windows
-------------------

Builds have been tested on Windows 10 (VS2017 build tools). Make sure you can build the unmodified version of OpenSSL by following the instructions in [INSTALL.W64](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/INSTALL.W64).

### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

    git clone --branch OQS-OpenSSL_1_0_2-stable https://github.com/open-quantum-safe/openssl.git

### Step 2: Build liboqs

Next, you must download and build liboqs using the master branch of liboqs (the nist branch is not currently supported on Windows).  The following instructions will download and build that branch of liboqs, then copy the required files it into a subdirectory inside the OpenSSL folder.  You may need to install dependencies before building liboqs; see the [liboqs master branch README.md](https://github.com/open-quantum-safe/liboqs/blob/master/README.md).

    git clone --branch master https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    msbuild VisualStudio\liboqs.sln
    mkdir ..\openssl\oqs
    mkdir ..\openssl\oqs\lib
    mkdir ..\openssl\oqs\include
    xcopy VisualStudio\x64\Release\oqs.lib ..\openssl\oqs\lib\
    xcopy /S VisualStudio\include ..\openssl\oqs\include\

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL, for example

    cd ..\openssl
    perl Configure VC-WIN64A
    ms\do_win64a
    nmake -f ms\nt.mak

Running
-------

See the [liboqs documentation](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### openssl speed

OpenSSL's `speed` command performs basic benchmarking of cryptographic primitives.  You can see results for primitives from liboqs by typing

	apps/openssl speed oqskem

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To run a server, we first need to generate a self-signed X.509 certificate.  Run the following command:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout rsa.key -out rsa.crt -nodes -subj "/CN=oqstest" -days 365 -config apps/openssl.cnf

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cert rsa.crt -key rsa.key -www -tls1_2 -cipher OQSKEM-DEFAULT:OQSKEM-DEFAULT-ECDHE

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites, for example:

	apps/openssl s_client -cipher OQSKEM-DEFAULT
	apps/openssl s_client -cipher OQSKEM-DEFAULT-ECDHE

License
-------

All modifications in the open-quantum-safe/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/LICENSE).  

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

### Contributors

Contributors to open-quantum-safe/openssl branch OQS-OpenSSL\_1\_0\_2-stable include:

- Kevin Kane (Microsoft)
- Tancrède Lepoint (SRI)
- Shravan Mishra (University of Waterloo)
- Christian Paquin (Microsoft Research)

See the liboqs documentation for a list of contributors to liboqs.

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.  

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, and Microsoft Research.  

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.
