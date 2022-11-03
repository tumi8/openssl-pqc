/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <oqs/oqs.h>

/*
 * This table MUST be kept in ascending order of the NID each method
 * represents (corresponding to the pkey_id field) as OBJ_bsearch
 * is used to search it.
 */
static const EVP_PKEY_ASN1_METHOD *standard_methods[] = {
#ifndef OPENSSL_NO_RSA
    &rsa_asn1_meths[0],
    &rsa_asn1_meths[1],
#endif
#ifndef OPENSSL_NO_DH
    &dh_asn1_meth,
#endif
#ifndef OPENSSL_NO_DSA
    &dsa_asn1_meths[0],
    &dsa_asn1_meths[1],
    &dsa_asn1_meths[2],
    &dsa_asn1_meths[3],
    &dsa_asn1_meths[4],
#endif
#ifndef OPENSSL_NO_EC
    &eckey_asn1_meth,
#endif
    &hmac_asn1_meth,
#ifndef OPENSSL_NO_CMAC
    &cmac_asn1_meth,
#endif
#ifndef OPENSSL_NO_RSA
    &rsa_pss_asn1_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ecx25519_asn1_meth,
    &ecx448_asn1_meth,
#endif
#ifndef OPENSSL_NO_POLY1305
    &poly1305_asn1_meth,
#endif
#ifndef OPENSSL_NO_SIPHASH
    &siphash_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ed25519_asn1_meth,
    &ed448_asn1_meth,
#endif
#ifndef OPENSSL_NO_SM2
    &sm2_asn1_meth,
#endif
///// OQS_TEMPLATE_FRAGMENT_SIG_ASN1_METHS_START
    &dilithium2_asn1_meth,
    &p256_dilithium2_asn1_meth,
    &rsa3072_dilithium2_asn1_meth,
    &sphincsharaka128frobust_asn1_meth,
    &p256_sphincsharaka128frobust_asn1_meth,
    &rsa3072_sphincsharaka128frobust_asn1_meth,
    &sphincsharaka128fsimple_asn1_meth,
    &p256_sphincsharaka128fsimple_asn1_meth,
    &rsa3072_sphincsharaka128fsimple_asn1_meth,
    &sphincsharaka128srobust_asn1_meth,
    &p256_sphincsharaka128srobust_asn1_meth,
    &rsa3072_sphincsharaka128srobust_asn1_meth,
    &sphincsharaka128ssimple_asn1_meth,
    &p256_sphincsharaka128ssimple_asn1_meth,
    &rsa3072_sphincsharaka128ssimple_asn1_meth,
    &sphincsharaka192frobust_asn1_meth,
    &p384_sphincsharaka192frobust_asn1_meth,
    &sphincsharaka192fsimple_asn1_meth,
    &p384_sphincsharaka192fsimple_asn1_meth,
    &sphincsharaka192srobust_asn1_meth,
    &p384_sphincsharaka192srobust_asn1_meth,
    &sphincsharaka192ssimple_asn1_meth,
    &p384_sphincsharaka192ssimple_asn1_meth,
    &sphincsharaka256frobust_asn1_meth,
    &p521_sphincsharaka256frobust_asn1_meth,
    &sphincsharaka256fsimple_asn1_meth,
    &p521_sphincsharaka256fsimple_asn1_meth,
    &sphincsharaka256srobust_asn1_meth,
    &p521_sphincsharaka256srobust_asn1_meth,
    &sphincsharaka256ssimple_asn1_meth,
    &p521_sphincsharaka256ssimple_asn1_meth,
    &sphincssha256128frobust_asn1_meth,
    &p256_sphincssha256128frobust_asn1_meth,
    &rsa3072_sphincssha256128frobust_asn1_meth,
    &sphincssha256128fsimple_asn1_meth,
    &p256_sphincssha256128fsimple_asn1_meth,
    &rsa3072_sphincssha256128fsimple_asn1_meth,
    &sphincssha256128srobust_asn1_meth,
    &p256_sphincssha256128srobust_asn1_meth,
    &rsa3072_sphincssha256128srobust_asn1_meth,
    &sphincssha256128ssimple_asn1_meth,
    &p256_sphincssha256128ssimple_asn1_meth,
    &rsa3072_sphincssha256128ssimple_asn1_meth,
    &sphincssha256192frobust_asn1_meth,
    &p384_sphincssha256192frobust_asn1_meth,
    &sphincssha256192fsimple_asn1_meth,
    &p384_sphincssha256192fsimple_asn1_meth,
    &sphincssha256192srobust_asn1_meth,
    &p384_sphincssha256192srobust_asn1_meth,
    &sphincssha256192ssimple_asn1_meth,
    &p384_sphincssha256192ssimple_asn1_meth,
    &sphincssha256256frobust_asn1_meth,
    &p521_sphincssha256256frobust_asn1_meth,
    &sphincssha256256fsimple_asn1_meth,
    &p521_sphincssha256256fsimple_asn1_meth,
    &sphincssha256256srobust_asn1_meth,
    &p521_sphincssha256256srobust_asn1_meth,
    &sphincssha256256ssimple_asn1_meth,
    &p521_sphincssha256256ssimple_asn1_meth,
    &sphincsshake256128frobust_asn1_meth,
    &p256_sphincsshake256128frobust_asn1_meth,
    &rsa3072_sphincsshake256128frobust_asn1_meth,
    &sphincsshake256128fsimple_asn1_meth,
    &p256_sphincsshake256128fsimple_asn1_meth,
    &rsa3072_sphincsshake256128fsimple_asn1_meth,
    &sphincsshake256128srobust_asn1_meth,
    &p256_sphincsshake256128srobust_asn1_meth,
    &rsa3072_sphincsshake256128srobust_asn1_meth,
    &sphincsshake256128ssimple_asn1_meth,
    &p256_sphincsshake256128ssimple_asn1_meth,
    &rsa3072_sphincsshake256128ssimple_asn1_meth,
    &sphincsshake256192frobust_asn1_meth,
    &p384_sphincsshake256192frobust_asn1_meth,
    &sphincsshake256192fsimple_asn1_meth,
    &p384_sphincsshake256192fsimple_asn1_meth,
    &sphincsshake256192srobust_asn1_meth,
    &p384_sphincsshake256192srobust_asn1_meth,
    &sphincsshake256192ssimple_asn1_meth,
    &p384_sphincsshake256192ssimple_asn1_meth,
    &sphincsshake256256frobust_asn1_meth,
    &p521_sphincsshake256256frobust_asn1_meth,
    &sphincsshake256256fsimple_asn1_meth,
    &p521_sphincsshake256256fsimple_asn1_meth,
    &sphincsshake256256srobust_asn1_meth,
    &p521_sphincsshake256256srobust_asn1_meth,
    &sphincsshake256256ssimple_asn1_meth,
    &p521_sphincsshake256256ssimple_asn1_meth,
///// OQS_TEMPLATE_FRAGMENT_SIG_ASN1_METHS_END
};
