/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdio.h"
#include "string.h"


#include "tss2_tpm2_types.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>



#if !defined(OPENSSL_NO_SM3) && OPENSSL_VERSION_NUMBER > 0x1010100FL
#   define ALG_SM3_256  1
#   include <openssl/sm3.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10200000L
    // Check the rsa_st and RSA_PRIME_INFO definitions in crypto/rsa/rsa_lcl.h and
    // either update the version check or provide the new definition for this version.
#   error Untested OpenSSL version
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    // from crypto/rsa/rsa_lcl.h
    typedef struct rsa_prime_info_st {
        BIGNUM* r;
        BIGNUM* d;
        BIGNUM* t;
        BIGNUM* pp;
        BN_MONT_CTX* m;
    } RSA_PRIME_INFO;

    DEFINE_STACK_OF(RSA_PRIME_INFO)

        struct rsa_st {
        int pad;
        int32_t version;
        const RSA_METHOD* meth;
        ENGINE* engine;
        BIGNUM* n;
        BIGNUM* e;
        BIGNUM* d;
        BIGNUM* p;
        BIGNUM* q;
        BIGNUM* dmp1;
        BIGNUM* dmq1;
        BIGNUM* iqmp;
        STACK_OF(RSA_PRIME_INFO)* prime_infos;
        RSA_PSS_PARAMS* pss;
        CRYPTO_EX_DATA ex_data;
        int references;
        int flags;
        /* Used to cache montgomery values */
        BN_MONT_CTX* _method_mod_n;
        BN_MONT_CTX* _method_mod_p;
        BN_MONT_CTX* _method_mod_q;
        char* bignum_data;
        BN_BLINDING* blinding;
        BN_BLINDING* mt_blinding;
        CRYPTO_RWLOCK* lock;
    };

#endif // OPENSSL_VERSION_NUMBER


#include "tpm2-tss-engine.h"

static struct opt {
    const char* filename;
    TPMI_ALG_PUBLIC alg;
    TPMI_ECC_CURVE curve;
    int exponent;
    char* importpub;
    char* importtpm;
    char* ownerpw;
    const char* password;
    TPM2_HANDLE parent;
    const char* parentpw;
    int keysize;
    int verbose;
    char* tcti_conf;
    BYTE* privateBuffer;
    UINT32 privateBufferSize;
    BYTE* publicBuffer;
    UINT32 publicBufferSize;
    BYTE* rsaBuffer;
    UINT16 rsaBufferSize;
} opt;

#ifdef ERR
#undef ERR
#endif

int verbose = 1;

#define VERB(...) if (verbose != 0) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)


static TPM2_DATA* genkey_rsa();
static int tpm2tss_rsa_genkey(RSA* rsa, int bits, BIGNUM* e, const char* password, TPM2_HANDLE parentHandle, UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize);
static int populate_rsa(RSA* rsa, UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize);
int tpm2tss_tpm2data_write(const TPM2_DATA* tpm2Data, BYTE* privateBuffer, UINT32 privateBufferSize,
    BYTE* publicBuffer, UINT32 publicBufferSize, const char* filename);


void tpm2tss_genkey_rsa(UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize, BYTE* privateBuffer, UINT32 privateBufferSize,
    BYTE* publicBuffer, UINT32 publicBufferSize, const char* parentPassword, const char* keyPassword, const char* filePath)
{
    TPM2_DATA* tpm2Data = NULL;

    /* set the default values */
    opt.filename = NULL;
    opt.alg = TPM2_ALG_RSA;
    opt.curve = TPM2_ECC_NIST_P256;
    opt.exponent = 65537;
    opt.importpub = NULL;
    opt.importtpm = NULL;
    opt.ownerpw = NULL;
    opt.password = NULL;
    opt.parent = 0;
    opt.parentpw = NULL;
    opt.keysize = 2048;
    opt.verbose = 0;
    opt.tcti_conf = NULL;

    opt.filename = filePath;
    opt.parent = 0x81000001;
    opt.exponent = inExponent;
    opt.password = keyPassword;
    opt.parentpw = parentPassword;

    opt.rsaBuffer = rsaBuffer;
    opt.rsaBufferSize = rsaBufferSize;
    opt.privateBuffer = privateBuffer;
    opt.privateBufferSize = privateBufferSize;
    opt.publicBuffer = publicBuffer;
    opt.publicBufferSize = publicBufferSize;

    tpm2Data = genkey_rsa();
    if (tpm2Data == NULL) {
        ERR("Key could not be generated.\n");
        //return 1;
        return;
    }

    /* Write the key to disk */
    VERB("Writing key to disk\n");

    if (!tpm2tss_tpm2data_write(tpm2Data, privateBuffer, privateBufferSize, publicBuffer, publicBufferSize, opt.filename)) {
        ERR("Error writing file\n");
        OPENSSL_free(tpm2Data);
        //return 1;
        return;
    }

    OPENSSL_free(tpm2Data);

    VERB("*** SUCCESS ***\n");
}

static TPM2_DATA*
genkey_rsa()
{
    VERB("Generating RSA key using TPM\n");

    RSA* rsa = NULL;
    BIGNUM* e = BN_new();
    if (!e) {
        ERR("out of memory\n");
        return NULL;
    }
    BN_set_word(e, opt.exponent);

    rsa = RSA_new();
    if (!rsa) {
        ERR("out of memory\n");
        BN_free(e);
        return NULL;
    }
    if (!tpm2tss_rsa_genkey(rsa, opt.keysize, e, opt.password, opt.parent, opt.exponent, opt.rsaBuffer, opt.rsaBufferSize)) {
        BN_free(e);
        RSA_free(rsa);
        ERR("Error: Generating key failed\n");
        return NULL;
    }

    VERB("Key generated\n");

    TPM2_DATA* tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR("out of memory\n");
        BN_free(e);
        RSA_free(rsa);
        return NULL;
    }
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    BN_free(e);
    RSA_free(rsa);

    return tpm2Data;
}


static int
tpm2tss_rsa_genkey(RSA* rsa, int bits, BIGNUM* e, const char* password,
    TPM2_HANDLE parentHandle, UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize)
{
    //DBG("Generating RSA key for %i bits keysize.\n", bits);

    TSS2_RC r = TSS2_RC_SUCCESS;
    //ESYS_CONTEXT* esys_ctx = NULL;
    //ESYS_TR parent = ESYS_TR_NONE;
    //TPM2B_PUBLIC* keyPublic = NULL;
    //TPM2B_PRIVATE* keyPrivate = NULL;
    TPM2_DATA* tpm2Data = NULL;
    //TPM2B_PUBLIC inPublic = keyTemplate;
    //TPM2B_SENSITIVE_CREATE inSensitive = {
    //    .sensitive = {
    //        .userAuth = {
    //             .size = 0,
    //         },
    //        .data = {
    //             .size = 0,
    //         }
    //    }
    //};

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        //ERR(tpm2tss_rsa_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    //inPublic.publicArea.parameters.rsaDetail.keyBits = bits;
    //if (e)
    //    inPublic.publicArea.parameters.rsaDetail.exponent = BN_get_word(e);

    if (password) {
        //DBG("Setting a password for the created key.\n");
        if (strlen(password) > sizeof(tpm2Data->userauth.buffer) - 1) {
            goto error;
        }
        tpm2Data->userauth.size = (UINT16)strlen(password);
        memcpy(&tpm2Data->userauth.buffer[0], password,
            tpm2Data->userauth.size);

        //inSensitive.sensitive.userAuth.size = strlen(password);
        //memcpy(&inSensitive.sensitive.userAuth.buffer[0], password,
        //    strlen(password));
    }
    else
        tpm2Data->emptyAuth = 1;

    //r = init_tpm_parent(&esys_ctx, parentHandle, &parent);
    //ERRchktss(tpm2tss_rsa_genkey, r, goto error);

    tpm2Data->parent = parentHandle;

    //DBG("Generating the RSA key inside the TPM.\n");

    //r = Esys_Create(esys_ctx, parent,
    //    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
    //    &inSensitive, &inPublic, &allOutsideInfo, &allCreationPCR,
    //    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    //ERRchktss(tpm2tss_rsa_genkey, r, goto error);

    //DBG("Generated the RSA key inside the TPM.\n");

    //tpm2Data->pub = *keyPublic;
    //tpm2Data->priv = *keyPrivate;

    if (!RSA_set_app_data(rsa, tpm2Data)) {
        //ERR(tpm2tss_rsa_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    if (!populate_rsa(rsa, inExponent, rsaBuffer, rsaBufferSize)) {
        goto error;
    }

    goto end;
error:
    r = -1;
    if (rsa)
        RSA_set_app_data(rsa, NULL);
    if (tpm2Data)
        OPENSSL_free(tpm2Data);

end:
    //Esys_Free(keyPrivate);
    //Esys_Free(keyPublic);

    //if (parent != ESYS_TR_NONE && !parentHandle)
    //    Esys_FlushContext(esys_ctx, parent);

    //esys_ctx_free(&esys_ctx);

    return (r == TSS2_RC_SUCCESS);
}

static int
populate_rsa(RSA* rsa, UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize)
{
    TPM2_DATA* tpm2Data = RSA_get_app_data(rsa);
    UINT32 exponent;
    exponent = inExponent;
    if (!exponent)
        exponent = 0x10001;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    /* Setting the public portion of the key */
    rsa->n = BN_bin2bn(rsaBuffer,
        rsaBufferSize, rsa->n);
    if (rsa->n == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    if (rsa->e == NULL)
        rsa->e = BN_new();
    if (rsa->e == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->e, exponent);

    /* Setting private portions to 0 values so the public key can be extracted
       from the keyfile if this is desired. */
    if (rsa->d == NULL)
        rsa->d = BN_new();
    if (rsa->d == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->d, 0);
    if (rsa->p == NULL)
        rsa->p = BN_new();
    if (rsa->p == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->p, 0);
    if (rsa->q == NULL)
        rsa->q = BN_new();
    if (rsa->q == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->q, 0);
    if (rsa->dmp1 == NULL)
        rsa->dmp1 = BN_new();
    if (rsa->dmp1 == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->dmp1, 0);
    if (rsa->dmq1 == NULL)
        rsa->dmq1 = BN_new();
    if (rsa->dmq1 == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->dmq1, 0);
    if (rsa->iqmp == NULL)
        rsa->iqmp = BN_new();
    if (rsa->iqmp == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->iqmp, 0);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    BIGNUM* n = BN_bin2bn(rsaBuffer,
        rsaBufferSize, NULL);
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* dmp1 = BN_new();
    BIGNUM* dmq1 = BN_new();
    BIGNUM* iqmp = BN_new();

    if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
        if (n)
            BN_free(n);
        if (e)
            BN_free(e);
        if (d)
            BN_free(d);
        if (p)
            BN_free(p);
        if (q)
            BN_free(q);
        if (dmp1)
            BN_free(dmp1);
        if (dmq1)
            BN_free(dmq1);
        if (iqmp)
            BN_free(iqmp);

        //ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    BN_set_word(e, exponent);
    BN_set_word(d, 0);
    BN_set_word(p, 0);
    BN_set_word(q, 0);
    BN_set_word(dmp1, 0);
    BN_set_word(dmq1, 0);
    BN_set_word(iqmp, 0);

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    return 1;
error:
    return 0;
}

#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

typedef struct {
    ASN1_OBJECT* type;
    ASN1_BOOLEAN emptyAuth;
    ASN1_INTEGER* parent;
    ASN1_OCTET_STRING* pubkey;
    ASN1_OCTET_STRING* privkey;
} TSSPRIVKEY;

DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY);

DECLARE_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY);
DECLARE_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY);

#define OID_loadableKey "2.23.133.10.1.3"

#ifdef ERR
#undef ERR
#endif
#define ERR(f,r)    (void)0

ASN1_SEQUENCE(TSSPRIVKEY) = {
    ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
    ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
    ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
    ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY);
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);

int
tpm2tss_tpm2data_write(const TPM2_DATA* tpm2Data, BYTE* privateBuffer, UINT32 privateBufferSize,
    BYTE* publicBuffer, UINT32 publicBufferSize, const char* filename)
{
    //TSS2_RC r;
    BIO* bio = NULL;
    TSSPRIVKEY* tpk = NULL;
    BIGNUM* bn_parent = NULL;

    //uint8_t privbuf[sizeof(tpm2Data->priv)];
    //uint8_t pubbuf[sizeof(tpm2Data->pub)];
    //size_t privbuf_len = 0, pubbuf_len = 0;

    if ((bio = BIO_new_file(filename, "w")) == NULL) {
        ERR(tpm2tss_tpm2data_write, TPM2TSS_R_FILE_WRITE);
        goto error;
    }

    tpk = TSSPRIVKEY_new();
    if (!tpk) {
        ERR(tpm2tss_tpm2data_write, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    //r = Tss2_MU_TPM2B_PRIVATE_Marshal(&tpm2Data->priv, &privbuf[0],
    //    sizeof(privbuf), &privbuf_len);
    //if (r) {
    //    ERR(tpm2tss_tpm2data_write, TPM2TSS_R_DATA_CORRUPTED);
    //    goto error;
    //}

    //r = Tss2_MU_TPM2B_PUBLIC_Marshal(&tpm2Data->pub, &pubbuf[0],
    //    sizeof(pubbuf), &pubbuf_len);
    //if (r) {
    //    ERR(tpm2tss_tpm2data_write, TPM2TSS_R_DATA_CORRUPTED);
    //    goto error;
    //}
    tpk->type = OBJ_txt2obj(OID_loadableKey, 1);
    tpk->parent = ASN1_INTEGER_new();
    tpk->privkey = ASN1_OCTET_STRING_new();
    tpk->pubkey = ASN1_OCTET_STRING_new();
    if (!tpk->type || !tpk->privkey || !tpk->pubkey || !tpk->parent) {
        ERR(tpm2tss_tpm2data_write, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    tpk->emptyAuth = tpm2Data->emptyAuth ? 0xFF : 0;
    bn_parent = BN_new();
    if (!bn_parent) {
        goto error;
    }
    if (tpm2Data->parent != 0) {
        BN_set_word(bn_parent, tpm2Data->parent);
    }
    else {
        BN_set_word(bn_parent, TPM2_RH_OWNER);
    }
    BN_to_ASN1_INTEGER(bn_parent, tpk->parent);
    //ASN1_STRING_set(tpk->privkey, &privbuf[0], privbuf_len);
    //ASN1_STRING_set(tpk->pubkey, &pubbuf[0], pubbuf_len);
    ASN1_STRING_set(tpk->privkey, privateBuffer, privateBufferSize);
    ASN1_STRING_set(tpk->pubkey, publicBuffer, publicBufferSize);

    PEM_write_bio_TSSPRIVKEY(bio, tpk);
    TSSPRIVKEY_free(tpk);
    BIO_free(bio);

    return 1;
error:
    if (bio)
        BIO_free(bio);
    if (tpk)
        TSSPRIVKEY_free(tpk);
    return 0;
}