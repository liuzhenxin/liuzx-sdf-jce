/* Some birds aren't meant to be caged, that's all. Their feathers are just too bright.*/
/*
 * (c)2013 SafeData Studio
 * --------------------------------------------------------------------------------------
 * NAME:         libsdf.h
 * DESCRIPTION:  GM/T 0018-2012
 * AUTHOR:       Robin
 * BUGS: *       -
 * HISTORY:      Created on Nov 6, 2012
 * HISTORY:
 */

#ifndef _LIB_SDF_H_
#define _LIB_SDF_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, libsdf, 1)

#if defined(_WINDOWS) || defined(__MINGW32__)
#define SDF_API __declspec(dllexport)
#else
#define SDF_API
#endif


typedef unsigned int SGD_RV;
typedef char SGD_CHAR;
typedef char SGD_INT8;
typedef short SGD_INT16;
typedef int SGD_INT32;
typedef long long SGD_INT64;
typedef unsigned char SGD_UCHAR;
typedef unsigned char SGD_UINT8;
typedef unsigned short SGD_UINT16;
typedef unsigned int SGD_UINT32;
typedef unsigned long long SGD_UINT64;
typedef void *SGD_OBJECT;
typedef char SGD_BOOL;
typedef void *SGD_HANDLE;

#ifndef SGD_NULL_PTR
#define SGD_NULL_PTR 0
#endif

typedef struct SysConf_st 
{
	unsigned int timeout;
	unsigned int worktype;
	unsigned int maxcipher;
	char ip[MAXCIPHER][16];
	unsigned int port[MAXCIPHER];
} SysConf;


typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;

/* RSA key define */

#define SGD_RSA_MAX_BITS 4096

#define LiteRSAref_MAX_BITS 2048
#define LiteRSAref_MAX_LEN ((LiteRSAref_MAX_BITS + 7) / 8)
#define LiteRSAref_MAX_PBITS ((LiteRSAref_MAX_BITS + 1) / 2)
#define LiteRSAref_MAX_PLEN ((LiteRSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKeyLite_st {
    unsigned int bits;
    unsigned char m[LiteRSAref_MAX_LEN];
    unsigned char e[LiteRSAref_MAX_LEN];
} RSArefPublicKeyLite;

typedef struct RSArefPrivateKeyLite_st {
    unsigned int bits;
    unsigned char m[LiteRSAref_MAX_LEN];
    unsigned char e[LiteRSAref_MAX_LEN];
    unsigned char d[LiteRSAref_MAX_LEN];
    unsigned char prime[2][LiteRSAref_MAX_PLEN];
    unsigned char pexp[2][LiteRSAref_MAX_PLEN];
    unsigned char coef[LiteRSAref_MAX_PLEN];
} RSArefPrivateKeyLite;

#define RSAref_MAX_BITS 4096
#define RSAref_MIN_BITS 1024
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

// Elliptic Curve
//
#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define ECCref_MIN_BITS 256
#define ECCref_MIN_LEN ((ECCref_MIN_BITS + 7) / 8)

#define SM2_KEY_BITS 256
#define SM2_KEY_BYTES ((SM2_KEY_BITS + 7) / 8)

typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];// x coordinate
    unsigned char y[ECCref_MAX_LEN];// y coordinate
} ECCrefPublicKey, ECCPUBLICKEYBLOB;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];// private key
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];//  point's x coordinate
    unsigned char y[ECCref_MAX_LEN];//  point's y coordinate
    unsigned char M[32];            // reserved for MAC data
    unsigned int L;
    unsigned char C[1];// encrypted data
} ECCCipher, ECCCIPHERBLOB;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];//r part of the signature
    unsigned char s[ECCref_MAX_LEN];//s part of the signature
} ECCSignature;

typedef struct SDF_ENVELOPEDKEYBLOB {
    unsigned long ulAsymmAlgID;
    unsigned long ulSymmAlgID;
    ECCCIPHERBLOB ECCCipherBlob;
    ECCPUBLICKEYBLOB PubKey;
    unsigned char cbEncryptedKey[64];
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*EDDSA *///20230608
#define ECCref_MAX_BITS_EDDSA 256
#define ECCref_MAX_LEN_EDDSA ((ECCref_MAX_BITS_EDDSA + 7) / 8)

typedef struct ECCrefPublicKey_st_EDDSA {
    unsigned int bits;
    unsigned char pub[ECCref_MAX_LEN_EDDSA];
} ECCrefPublicKey_EDDSA;

typedef struct ECCrefPrivateKey_st_EDDSA {
    unsigned int bits;
    unsigned char pri[ECCref_MAX_LEN_EDDSA];
} ECCrefPrivateKey_EDDSA;

typedef struct ECCSignature_st_EDDSA {
    unsigned char r[ECCref_MAX_LEN_EDDSA];
    unsigned char s[ECCref_MAX_LEN_EDDSA];
} ECCSignature_EDDSA;


/*ECDSA *///20230608
#define ECCref_MAX_BITS_ECDSA 521
#define ECCref_MAX_LEN_ECDSA ((ECCref_MAX_BITS_ECDSA + 7) / 8)

typedef struct ECCrefPublicKey_st_ECDSA {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN_ECDSA];
    unsigned char y[ECCref_MAX_LEN_ECDSA];
} ECCrefPublicKey_ECDSA;

typedef struct ECCrefPrivateKey_st_ECDSA {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN_ECDSA];
} ECCrefPrivateKey_ECDSA;

typedef struct ECCSignature_st_ECDSA {
    unsigned char r[ECCref_MAX_LEN_ECDSA];
    unsigned char s[ECCref_MAX_LEN_ECDSA];
} ECCSignature_ECDSA;

/*DSA *///20230608
#define DSAref_MAX_BITS 3072
#define DSAref_MAX_LEN (((DSAref_MAX_BITS + 7) / 8))

typedef struct DSArefPublicKey_st {
    unsigned int bits;
    unsigned char y[DSAref_MAX_LEN];
    unsigned char p[DSAref_MAX_LEN];
    unsigned char q[DSAref_MAX_LEN];
    unsigned char g[DSAref_MAX_LEN];
} DSArefPublicKey;

typedef struct DSArefPrivateKey_st {
    unsigned int bits;
    unsigned char x[DSAref_MAX_LEN];
    unsigned char p[DSAref_MAX_LEN];
    unsigned char q[DSAref_MAX_LEN];
    unsigned char g[DSAref_MAX_LEN];
} DSArefPrivateKey;

typedef struct DSASignature_st {
    unsigned char r[DSAref_MAX_LEN];
    unsigned char s[DSAref_MAX_LEN];
} DSASignature;

typedef struct RSArefPublicKeyOLD_st {
    unsigned int bits;
    unsigned char m[256];
    unsigned char e[256];
} RSArefPublicKey_OLD;

typedef struct RSArefPrivateKeyOLD_st {
    unsigned int bits;
    unsigned char m[256];
    unsigned char e[256];
    unsigned char d[256];
    unsigned char prime[2][128];
    unsigned char pexp[2][128];
    unsigned char coef[128];
} RSArefPrivateKey_OLD;
// sm9
#define SM9ref_MAX_BITS 256
#define SM9ref_MAX_LEN ((SM9ref_MAX_BITS + 7) / 8)

typedef struct SM9refMasterPrivateKey_st {
    unsigned int bits;
    unsigned char s[SM9ref_MAX_LEN];
} SM9MasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st {
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
} SM9SignMasterPublicKey;

typedef struct SM9refEncMasterPublicKey_st {
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9EncMasterPublicKey;

typedef struct SM9refUserSignPrivateKey_st {
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9UserSignPrivateKey;

typedef struct SM9refUserEncPrivateKey_st {
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
} SM9UserEncPrivateKey;

typedef struct SM9refCipher_st {
    unsigned int enType;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
    unsigned char h[SM9ref_MAX_LEN];
    unsigned int L;
    unsigned char C[1];
} SM9Cipher;

typedef struct SM9refSignature_st {
    unsigned char h[SM9ref_MAX_LEN];
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9refKeyPackage_st {
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9KeyPackage;

typedef struct SM9refPairEncEnvelopedKey_st {
    unsigned int version;
    unsigned int ulSymAlgID;
    unsigned int bits;
    unsigned char encryptedPriKey[SM9ref_MAX_LEN * 4];
    SM9EncMasterPublicKey encMastPubKey;
    unsigned int userIDLen;
    unsigned char userID[1024];
    unsigned int keyLen;
    SM9KeyPackage keyPackage;
} SM9PairEncEnvelopedKey;

typedef struct SM9refPairSignEnvelopedKey_st {
    unsigned int version;
    unsigned int ulSymAlgID;
    unsigned int bits;
    unsigned char encryptedPriKey[SM9ref_MAX_LEN * 4];
    SM9SignMasterPublicKey signMastPubKey;
    unsigned int userIDLen;
    unsigned char userID[1024];
    unsigned int keyLen;
    SM9KeyPackage keyPackage;
} SM9PairSignEnvelopedKey;


#define SGD_TRUE 1
#define SGD_FALSE 0

// algorithm tags
// -- GMT 00060-2012
//
// symmetric algorithms
//
#define SGD_MODE_ECB 0x00000001
#define SGD_MODE_CBC 0x00000002
#define SGD_MODE_CFB 0x00000004
#define SGD_MODE_OFB 0x00000008
#define SGD_MODE_MAC 0x00000010

#define SGD_SM1_BASE 0x00000100
#define SGD_SM1_ECB (SGD_SM1_BASE | SGD_MODE_ECB)
#define SGD_SM1_CBC (SGD_SM1_BASE | SGD_MODE_CBC)
#define SGD_SM1_CFB (SGD_SM1_BASE | SGD_MODE_CFB)
#define SGD_SM1_OFB (SGD_SM1_BASE | SGD_MODE_OFB)
#define SGD_SM1_MAC (SGD_SM1_BASE | SGD_MODE_MAC)
#define SGD_SM1_BLOCK_SIZE 16

#define SGD_SSF33 0x00000200
#define SGD_SSF33_ECB 0x00000201
#define SGD_SSF33_CBC 0x00000202
#define SGD_SSF33_CFB 0x00000204
#define SGD_SSF33_OFB 0x00000208
#define SGD_SSF33_MAC 0x00000210
#define SGD_SSF33_BLOCK_SIZE 16

#define SGD_SMS4_BASE 0x00000400
#define SGD_SMS4_ECB (SGD_SMS4_BASE | SGD_MODE_ECB)
#define SGD_SMS4_CBC (SGD_SMS4_BASE | SGD_MODE_CBC)
#define SGD_SMS4_CFB (SGD_SMS4_BASE | SGD_MODE_CFB)
#define SGD_SMS4_OFB (SGD_SMS4_BASE | SGD_MODE_OFB)
#define SGD_SMS4_MAC (SGD_SMS4_BASE | SGD_MODE_MAC)
#define SGD_SMS4_BLOCK_SIZE 16

#define SGD_SM6 0x00000600
#define SGD_SM6_ECB 0x00000601
#define SGD_SM6_CBC 0x00000602
#define SGD_SM6_CFB 0x00000604
#define SGD_SM6_OFB 0x00000608
#define SGD_SM6_MAC 0x00000610
#define SGD_SM6_CTR 0x00000620

#define SGD_SM7 0x00001000
#define SGD_SM7_ECB 0x00001001
#define SGD_SM7_CBC 0x00001002
#define SGD_SM7_CFB 0x00001004
#define SGD_SM7_OFB 0x00001008
#define SGD_SM7_MAC 0x00001010
#define SGD_SM7_CTR 0x00001020

#ifdef _JIT_VERSION
#define SGD_DES 0x00003000
#define SGD_DES_ECB 0x00003001
#define SGD_DES_CBC 0x00003002
#define SGD_DES_CFB 0x00003004
#define SGD_DES_OFB 0x00003008
#define SGD_DES_MAC 0x00003010

#define SGD_3DES 0x00001000
#define SGD_3DES_ECB 0x00001001
#define SGD_3DES_CBC 0x00001002
#define SGD_3DES_CFB 0x00001004
#define SGD_3DES_OFB 0x00001008
#define SGD_3DES_MAC 0x00001010

#define SGD_AES 0x00002000
#define SGD_AES_ECB 0x00002001
#define SGD_AES_CBC 0x00002002
#define SGD_AES_CFB 0x00002004
#define SGD_AES_OFB 0x00002008
#define SGD_AES_MAC 0x00002010
#define SGD_AES_CTR 0x00002020
#else
#define SGD_DES 0x00002000
#define SGD_DES_ECB 0x00002001
#define SGD_DES_CBC 0x00002002
#define SGD_DES_CFB 0x00002004
#define SGD_DES_OFB 0x00002008
#define SGD_DES_MAC 0x00002010

#define SGD_3DES 0x00004000
#define SGD_3DES_ECB 0x00004001
#define SGD_3DES_CBC 0x00004002
#define SGD_3DES_CFB 0x00004004
#define SGD_3DES_OFB 0x00004008
#define SGD_3DES_MAC 0x00004010

#define SGD_AES 0x00008000
#define SGD_AES_ECB 0x00008001
#define SGD_AES_CBC 0x00008002
#define SGD_AES_CFB 0x00008004
#define SGD_AES_OFB 0x00008008
#define SGD_AES_MAC 0x00008010
#define SGD_AES_CTR 0x00008020
#define SGD_AES_BLOCK_SIZE 16
#endif

#define SGD_ZUC_EEA3 0x00000801
#define SGD_ZUC_EIA3 0x00000802

// asymmetric algorithms
//
#define SGD_RSA 0x00010000
#define SGD_RSA_SIGN 0x00010100// discarded in GM/T 0006-2012
#define SGD_RSA_ENC 0x00010200 // discarded in GM/T 0006-2012

#define SGD_SM2 0x00020100
#define SGD_SM2_1 0x00020200// SM2 signature algorithm
#define SGD_SM2_2 0x00020400// SM2 key exchange algorithm
#define SGD_SM2_3 0x00020800// SM2 encryption algorithm

#define SGD_SM9 0x00030000
#define SGD_SM9_1 0x00030200
#define SGD_SM9_2 0x00030400
#define SGD_SM9_3 0x00030800


#define SGD_ECDSA 0x00040000
#define SGD_ECDSA_1 0x00040200

#define SGD_EDDSA 0x00050000
#define SGD_EDDSA_1 0x00050200

#define SGD_DSA 0x00060000
#define SGD_DSA_1 0x00060200

// hash algorithms
//
#define SGD_SM3 0x00000001
#define SGD_SHA1 0x00000002
#define SGD_SHA256 0x00000004
#define SGD_SHA512 0x00000008
#define SGD_SHA384 0x00000040
#define SGD_SHA224 0x00000020
#define SGD_MD5 0x00000080

#define KEY_TYPE_SM2 10
#define KEY_TYPE_EDDSA 9
#define KEY_TYPE_ECDSA 7
#define KEY_TYPE_DSA 6
#define KEY_TYPE_RSA 4
#define KEY_TYPE_KEK 1
#define KEY_TYPE_SYMM_KEY 8

#define SDR_OK 0x00000000
#define SDR_BASE 0x01000000
#define SDR_UNKNOWERR (SDR_BASE + 0x00000001)
#define SDR_GENERAL_ERROR (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION (SDR_BASE + 0x00000006)
#define SDR_PARDENY (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST (SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT (SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR (SDR_BASE + 0x0000000F)
#define SDR_STEPERR (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR (SDR_BASE + 0x00000014)
#define SDR_KEYERR (SDR_BASE + 0x00000015)
#define SDR_ENCDATAERR (SDR_BASE + 0x00000016)
#define SDR_RANDERR (SDR_BASE + 0x00000017)
#define SDR_PRKRERR (SDR_BASE + 0x00000018)
#define SDR_MACERR (SDR_BASE + 0x00000019)
#define SDR_FILEEXISTS (SDR_BASE + 0x0000001A)
#define SDR_FILEWERR (SDR_BASE + 0x0000001B)
#define SDR_NOBUFFER (SDR_BASE + 0x0000001C)
#define SDR_INARGERR (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR (SDR_BASE + 0x0000001F)

// rename the obscure macro name
#define SDR_ARGUMENTS_BAD SDR_INARGERR

#define SDR_DAYOU 0x80000000
#define SDR_BUFFER_TOO_SMALL (SDR_DAYOU + 0x00000001)
#define SDR_OBJECT_EXIST (SDR_DAYOU + 0x00000002)
#define SDR_OBJECT_NOT_EXIST (SDR_DAYOU + 0x00000003)
#define SDR_MALLOC_ERROR (SDR_DAYOU + 0x00000004)

#define SDR_ENCODE_ERROR (SDR_DAYOU + 0x0000FFFE)          //encode request object or response object error
#define SDR_DECODE_ERROR (SDR_DAYOU + 0x0000FFFD)          //decode request object or response object error
#define SDR_INVALID_INSTRUCTION (SDR_DAYOU + 0x0000FFFC)   //instruction not supported
#define SDR_FUNCITON_NOT_SUPPORTED (SDR_DAYOU + 0x0000FFFB)//function not supported
#define SDR_WAIT_TIMEOUT (SDR_DAYOU + 0x0000FFFA)          //communication timed out
#define SDR_INCOMPLETE_PACKAGE (SDR_DAYOU + 0x0000FFF9)    //request package incomplete

/*-----------------------------------------------------------------------------
 * Device Management
 */

SDF_API int SDF_OpenDevice(
        void **phDeviceHandle);

SDF_API int SDF_CloseDevice(
        void *hDeviceHandle);

SDF_API int SDF_OpenSession(
        void *hDeviceHandle,
        void **phSessionHandle);

SDF_API int SDF_CloseSession(
        void *hSessionHandle);

SDF_API int SDF_GetDeviceInfo(
        void *hSessionHandle,
        DEVICEINFO *pstDeviceInfo);

SDF_API int SDF_GenerateRandom(
        void *hSessionHandle,
        unsigned int uiLength,
        unsigned char *pucRandom);

SDF_API int SDF_GetPrivateKeyAccessRight(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned char *pucPassword,
        unsigned int uiPwdLength);

SDF_API int SDF_ReleasePrivateKeyAccessRight(
        void *hSessionHandle,
        unsigned int uiKeyIndex);

/*-----------------------------------------------------------------------------
 *  Key Management
 */
/*\short 6.3.1
 *
 */
SDF_API int SDF_ExportSignPublicKey_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        RSArefPublicKey *pucPublicKey);
/*\short 6.3.2
 *
 */
SDF_API int SDF_ExportEncPublicKey_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        RSArefPublicKey *pucPublicKey);
/*\short 6.3.3
 *
 */
SDF_API int SDF_GenerateKeyPair_RSA(
        void *hSessionHandle,
        unsigned int uiKeyBits,
        RSArefPublicKey *pucPublicKey,
        RSArefPrivateKey *pucPrivateKey);
/*\short 6.3.4
 *
 */
SDF_API int SDF_GenerateKeyWithIPK_RSA(
        void *hSessionHandle,
        unsigned int uiIPKIndex,
        unsigned int uiKeyBits,
        unsigned char *pucKey,
        unsigned int *puiKeyLength,
        void **phKeyHandle);
/*\short 6.3.5
 *
 */
SDF_API int SDF_GenerateKeyWithEPK_RSA(
        void *hSessionHandle,
        unsigned int uiKeyBits,
        RSArefPublicKey *pucPublicKey,
        unsigned char *pucKey,
        unsigned int *puiKeyLength,
        void **phKeyHandle);
/*\short 6.3.6
 *
 */
SDF_API int SDF_ImportKeyWithISK_RSA(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned char *pucKey,
        unsigned int uiKeyLength,
        void **phKeyHandle);
/*\short 6.3.7
 *
 */
SDF_API int SDF_ExchangeDigitEnvelopeBaseOnRSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        RSArefPublicKey *pucPublicKey,
        unsigned char *pucDEInput,
        unsigned int uiDELength,
        unsigned char *pucDEOutput,
        unsigned int *puiDELength);
/*\short 6.3.8
 *
 */
SDF_API int SDF_ExportSignPublicKey_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        ECCrefPublicKey *pucPublicKey);
/*\short 6.3.9
 *
 */
SDF_API int SDF_ExportEncPublicKey_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        ECCrefPublicKey *pucPublicKey);
/*\short 6.3.10
 *
 */
SDF_API int SDF_GenerateKeyPair_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        ECCrefPublicKey *pucPublicKey,
        ECCrefPrivateKey *pucPrivateKey);
/*\short 6.3.11
 *
 */
SDF_API int SDF_GenerateKeyWithIPK_ECC(
        void *hSessionHandle,
        unsigned int uiIPKIndex,
        unsigned int uiKeyBits,
        ECCCipher *pucKey,
        void **phKeyHandle);
/*\short 6.3.12
 *
 */
SDF_API int SDF_GenerateKeyWithEPK_ECC(
        void *hSessionHandle,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        ECCCipher *pucKey,
        void **phKeyHandle);
/*\short 6.3.13
 *
 */
SDF_API int SDF_ImportKeyWithISK_ECC(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        ECCCipher *pucKey,
        void **phKeyHandle);
/*\short 6.3.14
 *
 */
SDF_API int SDF_GenerateAgreementDataWithECC(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiKeyBits,
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        ECCrefPublicKey *pucSponsorPublicKey,
        ECCrefPublicKey *pucSponsorTmpPublicKey,
        void **phAgreementHandle);
/*\short 6.3.15
 *
 */
SDF_API int SDF_GenerateKeyWithECC(
        void *hSessionHandle,
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        ECCrefPublicKey *pucResponsePublicKey,
        ECCrefPublicKey *pucResponseTmpPublicKey,
        void *phAgreementHandle,
        void **phKeyHandle);
/*\short 6.3.16
 * It's a wonderful  function !!!
 */
SDF_API int SDF_GenerateAgreementDataAndKeyWithECC(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiKeyBits,
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        unsigned char *pucResponseID,
        unsigned int uiResponseIDLength,
        ECCrefPublicKey *pucSponsorPublicKey,
        ECCrefPublicKey *pucSponsorTmpPublicKey,
        ECCrefPublicKey *pucResponsePublicKey,
        ECCrefPublicKey *pucResponseTmpPublicKey,
        void **phKeyHandle);
/*\short 6.3.17
 *
 */
SDF_API int SDF_ExchangeDigitEnvelopeBaseOnECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        ECCCipher *pucEncDataIn,
        ECCCipher *pucEncDataOut);
/*\short 6.3.17
 *
 */
SDF_API int SDF_GenerateKeyWithKEK(
        void *hSessionHandle,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        unsigned int uiKEKIndex,
        unsigned char *pucKey,
        unsigned int *puiKeyLength,
        void **phKeyHandle);
/*\short 6.3.18
 *
 */
SDF_API int SDF_ImportKeyWithKEK(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKEKIndex,
        unsigned char *pucKey,
        unsigned int uiKeyLength,
        void **phKeyHandle);
/*\short 6.3.19
 *
 */
SDF_API int SDF_ImportKey(
        void *hSessionHandle,
        unsigned char *pucKey,
        unsigned int uiKeyLength,
        void **phKeyHandle);
/*\short 6.3.20
 *
 */
SDF_API int SDF_DestroyKey(
        void *hSessionHandle,
        void *hKeyHandle);

/*\short extended
 *
 */
SDF_API int SDF_GetSymmKeyHandle(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        void **phKeyHandle);

/*-----------------------------------------------------------------------------
 * RSA algorithm encryption
 */
/*\short 6.4.1
 *
 */
SDF_API int SDF_ExternalPublicKeyOperation_RSA(
        void *hSessionHandle,
        RSArefPublicKey *pucPublicKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);
/*\short 6.4.2
 *
 */
SDF_API int SDF_ExternalPrivateKeyOperation_RSA(
        void *hSessionHandle,
        RSArefPrivateKey *pucPrivateKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);
/*\short 6.4.3
 *
 */
SDF_API int SDF_InternalPublicKeyOperation_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);
/*\short 6.4.4
 *
 */
SDF_API int SDF_InternalPrivateKeyOperation_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);

SDF_API int SDF_InternalEncrypt_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);

SDF_API int SDF_InternalDecrypt_RSA(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);

/*-----------------------------------------------------------------------------
 * ECC algorithm encryption
 */
/*\short 6.4.5
 *
 */
SDF_API int SDF_ExternalSign_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);
/*
 * short 6.4.6
 */
SDF_API int SDF_ExternalVerify_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        ECCSignature *pucSignature);
/*
 * short 6.4.7
 */
SDF_API int SDF_InternalSign_ECC(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);
/*
 * short 6.4.8
 */
SDF_API int SDF_InternalVerify_ECC(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);
/*
 * short 6.4.9
 */
SDF_API int SDF_ExternalEncrypt_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCCipher *pucEncData);
/*
 * short 6.4.10
 */
SDF_API int SDF_ExternalDecrypt_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

#ifndef SGD_SM2_DECENC

SDF_API int SDF_InternalEncrypt_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int uiAlgID,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCCipher *pucEncData);

#else
SDF_API int SDF_InternalEncrypt_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCCipher *pucEncData);
#endif

#ifndef SGD_SM2_DECENC

SDF_API int SDF_InternalDecrypt_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int uiAlgID,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

#else
SDF_API int SDF_InternalDecrypt_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);
#endif

/*-----------------------------------------------------------------------------
 * Secret key algorithm encryption
 */
/*\short 6.5.1
 *
 */
SDF_API int SDF_Encrypt(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucEncData,
        unsigned int *puiEncDataLength);
/*\short 6.5.2
 *
 */
SDF_API int SDF_Decrypt(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength);
/*\short 6.5.3
 *
 */
SDF_API int SDF_CalculateMAC(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucMAC,
        unsigned int *puiMACLength);
/*-----------------------------------------------------------------------------
 * HASH Functions
 */
/*\short 6.6.1
 *
 */
SDF_API int SDF_HashInit(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucID,
        unsigned int uiIDLength);
/*\short 6.6.2
 *
 */
SDF_API int SDF_HashUpdate(
        void *hSessionHandle,
        unsigned char *pucData,
        unsigned int uiDataLength);
/*\short 6.6.3
 *
 */
SDF_API int SDF_HashFinal(
        void *hSessionHandle,
        unsigned char *pucHash,
        unsigned int *puiHashLength);

/*-----------------------------------------------------------------------------
 * File access
 */
/*\short 6.7.1
 *
 */
SDF_API int SDF_CreateFile(
        void *hSessionHandle,
        unsigned char *pucFileName,
        unsigned int uiNameLen,
        unsigned int uiFileSize);
/*\short 6.7.2
 *
 */
SDF_API int SDF_ReadFile(
        void *hSessionHandle,
        unsigned char *pucFileName,
        unsigned int uiNameLen,
        unsigned int uiOffset,
        unsigned int *puiReadLength,
        unsigned char *pucBuffer);
/*\short 6.7.3
 *
 */
SDF_API int SDF_WriteFile(
        void *hSessionHandle,
        unsigned char *pucFileName,
        unsigned int uiNameLen,
        unsigned int uiOffset,
        unsigned int uiWriteLength,
        unsigned char *pucBuffer);
/*\short 6.7.4
 *
 */
SDF_API int SDF_DeleteFile(
        void *hSessionHandle,
        unsigned char *pucFileName,
        unsigned int uiNameLen);

SDF_API int SDF_Echo(
        void *hSessionHandle,
        unsigned char *inData,
        unsigned int inDataLen,
        unsigned char *outData,
        unsigned int *outDataLen);

SDF_API int SDF_OpenDeviceEx(
        void **phDeviceHandle,
        char *iniPath,
        SysConf *pconf);

SDF_API int SDF_GenerateKeyPair_ECDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        ECCrefPublicKey_ECDSA *pucPublicKey,
        ECCrefPrivateKey_ECDSA *pucPrivateKey);

SDF_API int SDF_ExternalSign_ECC_ECDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPrivateKey_ECDSA *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_ECDSA *pucSignature);

SDF_API int SDF_ExternalVerify_ECC_ECDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey_ECDSA *pucPublicKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_ECDSA *pucSignature);

SDF_API int SDF_GenerateKeyPair_EDDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        ECCrefPublicKey_EDDSA *pucPublicKey,
        ECCrefPrivateKey_EDDSA *pucPrivateKey);

SDF_API int SDF_ExternalSign_ECC_EDDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPrivateKey_EDDSA *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_EDDSA *pucSignature);

SDF_API int SDF_ExternalVerify_ECC_EDDSA(
        void *hSessionHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey_EDDSA *pucPublicKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_EDDSA *pucSignature);

SDF_API int SDF_GenerateKeyPair_DSA(
        void *hSessionHandle,
        unsigned int uiKeyBits,
        DSArefPublicKey *pucPublicKey,
        DSArefPrivateKey *pucPrivateKey);

SDF_API int SDF_ExternalSign_DSA(
        void *hSessionHandle,
        DSArefPrivateKey *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        DSASignature *pucSignature);

SDF_API int SDF_ExternalVerify_DSA(
        void *hSessionHandle,
        DSArefPublicKey *pucPublicKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        DSASignature *pucSignature);

SDF_API int SDF_OpenDevice_EX(
        char *hsmAddr,
        int port,
        void **phDeviceHandl);

SDF_API int SDF_GenerateKeyPairWithKEK_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        unsigned int uiKEKIndex,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucEncPrivateKey);

SDF_API int SDF_ImportKeyPairWithKEK_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        unsigned int uiKEKIndex,
        unsigned int uiKeyPairIndex,
        unsigned int uiEccAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucEncPrivateKey);

SDF_API int SDF_ImportKeyWithKEK_EX(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKEKIndex,
        unsigned int uiKeyIndex,
        unsigned char *pucKey,
        unsigned int puiKeyLength);


//AYDH
SDF_API int SDF_GETSM2_DECENC_Temp();

SDF_API int SDF_InternalEncrypt(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucEncData,
        unsigned int *puiEncDataLength);

SDF_API int SDF_InternalDecrypt(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        unsigned char *pucIV,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength);

SDF_API int SDF_GenerateKey_Handle_ECC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        unsigned int uiKEKIndex,
        unsigned char *pucEncPrivateKey,
        void **sm2PrikeyHandle);

SDF_API int SDF_HandleSign_ECC(
        void *hSessionHandle,
        void *sm2PrikeyHandle,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);

SDF_API int SDF_HandleDecrypt_ECC(
        void *hSessionHandle,
        void *sm2PrikeyHandle,
        unsigned int uiAlgID,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

SDF_API int SDF_ImportKeyWithHandle_ECC(
        void *hSessionHandle,
        void *sm2PrikeyHandle,
        ECCCipher *pucKey,
        void **phKeyHandle);

SDF_API int SDF_ExchangeHandleEnvelopeBaseOnECC(
        void *hSessionHandle,
        void *sm2PrikeyHandle,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        ECCCipher *pucEncDataIn,
        ECCCipher *pucEncDataOut);

SDF_API int SDF_InternalMAC(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucMAC,
        unsigned int *puiMACLength);

SDF_API int SDF_DestroyKey_Handle_ECC(
        void *hSessionHandle,
        void *sm2PrikeyHandle);

SDF_API int SDF_Encrypt_Index(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned int uiKeyIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucEncData,
        unsigned int *puiEncDataLength);

SDF_API int SDF_Decrypt_Index(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned int uiKeyIndex,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength);

SDF_API int SDF_ImportCryptKeyPair_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int forceUpdate,
        ECCrefPublicKey *pucPublicKey,
        ECCrefPrivateKey *pucPrivateKey);

SDF_API int SDF_ImportSignKeyPair_ECC(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int forceUpdate,
        ECCrefPublicKey *pucPublicKey,
        ECCrefPrivateKey *pucPrivateKey);

SDF_API int SDF_GenerateRandomExt(
        void *hSessionHandle,
        unsigned char *pucRandom,
        unsigned int uiLength);

SDF_API int API_ImportEncData(
        void *hSessionHandle,
        unsigned char *pucData,
        unsigned int uDataLen,
        unsigned int decIndex,
        unsigned int uAlgID,
        unsigned char *pucIV,
        unsigned int uiIndex,
        unsigned int uSaveOpt,
        unsigned int iCut,
        unsigned int iCutLen,
        void *reserve);

SDF_API int API_EncData_Index(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int uAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLen,
        unsigned char *outData,
        unsigned int *outLen);

SDF_API int API_GenRandData(
        void *hSessionHandle,
        unsigned char *pucRandom,
        unsigned int uiLength,
        unsigned int uiIndex,
        unsigned int uSaveOpt);

SDF_API int API_ExportEncData(
        void *hSessionHandle,
        unsigned char *pucData,
        unsigned int *uiDataLen,
        unsigned int uiEncIndex,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned int uiIndex,
        unsigned int uSaveOpt,
        unsigned int iCut,
        unsigned int iCutLen,
        void *reserve);

SDF_API int API_ImportEncData_Cov(
        void *hSessionHandle,
        unsigned char *pucData,
        unsigned int uDataLen,
        unsigned int decIndex,
        unsigned int uAlgID,
        unsigned char *pucIV,
        unsigned int uiIndex,
        unsigned int uSaveOpt,
        unsigned int iCut,
        unsigned int iCutLen,
        unsigned int isCover,
        void *reserve);

SDF_API int API_ExportEncData_Cov(
        void *hSessionHandle,
        unsigned char *pucData,
        unsigned int *uiDataLen,
        unsigned int uiEncIndex,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned int uiIndex,
        unsigned int uSaveOpt,
        unsigned int iCut,
        unsigned int iCutLen,
        unsigned int isCover,
        void *reserve);

SDF_API int SDF_HMAC(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucInData,
        unsigned int uiInDataLength,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLength);

SDF_API int SDF_HMACBatch(
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char **pucDataArray,
        unsigned int *uiDataLengthArray,
        unsigned char **pucHmacArray,
        unsigned int *puiHmacLenArray,
        unsigned int arrayCount);

SDF_API int SDFE_ImportKEK(
        void *hSessionHandle,
        unsigned int uiKEKIndex,
        unsigned char *pucKey,
        unsigned int uiKeyBits);

SDF_API int SDF_InternalSign_ECC_DSA(
        void *hSessionHandle,
        unsigned int uiIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        DSASignature *pucSignature);

SDF_API int SDF_InternalVerify_ECC_DSA(
        void *hSessionHandle,
        unsigned int uiIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        DSASignature *pucSignature);

SDF_API int SDF_InternalSign_ECC_ECDSA(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiAlgID,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_ECDSA *pucSignature);

SDF_API int SDF_InternalVerify_ECC_ECDSA(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiAlgID,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_ECDSA *pucSignature);

SDF_API int SDF_InternalSign_ECC_EDDSA(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiAlgID,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_EDDSA *pucSignature);

SDF_API int SDF_InternalVerify_ECC_EDDSA(
        void *hSessionHandle,
        unsigned int uiISKIndex,
        unsigned int uiAlgID,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature_EDDSA *pucSignature);


/* generate key pair */
SDF_API int SDF_GenerateSignMasterKeyPair_SM9(
        void *hSessionHandle,
        unsigned int uiAlgID,
        SM9MasterPrivateKey *pPrivateKey,
        SM9SignMasterPublicKey *pPuclicKey);

SDF_API int SDF_GenerateEncMasterKeyPair_SM9(
        void *hSessionHandle,
        unsigned int uiAlgID,
        SM9MasterPrivateKey *pPrivateKey,
        SM9EncMasterPublicKey *pPuclicKey);

SDF_API int SDF_GenerateUserSignKey_SM9(
        void *hSessionHandle,
        unsigned int uiAlgID,
        SM9MasterPrivateKey *pPrivateKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserSignPrivateKey *vk);

SDF_API int SDF_GenerateUserEncKey_SM9(
        void *hSessionHandle,
        unsigned int uiAlgID,
        SM9MasterPrivateKey *pPrivateKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserEncPrivateKey *vk);

/* key management*/
SDF_API int SDF_ExportSignMasterPublicKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        SM9SignMasterPublicKey *pSignMasterPubKey);

SDF_API int SDF_ExportEncMasterPublicKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        SM9EncMasterPublicKey *pEncMastPubKey);

int SDFE_GenerateUserEncKey_SM9(
        void *hSessionHandle,
        unsigned int uiAlgID,
        SM9MasterPrivateKey *pPrivateKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserEncPrivateKey *vk);

SDF_API int SDF_CreateSignMasterKeyPair_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        SM9SignMasterPublicKey *pPuclicKey);

SDF_API int SDF_CreateEncMasterKeyPair_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        SM9EncMasterPublicKey *pPuclicKey);

SDF_API int SDF_CreateUserSignKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen);

SDF_API int SDF_CreateUserEncKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen);

int SDF_DeleteInternalKeyPair_SM9(
        void *hSessionHandle,
        unsigned int uiMastFlag,
        unsigned int uiSignFlag,
        unsigned int uiKeyIndex,
        char *AdminPIN);

int SDF_GenerateUserSignKeyWithMasterEPK_SM9(
        void *hSessionHandle,
        unsigned int indexGen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucEncID,
        unsigned int uiEncIDLen,
        SM9EncMasterPublicKey *pk,
        SM9PairSignEnvelopedKey *vk);

int SDF_GenerateUserEncKeyWithMasterEPK_SM9(
        void *hSessionHandle,
        unsigned int indexGen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucEncID,
        unsigned int uiEncIDLen,
        SM9EncMasterPublicKey *pk,
        SM9PairEncEnvelopedKey *vk);

int SDF_ImportUserSignKeyWithMasterISK_SM9(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        SM9PairSignEnvelopedKey *pEnvelpoedKey,
        unsigned int *puiUserKeyIndex);

int SDF_ImportUserEncKeyWithMasterISK_SM9(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        SM9PairEncEnvelopedKey *pEnvelpoedKey,
        unsigned int *puiUserKeyIndex);

/* key encap */
int SDF_GenerateKeyWithMasterEPK_SM9(
        void *hSessionHandle,
        unsigned int uiKeyLen,
        SM9EncMasterPublicKey *pPublicKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9KeyPackage *pucKey,
        void **phKeyHandle);

int SDF_ImportKeyWithEncKey_SM9(
        void *hSessionHandle,
        unsigned int uiKeyLen,
        SM9UserEncPrivateKey *vk,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9KeyPackage *pucKey,
        void **phKeyHandle);

int SDF_GenerateKeyWithMasterIPK_SM9(
        void *hSessionHandle,
        unsigned int uiKeyLen,
        unsigned int uiMasterKeyIndex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9KeyPackage *pucKey,
        void **phKeyHandle);

int SDF_ImportKeyWithISK_SM9(
        void *hSessionHandle,
        unsigned int uiKeyIndex,
        unsigned int uiKeyLen,
        SM9KeyPackage *pucKey,
        void **phKeyHandle);

SDF_API int SDF_ImportSignMasterKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        SM9MasterPrivateKey *pPrivateKey,
        SM9SignMasterPublicKey *pPuclicKey);

SDF_API int SDF_ImportEncMasterKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        SM9MasterPrivateKey *pPrivateKey,
        SM9EncMasterPublicKey *pPuclicKey);

SDF_API int SDF_ImportUserSignKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserSignPrivateKey *vk);

SDF_API int SDF_ImportUserEncKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserEncPrivateKey *vk);

SDF_API int SDF_DeleteSignMasterKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex);

SDF_API int SDF_DeleteEncMasterKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex);

SDF_API int SDF_DeleteSignUserKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex);

SDF_API int SDF_DeleteEncUserKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyindex,
        unsigned int uiUserKeyindex);

/* key exchange */
int SDF_GenerateAgreementDataWithSM9(
        void *hSessionHandle,
        SM9EncMasterPublicKey *pSponsorEncMastPubKey,
        SM9UserEncPrivateKey *pSponsorPrivateKey,
        unsigned int uiKeyBits,
        unsigned char *pResponseID,
        unsigned int ulResponseIDLen,
        unsigned char *pSponsorID,
        unsigned int ulSponsorIDLen,
        SM9EncMasterPublicKey *pSponsorTempPublicKey,
        void **phAgreementHandle);

int SDF_GenerateKeyWithSM9(
        void *hSessionHandle,
        void *hAgreementHandle,
        SM9EncMasterPublicKey *pResponseTempPublicKey,
        void **phKeyHandle);

int SDF_GenerateAgreementDataAndKeyWithSM9(
        void *hSessionHandle,
        SM9EncMasterPublicKey *pResponsorEncMastPubKey,
        SM9UserEncPrivateKey *pResponsorPrivateKey,
        unsigned int uiKeyBits,
        unsigned char *pResponseID,
        unsigned int ulResponseIDLen,
        unsigned char *pSponsorID,
        unsigned int ulSponsorIDLen,
        SM9EncMasterPublicKey *pSponsorTempPublicKey,
        SM9EncMasterPublicKey *pResponseTempPublicKey,
        void **phKeyHandle);

int SDFE_GenerateAgreementDataWithSM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned int uiISKIndex,
        unsigned int uiKeyBits,
        unsigned char *pResponseID,
        unsigned int ulResponseIDLen,
        unsigned char *pSponsorID,
        unsigned int ulSponsorIDLen,
        SM9EncMasterPublicKey *pSponsorTempPublicKey,
        void **phAgreementHandle);

int SDFE_GenerateAgreementDataAndKeyWithSM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned int uiISKIndex,
        unsigned int uiKeyBits,
        unsigned char *pResponseID,
        unsigned int ulResponseIDLen,
        unsigned char *pSponsorID,
        unsigned int ulSponsorIDLen,
        SM9EncMasterPublicKey *pSponsorTempPublicKey,
        SM9EncMasterPublicKey *pResponseTempPublicKey,
        void **phKeyHandle);

/* key calc*/
SDF_API int SDF_SignWithMasterEPK_SM9(
        void *hSessionHandle,
        SM9SignMasterPublicKey *pPublicKey,
        SM9UserSignPrivateKey *vk,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Signature *pSignature);

SDF_API int SDF_InternalSignWithMasterEPK_SM9(
        void *hSessionHandle,
        SM9SignMasterPublicKey *pPublicKey,
        unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Signature *pSignature);

SDF_API int SDF_InternalSignWithMasterIPK_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Signature *pSignature);

SDF_API int SDF_VerifyWithMasterEPK_SM9(
        void *hSessionHandle,
        SM9SignMasterPublicKey *pPublicKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Signature *pSignature);

SDF_API int SDF_VerifyWithMasterIPK_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Signature *pSignature);

SDF_API int SDF_EncryptWithMasterEPK_SM9(
        void *hSessionHandle,
        SM9EncMasterPublicKey *pPublicKey,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned int ulAlgID,
        unsigned char *pIV,
        unsigned int uiIVLength,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Cipher *pEncData);

SDF_API int SDF_EncryptWithMasterIPK_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned int uiAlgID,
        unsigned char *pIV,
        unsigned int uiIVLength,
        unsigned char *pucData,
        unsigned int uiDataLength,
        SM9Cipher *pEncData);

SDF_API int SDF_DecryptWithUserEncKey_SM9(
        void *hSessionHandle,
        SM9UserEncPrivateKey *vk,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pIV,
        unsigned int uiIVLength,
        SM9Cipher *pEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

SDF_API int SDF_DecryptWithInternalKey_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned int uiKeyIndex,
        unsigned char *pIV,
        unsigned int uiIVLength,
        SM9Cipher *pEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

SDF_API int SDF_GenerateUserSignKeyWithIPK_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserSignPrivateKey *vk);

SDF_API int SDF_GenerateUserEncKeyWithIPK_SM9(
        void *hSessionHandle,
        unsigned int uiMasterKeyIndex,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        SM9UserEncPrivateKey *vk);

SDF_API int SDFE_GenerateKeyPair(void *hSessionHandle,
                                 unsigned int uiAlgID,
                                 unsigned int keyindex,
                                 unsigned int uiKeyBits);

SDF_API int SDFE_ImportKeyPair(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex,
        unsigned char *pucPublicKey,
        unsigned int pucPublicKeyLen,
        unsigned char *pucPrivateKey,
        unsigned int pucPrivateKeyLen);

SDF_API int SDFE_DeleteKeyPair(
        void *hSessionHandle,
        unsigned int uiAlgID,
        unsigned int uiKeyIndex);

SDF_API int SDFE_GenerateKEK(void *hSessionHandle,
                             unsigned int uiAlgID,
                             unsigned int keyindex,
                             unsigned int uiKeyBits);

SDF_API int SDFE_DeleteKEK(void *hSessionHandle,
                           unsigned int uiAlgID,
                           unsigned int keyindex);

SDF_API int SDFE_HashInit(void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength,
	unsigned char ctx[512]);

SDF_API int SDFE_HashUpdate(
	void *hSessionHandle,
	unsigned char ctx[512],
	unsigned char *pucData,
	unsigned int uiDataLength);

SDF_API int SDFE_HashFinal(
	void *hSessionHandle,
	unsigned char ctx[512],
	unsigned char *pucHash,
	unsigned int *puiHashLength);

SDF_API int SDFE_HmacInit(void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int keyindex,
	unsigned char *pucKey,
	unsigned int uiKeyLength);

SDF_API int SDFE_HmacUpdate(void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength);

SDF_API int SDFE_HmacFinal(void *hSessionHandle,
	unsigned char *pucHMAC,
	unsigned int *puiHMACLength);

SDF_API int SDFE_GcmInit(void *hSessionHandle,
	int mode,
	unsigned int uiAlgID,
	unsigned int keyindex,
	unsigned char *pucIV,
	int pucIVLen,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	unsigned char *aad,
	size_t aad_len);

SDF_API int SDFE_GcmUpdate(void *hSessionHandle, unsigned char *indata, int inlen, unsigned char *outdata, int *outlen);

SDF_API int SDFE_GcmFinal(void *hSessionHandle, int outlen, unsigned char *tag, int *tagLen);

SDF_API int SDFE_CcmInit(void *hSessionHandle,
	int mode,
	unsigned int uiAlgID,
	unsigned int keyindex,
	int length,
	unsigned char *pucIV,
	int pucIVLen,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	unsigned char *aad,
	size_t aad_len);

SDF_API int SDFE_CcmUpdate(void *hSessionHandle, unsigned char *indata, int inlen, unsigned char *outdata, int *outlen);

SDF_API int SDFE_CcmFinal(void *hSessionHandle, unsigned char *tag, int *tagLen);

#pragma pack(pop, libsdf)

#ifdef __cplusplus
}
#endif

#endif /*#ifndef _LIB_SDF_H_*/
