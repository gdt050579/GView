#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ts.h>
#include <openssl/cms.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <time.h>

#include <memory>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace Authenticode
{
constexpr char const* NID_spc_info                = "1.3.6.1.4.1.311.2.1.12";
constexpr char const* NID_spc_ms_countersignature = "1.3.6.1.4.1.311.3.3.1";
constexpr char const* NID_spc_nested_signature    = "1.3.6.1.4.1.311.2.4.1";
constexpr char const* NID_spc_indirect_data       = "1.3.6.1.4.1.311.2.1.4";

typedef struct
{
    int type;
    union
    {
        ASN1_BMPSTRING* unicode;
        ASN1_IA5STRING* ascii;
    } value;
} SpcString;

typedef struct
{
    ASN1_OCTET_STRING* classId;
    ASN1_OCTET_STRING* serializedData;
} SpcSerializedObject;

typedef struct
{
    int type;
    union
    {
        ASN1_IA5STRING* url;
        SpcSerializedObject* moniker;
        SpcString* file;
    } value;
} SpcLink;

typedef struct
{
    ASN1_OBJECT* type;
    ASN1_TYPE* value;
} SpcAttributeTypeAndOptionalValue;

typedef struct
{
    ASN1_BIT_STRING* flags;
    SpcLink* file;
} SpcPeImageData;

typedef struct
{
    ASN1_OBJECT* algorithm;
    ASN1_TYPE* parameters;
} AlgorithmIdentifier;

typedef struct
{
    AlgorithmIdentifier* digestAlgorithm;
    ASN1_OCTET_STRING* digest;
} DigestInfo;

typedef struct
{
    SpcAttributeTypeAndOptionalValue* data;
    DigestInfo* messageDigest;
} SpcIndirectDataContent;

typedef struct
{
    ASN1_OBJECT* contentType;
    SpcIndirectDataContent* content;
} SpcContentInfo;

typedef struct
{
    SpcString* programName;
    SpcLink* moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcString)
DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)
DECLARE_ASN1_FUNCTIONS(SpcLink)
DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)
DECLARE_ASN1_FUNCTIONS(SpcPeImageData)
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)
DECLARE_ASN1_FUNCTIONS(DigestInfo)
DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)
DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)
DECLARE_ASN1_FUNCTIONS(SpcContentInfo)

enum class AuthenticodeVFY
{
    Valid            = 0,  /* Signature is valid */
    CantParse        = 1,  /* Parsing error (from OpenSSL functions) */
    NoSignerCert     = 2,  /* Signers certificate is missing */
    DigestMissing    = 3,  /* No digest saved inside the signature */
    InternalError    = 4,  /* Non verification errors - allocations etc. */
    NoSignerInfo     = 5,  /* SignerInfo part of PKCS7 is missing */
    WrongPKCS7Type   = 6,  /* PKCS7 doesn't have type of SignedData, can't proceed */
    BadContent       = 7,  /* PKCS7 doesn't have corrent content, can't proceed */
    Invalid          = 8,  /* Contained and calculated digest don't match */
    WrongFileDigest  = 9,  /* Signature hash and file hash doesn't match */
    UnknownAlgorithm = 10, /* Unknown algorithm, can't proceed with verification */
};

enum class CountersignatureVFY
{
    Valid                = 0, /* Countersignature is valid */
    CantParse            = 1, /* Parsing error (from OpenSSL functions) */
    NoSignerCert         = 2, /* Signers certificate is missing */
    UnknownAlgorithm     = 3, /* Unknown algorithm, can't proceed with verification */
    Invalid              = 4, /* Verification failed, digest mismatch */
    CantDecryptDigest    = 5, /* Failed to decrypt countersignature enc_digest for verification */
    DigestMissing        = 6, /* No digest saved inside the countersignature */
    DoesntMatchSignature = 7, /* Message digest inside countersignature doesn't match signature it countersigns */
    InternalError        = 8, /* Non verification errors - allocations etc. */
    TimeMissing          = 9, /* Time is missing in the timestamp signature */
};

/* Endianity related functions for PE reading */
uint16_t bswap16(uint16_t d);
uint32_t bswap32(uint32_t d);

#if defined(WORDS_BIGENDIAN)
#    define letoh16(x) bswap16(x)
#    define letoh32(x) bswap32(x)
#    define betoh16(x) (x)
#    define betoh32(x) (x)
#else
#    define letoh16(x) (x)
#    define letoh32(x) (x)
#    define betoh16(x) bswap16(x)
#    define betoh32(x) bswap32(x)
#endif

/* OpenSSL defines OPENSSL_free as a macro, which we can't use with decltype.
 * So we wrap it here for use with unique_ptr.
 */
static void My_OpenSSL_free(void* ptr)
{
    OPENSSL_free(ptr);
}

/* Convenient self-releasing aliases for libcrypto and custom ASN.1 types. */
using BIO_ptr               = std::unique_ptr<BIO, decltype(&BIO_free)>;
using ASN1_OBJECT_ptr       = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using ASN1_TYPE_ptr         = std::unique_ptr<ASN1_TYPE, decltype(&ASN1_TYPE_free)>;
using OpenSSL_ptr           = std::unique_ptr<char, decltype(&My_OpenSSL_free)>;
using BN_ptr                = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PKCS7_SIGNER_INFO_ptr = std::unique_ptr<PKCS7_SIGNER_INFO, decltype(&PKCS7_SIGNER_INFO_free)>;
using PKCS7_ptr             = std::unique_ptr<PKCS7, decltype(&PKCS7_free)>;
using CMS_ContentInfo_ptr   = std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>;
using ASN1_PCTX_ptr         = std::unique_ptr<ASN1_PCTX, decltype(&ASN1_PCTX_free)>;

class Attributes /* Various X509 attributes parsed out in raw bytes*/
{
  public:
    std::vector<char> country;
    std::vector<char> organization;
    std::vector<char> organizationalUnit;
    std::vector<char> nameQualifier;
    std::vector<char> state;
    std::vector<char> commonName;
    std::vector<char> serialNumber;
    std::vector<char> locality;
    std::vector<char> title;
    std::vector<char> surname;
    std::vector<char> givenName;
    std::vector<char> initials;
    std::vector<char> pseudonym;
    std::vector<char> generationQualifier;
    std::vector<char> emailAddress;
};

class Certificate
{
  public:
    long version;                                 /* Raw version of X509 */
    std::unique_ptr<char> issuer{ nullptr };      /* Oneline name of Issuer */
    std::unique_ptr<char> subject{ nullptr };     /* Oneline name of Subject */
    std::unique_ptr<char> serial{ nullptr };      /* Serial number in format 00:01:02:03:04... */
    std::vector<unsigned char> sha1;              /* SHA1 of the DER representation of the cert */
    std::vector<unsigned char> sha256;            /* SHA256 of the DER representation of the cert */
    std::unique_ptr<char> key_alg{ nullptr };     /* Name of the key algorithm */
    std::unique_ptr<char> sig_alg{ nullptr };     /* Name of the signature algorithm */
    std::unique_ptr<char> sig_alg_oid{ nullptr }; /* OID of the signature algorithm */
    time_t not_before;                            /* NotBefore validity */
    time_t not_after;                             /* NotAfter validity */
    std::unique_ptr<char> key{ nullptr };         /* PEM encoded public key */
    Attributes issuer_attrs;                      /* Parsed X509 Attributes of Issuer */
    Attributes subject_attrs;                     /* Parsed X509 Attributes of Subject */

    bool Parse(X509* x509);
};

class Countersignature
{
  public:
    int verifyFlags;                    /* COUNTERISGNATURE_VFY_ flag */
    time_t signTime;                    /* Signing time of the timestamp countersignature */
    std::unique_ptr<char> digest_alg{}; /* Name of the digest algorithm used */
    std::vector<unsigned char> digest;  /* Stored message digest */
    std::vector<Certificate> chain;     /* Certificate chain of the signer */

    bool ParsePKCS9(const uint8_t* data, long size, STACK_OF(X509) * certs, ASN1_STRING* enc_digest, PKCS7_SIGNER_INFO* counter);
    bool ParseMS(const uint8_t* data, long size, ASN1_STRING* enc_digest);
};

class Signer /* Represents SignerInfo structure */
{
  public:
    std::vector<unsigned char> digest;    /* Message Digest of the SignerInfo */
    std::unique_ptr<char> digest_alg{};   /* name of the digest algorithm */
    std::unique_ptr<char> program_name{}; /* Program name stored in SpcOpusInfo structure of Authenticode */
    std::vector<Certificate> chain;       /* Certificate chain of the signer */
};

class Authenticode
{
  public:
    uint32_t verify_flags;                     /* AUTHENTICODE_VFY_ flag */
    uint64_t version;                          /* Raw PKCS7 version */
    std::unique_ptr<char> digest_alg{};        /* name of the digest algorithm */
    std::vector<unsigned char> digest;         /* File Digest stored in the Signature */
    std::vector<unsigned char> file_digest;    /* Actual calculated file digest */
    Signer signer;                             /* SignerInfo information of the Authenticode */
    std::vector<Certificate> certs;            /* All certificates in the Signature including the ones in timestamp
                                                  countersignatures */
    std::vector<Countersignature> countersigs; /* Array of timestamp countersignatures */
};

class AuthenticodeParser
{
  private:
    std::vector<Authenticode> authenticodeData;

  public:
    AuthenticodeParser();
    bool AuthenticodeParse(const uint8_t* bufferPE, uint64_t len);
    bool AuthenticodeNew(const uint8_t* data, long len, std::vector<Authenticode>& result);
    void ParseNestedAuthenticode(PKCS7_SIGNER_INFO* si, std::vector<Authenticode>& result);
    static std::vector<Certificate> ParseSignerChain(X509* signerCert, STACK_OF(X509) * certs);
    bool Dump(std::string& output) const;
};

/* Calculates digest md of data, return bytes written to digest or 0 on error
 * Maximum of EVP_MAX_MD_SIZE will be written to digest */
int CalculateDigest(const EVP_MD* md, const uint8_t* data, size_t len, uint8_t* digest);
/* Converts ASN1_TIME string time into a unix timestamp */
time_t ASN1_TIME_to_time_t(const ASN1_TIME* time);
} // namespace Authenticode
