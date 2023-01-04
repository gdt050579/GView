#include "Internal.hpp"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/asn1t.h>

#include "authenticode.hpp"

namespace GView::DigitalSignature
{
struct WrapperBIO
{
    BIO* memory = nullptr;

    ~WrapperBIO()
    {
        BIO_free(memory);
    }
};

struct WrapperCMS_ContentInfo
{
    CMS_ContentInfo* data = nullptr;

    ~WrapperCMS_ContentInfo()
    {
        CMS_ContentInfo_free(data);
    }
};

struct WrapperPKCS7
{
    PKCS7* data = nullptr;

    ~WrapperPKCS7()
    {
        if (data != nullptr)
        {
            // PKCS7_free(data);
            data = nullptr;
        }
    }
};

struct WrapperASN1_PCTX
{
    ASN1_PCTX* data = nullptr;

    ~WrapperASN1_PCTX()
    {
        ASN1_PCTX_free(data);
    }
};

struct WrapperSTACK_OF_X509
{
    STACK_OF(X509) * data = nullptr;

    ~WrapperSTACK_OF_X509()
    {
        sk_X509_pop_free(data, X509_free);
    }
};

struct WrapperBIGNUM
{
    BIGNUM* data = nullptr;

    ~WrapperBIGNUM()
    {
        BN_free(data);
    }
};

struct WrapperEVP_PKEY
{
    EVP_PKEY* data = nullptr;

    ~WrapperEVP_PKEY()
    {
        EVP_PKEY_free(data);
    }
};

struct WrapperBUF_MEM
{
    BUF_MEM* data = nullptr;

    ~WrapperBUF_MEM()
    {
        BUF_MEM_free(data);
    }
};

/* OpenSSL defines OPENSSL_free as a macro, which we can't use with decltype.
 * So we wrap it here for use with unique_ptr.
 */
void OpenSSL_free(void* ptr)
{
    OPENSSL_free(ptr);
}

void SK_X509_free(stack_st_X509* ptr)
{
    sk_X509_free(ptr);
}

/* Convenient self-releasing aliases for libcrypto and custom ASN.1 types. */
using BIO_ptr           = std::unique_ptr<BIO, decltype(&BIO_free)>;
using ASN1_OBJECT_ptr   = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using ASN1_TYPE_ptr     = std::unique_ptr<ASN1_TYPE, decltype(&ASN1_TYPE_free)>;
using OpenSSL_ptr       = std::unique_ptr<char, decltype(&OpenSSL_free)>;
using BN_ptr            = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), decltype(&SK_X509_free)>;

/**
 * A convenience union for representing the kind of checksum returned, as
 * well as its actual digest data.
 */
using Checksum = std::tuple<uint32, std::string>;

inline static bool ASN1TIMEtoString(const ASN1_TIME* time, String& output)
{
    WrapperBIO out{ BIO_new(BIO_s_mem()) };
    CHECK(out.memory, false, "");

    ASN1_TIME_print(out.memory, time);
    BUF_MEM* buf{};
    BIO_get_mem_ptr(out.memory, &buf);
    CHECK(buf, false, "");

    CHECK(output.Set(buf->data, (uint32) buf->length), false, "");
    return true;
};

inline static void GetError(uint32& errorCode, String& output)
{
    errorCode = ERR_get_error();
    output.Set(ERR_error_string(errorCode, nullptr));
}

bool CMSToHumanReadable(const Buffer& buffer, String& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperCMS_ContentInfo cms{ d2i_CMS_bio(in.memory, nullptr) };
    GetError(error, output);
    CHECK(cms.data != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperBIO out{ BIO_new(BIO_s_mem()) };
    GetError(error, output);
    CHECK(out.memory != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperASN1_PCTX pctx{ ASN1_PCTX_new() };
    GetError(error, output);
    CHECK(pctx.data != nullptr, false, output.GetText());

    ASN1_PCTX_set_flags(pctx.data, ASN1_PCTX_FLAGS_SHOW_ABSENT);
    ASN1_PCTX_set_str_flags(pctx.data, ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_DUMP_ALL);
    ASN1_PCTX_set_oid_flags(pctx.data, 0);
    ASN1_PCTX_set_cert_flags(pctx.data, 0);

    ERR_clear_error();
    const auto ctxCode = CMS_ContentInfo_print_ctx(out.memory, cms.data, 4, pctx.data);
    GetError(error, output);
    CHECK(ctxCode == 1, false, output.GetText());

    BUF_MEM* buf{};
    ERR_clear_error();
    BIO_get_mem_ptr(out.memory, &buf);
    GetError(error, output);
    CHECK(output.Set(buf->data, (uint32) buf->length), false, "");

    return true;
}

bool CMSToPEMCerts(const Buffer& buffer, String output[32], uint32& count)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    count         = 1;
    auto& current = output[0];

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, current);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperCMS_ContentInfo cms{ d2i_CMS_bio(in.memory, nullptr) };
    GetError(error, current);
    CHECK(cms.data != nullptr, false, "");

    ERR_clear_error();
    WrapperSTACK_OF_X509 certs{ CMS_get1_certs(cms.data) };
    GetError(error, current);
    CHECK(certs.data != nullptr, false, "");

    count = static_cast<uint32>(sk_X509_num(certs.data));
    if (count >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (uint32 i = 0; i < count; i++)
    {
        auto& current = output[i];

        ERR_clear_error();
        const auto cert = sk_X509_value(certs.data, i);
        GetError(error, current);
        CHECK(cert != nullptr, false, "");

        ERR_clear_error();
        WrapperBIO bioCert{ BIO_new(BIO_s_mem()) };
        GetError(error, current);
        CHECK(bioCert.memory != nullptr, false, "");

        ERR_clear_error();
        const auto bioWrite = PEM_write_bio_X509(bioCert.memory, cert);
        GetError(error, current);
        CHECK(bioWrite == 1, false, "");

        BUF_MEM* buf{};
        ERR_clear_error();
        BIO_get_mem_ptr(bioCert.memory, &buf);
        GetError(error, current);
        CHECK(buf != nullptr, false, "");
        current.Set(buf->data, (uint32) buf->length);
    }

    return true;
}

bool CMSToStructure(const Buffer& buffer, SignatureMachO& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, output.errorMessage);

    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(),
          false,
          output.errorMessage.GetText());

    ERR_clear_error();
    WrapperCMS_ContentInfo cms{ d2i_CMS_bio(in.memory, nullptr) };
    GetError(error, output.errorMessage);
    CHECK(cms.data, false, output.errorMessage.GetText());

    output.isDetached = CMS_is_detached(cms.data);

    const ASN1_OBJECT* obj = CMS_get0_type(cms.data); // no need to free (pointer from CMS structure)
    output.sn              = OBJ_nid2ln(OBJ_obj2nid(obj));

    ERR_clear_error();
    ASN1_OCTET_STRING** pos = CMS_get0_content(cms.data); // no need to free (pointer from CMS structure)
    GetError(error, output.errorMessage);
    if (pos && (*pos))
    {
        output.snContent.Resize((*pos)->length);
        memcpy(output.snContent.GetData(), (*pos)->data, (*pos)->length);
    }

    ERR_clear_error();
    WrapperSTACK_OF_X509 certs{ CMS_get1_certs(cms.data) };
    GetError(error, output.errorMessage);
    CHECK(certs.data != nullptr, false, "");

    output.certificatesCount = sk_X509_num(certs.data);
    if (output.certificatesCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (auto i = 0U; i < output.certificatesCount; i++)
    {
        ERR_clear_error();
        const auto cert = sk_X509_value(certs.data, i);
        GetError(error, output.errorMessage);
        CHECK(cert != nullptr, false, "");

        auto& sigCert = output.certificates[i];

        sigCert.version = X509_get_version(cert);

        const auto serialNumber = X509_get_serialNumber(cert);
        if (serialNumber)
        {
            WrapperBIGNUM num{ ASN1_INTEGER_to_BN(serialNumber, nullptr) };
            if (num.data != nullptr)
            {
                const auto hex = BN_bn2hex(num.data);
                if (hex != nullptr)
                {
                    sigCert.serialNumber.Set(hex);
                    OPENSSL_free(hex);
                }
            }
        }

        sigCert.signatureAlgorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

        WrapperEVP_PKEY pubkey{ X509_get_pubkey(cert) };
        sigCert.publicKeyAlgorithm = OBJ_nid2ln(EVP_PKEY_id(pubkey.data));

        ASN1TIMEtoString(X509_get0_notBefore(cert), sigCert.validityNotBefore);
        ASN1TIMEtoString(X509_get0_notAfter(cert), sigCert.validityNotAfter);

        char* issues = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        if (issues != nullptr)
        {
            sigCert.issuer = issues;
            OPENSSL_free(issues);
            issues = nullptr;
        }

        char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        if (subject)
        {
            sigCert.subject = subject;
            OPENSSL_free(subject);
            subject = nullptr;
        }

        ERR_clear_error();
        WrapperEVP_PKEY pkey{ X509_get_pubkey(cert) };
        GetError(error, output.errorMessage);
        CHECK(pkey.data != nullptr, false, "");

        ERR_clear_error();
        sigCert.verify = X509_verify(cert, pkey.data);
        if (sigCert.verify != 1)
        {
            GetError(error, sigCert.errorVerify);
        }

        STACK_OF(CMS_SignerInfo)* siStack = CMS_get0_SignerInfos(cms.data); // no need to free (pointer from CMS structure)
        for (int32 i = 0; i < sk_CMS_SignerInfo_num(siStack); i++)
        {
            CMS_SignerInfo* si = sk_CMS_SignerInfo_value(siStack, i);
            ERR_clear_error();
            sigCert.signerVerify = CMS_SignerInfo_cert_cmp(si, cert);
            if (sigCert.signerVerify != 0)
            {
                GetError(error, sigCert.errorSignerVerify);
            }
            else
            {
                break;
            }
        }
    }

    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms.data);
    output.signersCount           = sk_CMS_SignerInfo_num(sis);
    if (output.signersCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of signers!");
    }
    for (int32 i = 0; i < sk_CMS_SignerInfo_num(sis); i++)
    {
        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(sis, i);
        auto& signer       = output.signers[i];

        signer.count = CMS_signed_get_attr_count(si);
        if ((uint32) signer.count >= MAX_SIZE_IN_CONTAINER && signer.count != ERR_SIGNER)
        {
            throw std::runtime_error("Unable to parse this number of signers!");
        }
        if (signer.count == ERR_SIGNER)
        {
            continue;
        }

        for (int32 j = 0; j < signer.count; j++)
        {
            X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, j); // no need to free (pointer from CMS structure)
            if (!attr)
            {
                continue;
            }

            auto& attribute = signer.attributes[j];

            attribute.count = X509_ATTRIBUTE_count(attr);
            if (attribute.count <= 0)
            {
                continue;
            }

            if ((uint32) attribute.count >= MAX_SIZE_IN_CONTAINER)
            {
                throw std::runtime_error("Unable to parse this number of attributes!");
            }

            ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr); // no need to free (pointer from CMS structure)
            if (!obj)
            {
                continue;
            }

            attribute.name = OBJ_nid2ln(OBJ_obj2nid(obj));

            auto objLen = OBJ_obj2txt(nullptr, -1, obj, 1) + 1;
            attribute.contentType.Realloc(objLen);
            OBJ_obj2txt(const_cast<char*>(attribute.contentType.GetText()), objLen, obj, 1);
            attribute.contentType.Realloc(objLen - 1);

            ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
            if (av == nullptr)
            {
                continue;
            }

            auto& asnType = attribute.types[j] = (ASN1TYPE) av->type;

            if (asnType == ASN1TYPE::OBJECT)
            {
                attribute.contentTypeData = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
            }
            else if (asnType == ASN1TYPE::OCTET_STRING)
            {
                LocalString<64> ls;
                for (int m = 0; m < av->value.octet_string->length; m++)
                {
                    ls.AddFormat("%02X", (uint8_t) av->value.octet_string->data[m]);
                }

                attribute.contentTypeData.Set(ls.GetText());
                attribute.CDHashes[j].Set(ls.GetText());
            }
            else if (asnType == ASN1TYPE::UTCTIME)
            {
                ERR_clear_error();
                WrapperBIO bio{ BIO_new(BIO_s_mem()) };
                GetError(error, output.errorMessage);
                CHECK(bio.memory != nullptr, false, "");

                ASN1_UTCTIME_print(bio.memory, av->value.utctime);
                BUF_MEM* bptr = nullptr; // no need to free (pointer from BIO structure)
                BIO_get_mem_ptr(bio.memory, &bptr);
                BIO_set_close(bio.memory, BIO_NOCLOSE);

                attribute.contentTypeData.Set(bptr->data, (uint32) bptr->length);
            }
            else if (asnType == ASN1TYPE::SEQUENCE)
            {
                for (int32 m = 0; m < attribute.count; m++)
                {
                    av = X509_ATTRIBUTE_get0_type(attr, m);
                    if (av != nullptr)
                    {
                        ERR_clear_error();
                        WrapperBIO in{ BIO_new(BIO_s_mem()) };
                        GetError(error, output.errorMessage);
                        CHECK(in.memory != nullptr, false, "");

                        ASN1_STRING* sequence = av->value.sequence;
                        attribute.types[m]    = (ASN1TYPE) av->type;
                        ASN1_parse_dump(in.memory, sequence->data, sequence->length, 2, 0);
                        BUF_MEM* buf = nullptr;
                        BIO_get_mem_ptr(in.memory, &buf);
                        BIO_set_close(in.memory, BIO_NOCLOSE);
                        attribute.contentTypeData.Set(buf->data, (uint32) buf->length);

                        auto& hash                             = attribute.CDHashes[m];
                        constexpr std::string_view startMarker = "[HEX DUMP]:";
                        if (attribute.contentTypeData.Contains(startMarker.data()))
                        {
                            if (attribute.contentTypeData.Contains("\n"))
                            {
                                std::string_view subString{ attribute.contentTypeData.GetText(), attribute.contentTypeData.Len() };

                                const auto indexStartMarker = subString.find(startMarker);
                                const auto indexNewLine     = subString.find('\n', indexStartMarker);
                                const auto newLength        = indexNewLine - indexStartMarker - startMarker.length();
                                subString                   = { subString.data() + indexStartMarker + startMarker.length(), newLength };

                                hash.Set(subString.data(), (uint32) subString.length());
                            }
                        }
                    }
                }
            }
            else
            {
                throw std::runtime_error("Unknown hash!");
            }
        }
    }

    output.error = false;

    return true;
}

typedef struct
{
    ASN1_OBJECT* type;
    ASN1_TYPE* value;
} Authenticode_SpcAttributeTypeAndOptionalValue;

typedef struct
{
    X509_ALGOR* digestAlgorithm;
    ASN1_OCTET_STRING* digest;
} Authenticode_DigestInfo;

typedef struct
{
    Authenticode_SpcAttributeTypeAndOptionalValue* data;
    Authenticode_DigestInfo* messageDigest;
} Authenticode_SpcIndirectDataContent;

/* Custom ASN.1 insanity is quarantined to the impl namespace.
 */

// clang-format off
ASN1_SEQUENCE(Authenticode_SpcAttributeTypeAndOptionalValue) = {
  ASN1_SIMPLE(Authenticode_SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
  ASN1_OPT(Authenticode_SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(Authenticode_SpcAttributeTypeAndOptionalValue)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(Authenticode_DigestInfo) = {
  ASN1_SIMPLE(Authenticode_DigestInfo, digestAlgorithm, X509_ALGOR),
  ASN1_SIMPLE(Authenticode_DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Authenticode_DigestInfo)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_DigestInfo)

ASN1_SEQUENCE(Authenticode_SpcIndirectDataContent) = {
  ASN1_SIMPLE(Authenticode_SpcIndirectDataContent, data, Authenticode_SpcAttributeTypeAndOptionalValue),
  ASN1_SIMPLE(Authenticode_SpcIndirectDataContent, messageDigest, Authenticode_DigestInfo)
} ASN1_SEQUENCE_END(Authenticode_SpcIndirectDataContent)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_SpcIndirectDataContent)

; // clang-format on

constexpr auto SPC_INDIRECT_DATA_OID    = "1.3.6.1.4.1.311.2.1.4";
constexpr auto SPC_NESTED_SIGNATURE_OID = "1.3.6.1.4.1.311.2.4.1";

bool PKCS7ToStructure(const Buffer& buffer, SignatureMachO& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, output.errorMessage);

    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(),
          false,
          output.errorMessage.GetText());

    ERR_clear_error();
    WrapperPKCS7 pkcs7{ d2i_PKCS7_bio(in.memory, nullptr) };
    GetError(error, output.errorMessage);
    CHECK(pkcs7.data != nullptr, false, output.errorMessage.GetText());

    output.isDetached = PKCS7_is_detached(pkcs7.data);

    ERR_clear_error();
    STACK_OF(X509) * certs{ nullptr };
    switch (OBJ_obj2nid(pkcs7.data->type))
    {
    case NID_pkcs7_signed:
        certs = pkcs7.data->d.sign->cert;
        break;
    case NID_pkcs7_signedAndEnveloped:
        certs = pkcs7.data->d.signed_and_enveloped->cert;
        break;
    }
    CHECK(certs != nullptr, false, "");

    output.certificatesCount = sk_X509_num(certs);
    if (output.certificatesCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (auto i = 0U; i < output.certificatesCount; i++)
    {
        ERR_clear_error();
        const auto cert = sk_X509_value(certs, i);
        GetError(error, output.errorMessage);
        CHECK(cert != nullptr, false, "");

        auto& sigCert = output.certificates[i];

        sigCert.version = X509_get_version(cert);

        const auto serialNumber = X509_get_serialNumber(cert);
        if (serialNumber)
        {
            WrapperBIGNUM num{ ASN1_INTEGER_to_BN(serialNumber, nullptr) };
            if (num.data != nullptr)
            {
                const auto hex = BN_bn2hex(num.data);
                if (hex != nullptr)
                {
                    sigCert.serialNumber.Set(hex);
                    OPENSSL_free(hex);
                }
            }
        }

        sigCert.signatureAlgorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

        WrapperEVP_PKEY pubkey{ X509_get_pubkey(cert) };
        sigCert.publicKeyAlgorithm = OBJ_nid2ln(EVP_PKEY_id(pubkey.data));

        ASN1TIMEtoString(X509_get0_notBefore(cert), sigCert.validityNotBefore);
        ASN1TIMEtoString(X509_get0_notAfter(cert), sigCert.validityNotAfter);

        char* issues = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        if (issues != nullptr)
        {
            sigCert.issuer = issues;
            OPENSSL_free(issues);
            issues = nullptr;
        }

        char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        if (subject)
        {
            sigCert.subject = subject;
            OPENSSL_free(subject);
            subject = nullptr;
        }

        ERR_clear_error();
        WrapperEVP_PKEY pkey{ X509_get_pubkey(cert) };
        GetError(error, output.errorMessage);
        CHECK(pkey.data != nullptr, false, "");

        ERR_clear_error();
        sigCert.verify = X509_verify(cert, pkey.data);
        if (sigCert.verify != 1)
        {
            GetError(error, sigCert.errorVerify);
        }

        STACK_OF(PKCS7_SIGNER_INFO)* siStack = PKCS7_get_signer_info(pkcs7.data); // no need to free (pointer from CMS structure)
        for (int32 i = 0; i < sk_PKCS7_SIGNER_INFO_num(siStack); i++)
        {
            PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(siStack, i);
            ERR_clear_error();

            auto spcIndirectDataOid = OBJ_get0_data(pkcs7.data->d.sign->contents->type);

            //
            // OID ASN.1 Value for SPC_INDIRECT_DATA_OBJID
            //
            uint8 mSpcIndirectOidValue[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 };

            if (OBJ_length(pkcs7.data->d.sign->contents->type) != sizeof(mSpcIndirectOidValue))
            {
                CHECK(memcmp(spcIndirectDataOid, mSpcIndirectOidValue, sizeof(mSpcIndirectOidValue)) == 0, false, "");
            }

            auto spcIndirectDataContent = (uint8*) (pkcs7.data->d.sign->contents->d.other->value.asn1_string->data);

            //
            // Retrieve the SEQUENCE data size from ASN.1-encoded SpcIndirectDataContent.
            //
            auto asn1Byte = *(spcIndirectDataContent + 1);
            uint32 contentSize{ 0 };
            if ((asn1Byte & 0x80) == 0)
            {
                //
                // Short Form of Length Encoding (Length < 128)
                //
                contentSize = (uint32) (asn1Byte & 0x7F);
                //
                // Skip the SEQUENCE Tag;
                //
                spcIndirectDataContent += 2;
            }
            else if ((asn1Byte & 0x81) == 0x81)
            {
                //
                // Long Form of Length Encoding (128 <= Length < 255, Single Octet)
                //
                contentSize = (uint32) (*(uint8*) (spcIndirectDataContent + 2));
                //
                // Skip the SEQUENCE Tag;
                //
                spcIndirectDataContent += 3;
            }
            else if ((asn1Byte & 0x82) == 0x82)
            {
                //
                // Long Form of Length Encoding (Length > 255, Two Octet)
                //
                contentSize = (uint32) (*(uint8*) (spcIndirectDataContent + 2));
                contentSize = (contentSize << 8) + (uint32) (*(uint8*) (spcIndirectDataContent + 3));
                //
                // Skip the SEQUENCE Tag;
                //
                spcIndirectDataContent += 4;
            }
            else
            {
                RETURNERROR(false, "");
            }

            WrapperBIO bbio{ BIO_new(BIO_s_mem()) };
            CHECK((size_t) BIO_write(bbio.memory, spcIndirectDataContent, contentSize) == contentSize,
                  false,
                  output.errorMessage.GetText());

            sigCert.signerVerify = PKCS7_verify(pkcs7.data, certs, nullptr, bbio.memory, nullptr, PKCS7_NOVERIFY);

            if (sigCert.signerVerify != 1)
            {
                GetError(error, sigCert.errorSignerVerify);
            }
        }
    }

    STACK_OF(PKCS7_SIGNER_INFO)* sis = PKCS7_get_signer_info(pkcs7.data);
    output.signersCount              = sk_PKCS7_SIGNER_INFO_num(sis);
    if (output.signersCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of signers!");
    }
    for (int32 i = 0; i < sk_PKCS7_SIGNER_INFO_num(sis); i++)
    {
        auto si      = sk_PKCS7_SIGNER_INFO_value(sis, i);
        auto& signer = output.signers[i];

        auto signedAttributes = PKCS7_get_signed_attributes(si);
        signer.count          = sk_X509_ATTRIBUTE_num(signedAttributes);
        if ((uint32) signer.count >= MAX_SIZE_IN_CONTAINER && signer.count != ERR_SIGNER)
        {
            throw std::runtime_error("Unable to parse this number of signers!");
        }
        if (signer.count == ERR_SIGNER)
        {
            continue;
        }

        for (int32 j = 0; j < signer.count; j++)
        {
            X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(signedAttributes, j); // no need to free (pointer from CMS structure)
            if (!attr)
            {
                continue;
            }

            auto& attribute = signer.attributes[j];

            attribute.count = X509_ATTRIBUTE_count(attr);
            if (attribute.count <= 0)
            {
                continue;
            }

            if ((uint32) attribute.count >= MAX_SIZE_IN_CONTAINER)
            {
                throw std::runtime_error("Unable to parse this number of attributes!");
            }

            ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr); // no need to free (pointer from CMS structure)
            if (!obj)
            {
                continue;
            }

            attribute.name = OBJ_nid2ln(OBJ_obj2nid(obj));

            auto objLen = OBJ_obj2txt(nullptr, -1, obj, 1) + 1;
            attribute.contentType.Realloc(objLen);
            OBJ_obj2txt(const_cast<char*>(attribute.contentType.GetText()), objLen, obj, 1);
            attribute.contentType.Realloc(objLen - 1);

            ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
            if (av == nullptr)
            {
                continue;
            }

            auto& asnType = attribute.types[j] = (ASN1TYPE) av->type;

            if (asnType == ASN1TYPE::OBJECT)
            {
                attribute.contentTypeData = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
            }
            else if (asnType == ASN1TYPE::OCTET_STRING)
            {
                LocalString<64> ls;
                for (int m = 0; m < av->value.octet_string->length; m++)
                {
                    ls.AddFormat("%02X", (uint8_t) av->value.octet_string->data[m]);
                }

                attribute.contentTypeData.Set(ls.GetText());
                attribute.CDHashes[j].Set(ls.GetText());
            }
            else if (asnType == ASN1TYPE::UTCTIME)
            {
                ERR_clear_error();
                WrapperBIO bio{ BIO_new(BIO_s_mem()) };
                GetError(error, output.errorMessage);
                CHECK(bio.memory != nullptr, false, "");

                ASN1_UTCTIME_print(bio.memory, av->value.utctime);
                BUF_MEM* bptr = nullptr; // no need to free (pointer from BIO structure)
                BIO_get_mem_ptr(bio.memory, &bptr);
                BIO_set_close(bio.memory, BIO_NOCLOSE);

                attribute.contentTypeData.Set(bptr->data, (uint32) bptr->length);
            }
            else if (asnType == ASN1TYPE::SEQUENCE)
            {
                for (int32 m = 0; m < attribute.count; m++)
                {
                    av = X509_ATTRIBUTE_get0_type(attr, m);
                    if (av != nullptr)
                    {
                        ERR_clear_error();
                        WrapperBIO in{ BIO_new(BIO_s_mem()) };
                        GetError(error, output.errorMessage);
                        CHECK(in.memory != nullptr, false, "");

                        ASN1_STRING* sequence = av->value.sequence;
                        attribute.types[m]    = (ASN1TYPE) av->type;
                        ASN1_parse_dump(in.memory, sequence->data, sequence->length, 2, 0);
                        BUF_MEM* buf = nullptr;
                        BIO_get_mem_ptr(in.memory, &buf);
                        BIO_set_close(in.memory, BIO_NOCLOSE);
                        attribute.contentTypeData.Set(buf->data, (uint32) buf->length);

                        auto& hash                             = attribute.CDHashes[m];
                        constexpr std::string_view startMarker = "[HEX DUMP]:";
                        if (attribute.contentTypeData.Contains(startMarker.data()))
                        {
                            if (attribute.contentTypeData.Contains("\n"))
                            {
                                std::string_view subString{ attribute.contentTypeData.GetText(), attribute.contentTypeData.Len() };

                                const auto indexStartMarker = subString.find(startMarker);
                                const auto indexNewLine     = subString.find('\n', indexStartMarker);
                                const auto newLength        = indexNewLine - indexStartMarker - startMarker.length();
                                subString                   = { subString.data() + indexStartMarker + startMarker.length(), newLength };

                                hash.Set(subString.data(), (uint32) subString.length());
                            }
                        }
                    }
                }
            }
        }
    }

    output.error = false;

    return true;
}

Authenticode_SpcIndirectDataContent* GetIndirectDataContent(const WrapperPKCS7& p7)
{
    auto* contents = p7.data->d.sign->contents;
    CHECK(contents != nullptr, nullptr, "");

    OBJ_create(SPC_INDIRECT_DATA_OID, NULL, NULL);
    auto* indirectDataASN1Raw = OBJ_txt2obj(SPC_INDIRECT_DATA_OID, 1);
    CHECK(indirectDataASN1Raw != nullptr, nullptr, "");

    ASN1_OBJECT_ptr indirectDataASN1(indirectDataASN1Raw, ASN1_OBJECT_free);
    CHECK(ASN1_TYPE_get(contents->d.other) == V_ASN1_SEQUENCE, nullptr, "");
    CHECK(OBJ_cmp(contents->type, indirectDataASN1.get()) == 0, nullptr, "");

    const auto* data          = contents->d.other->value.sequence->data;
    auto* indirectDataContent = d2i_Authenticode_SpcIndirectDataContent(nullptr, &data, contents->d.other->value.sequence->length);
    CHECK(indirectDataContent != nullptr, nullptr, "");
    CHECK(indirectDataContent->messageDigest->digest->data != nullptr, nullptr, "");
    CHECK(indirectDataContent->messageDigest->digest->length < contents->d.other->value.sequence->length, nullptr, "");

    return indirectDataContent;
}

bool GetNestedSignedData(WrapperPKCS7& p7, Buffer& buffer)
{
    PKCS7_SIGNER_INFO* signer_info = sk_PKCS7_SIGNER_INFO_value(p7.data->d.sign->signer_info, 0);

    /* NOTE(ww): OpenSSL stupidity: you actually need to call OBJ_create before
     * OBJ_txt2obj; the latter won't do it for you. Luckily (?) OpenSSL 1.1.0+
     * auto-frees these, so they're not totally impossible to use in leakless C++.
     */
    OBJ_create(SPC_NESTED_SIGNATURE_OID, NULL, NULL);
    auto* spc_nested_sig_oid_ptr = OBJ_txt2obj(SPC_NESTED_SIGNATURE_OID, 1);
    CHECK(spc_nested_sig_oid_ptr != nullptr, false, "");

    ASN1_OBJECT_ptr spc_nested_sig_oid(spc_nested_sig_oid_ptr, ASN1_OBJECT_free);
    auto* nested_signed_data = PKCS7_get_attribute(signer_info, OBJ_obj2nid(spc_nested_sig_oid.get()));
    CHECK(nested_signed_data != nullptr, false, "");
    CHECK(ASN1_TYPE_get(nested_signed_data) == V_ASN1_SEQUENCE, false, "");

    auto* nested_signed_data_seq = nested_signed_data->value.sequence;
    CHECK(buffer.Add(BufferView{ nested_signed_data_seq->data, (size_t) nested_signed_data_seq->length }), false, "");

    return true;
}

static inline std::string ToHex(std::uint8_t* buf, std::size_t len)
{
    CHECK(buf != nullptr, std::string{}, "");
    CHECK(len > 0, std::string{}, "");

    constexpr static char lookup_table[] = "0123456789ABCDEF";

    std::string hexstr;
    hexstr.reserve(len * 2); // each byte creates two hex digits

    for (auto i = 0; i < len; i++)
    {
        hexstr += lookup_table[buf[i] >> 4];
        hexstr += lookup_table[buf[i] & 0xF];
    }

    return hexstr;
}

Checksum GetChecksum(Authenticode_SpcIndirectDataContent& indirectData)
{
    auto nid    = OBJ_obj2nid(indirectData.messageDigest->digestAlgorithm->algorithm);
    auto digest = ToHex(indirectData.messageDigest->digest->data, indirectData.messageDigest->digest->length);
    return std::make_tuple(nid, digest);
}

std::string ComputeChecksum(
      uint32 algorithmNID,
      Utils::DataCache& cache,
      uint32 checksumOffset,
      uint32 certificateTableOffset,
      uint32 sizeOfHeaders,
      uint32 sVA,
      uint32 sSize)
{
    // https://security.stackexchange.com/questions/199599/are-all-fields-of-the-pe-certificate-directory-hashed-during-authenticode-signin
    // https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx

    const auto* md = EVP_get_digestbynid(algorithmNID);
    auto* md_ctx   = EVP_MD_CTX_new();
    EVP_DigestInit(md_ctx, md);

    Buffer _1st = cache.CopyToBuffer(0, checksumOffset);
    EVP_DigestUpdate(md_ctx, _1st.GetData(), _1st.GetLength());

    Buffer _2nd = cache.CopyToBuffer(checksumOffset + 4, certificateTableOffset - (checksumOffset + 4));
    EVP_DigestUpdate(md_ctx, _2nd.GetData(), _2nd.GetLength());

    Buffer _3rd = cache.CopyToBuffer(certificateTableOffset + 8, sizeOfHeaders - (certificateTableOffset + 8));
    EVP_DigestUpdate(md_ctx, _3rd.GetData(), _3rd.GetLength());

    if (sVA > 0)
    {
        Buffer _4th = cache.CopyToBuffer(sizeOfHeaders, sVA - sizeOfHeaders);
        EVP_DigestUpdate(md_ctx, _4th.GetData(), _4th.GetLength());

        Buffer _5th = cache.CopyToBuffer(sVA + sSize, static_cast<uint32>(cache.GetSize()) - (sVA + sSize));
        EVP_DigestUpdate(md_ctx, _5th.GetData(), _5th.GetLength());
    }
    else
    {
        Buffer _4th = cache.CopyToBuffer(sizeOfHeaders, static_cast<uint32>(cache.GetSize()) - sizeOfHeaders);
        EVP_DigestUpdate(md_ctx, _4th.GetData(), _4th.GetLength());
    }

    std::vector<uint8> md_buf;
    md_buf.resize(EVP_MAX_MD_SIZE);
    EVP_DigestFinal(md_ctx, md_buf.data(), nullptr);
    EVP_MD_CTX_free(md_ctx);

    return ToHex(md_buf.data(), EVP_MD_size(md));
}

bool PKCS7VerifySignature(
      const WrapperPKCS7& pkcs7,
      Utils::DataCache& cache,
      uint32 checksumOffset,
      uint32 certificateTableOffset,
      uint32 sizeOfHeaders,
      uint32 sVA,
      uint32 sSize)
{
    Buffer b = cache.CopyEntireFile(true);
    Authenticode::AuthenticodeParser parser;
    parser.AuthenticodeParse(b.GetData(), b.GetLength());

    STACK_OF(X509)* certs = nullptr;
    switch (OBJ_obj2nid(pkcs7.data->type))
    {
    case NID_pkcs7_signed:
        certs = pkcs7.data->d.sign->cert;
        break;
    case NID_pkcs7_signedAndEnveloped:
        certs = pkcs7.data->d.signed_and_enveloped->cert;
        break;
    }

    CHECK(certs != nullptr, false, "");

    auto indirectData      = GetIndirectDataContent(pkcs7);
    uint8* indirectDataRaw = nullptr;
    auto indirectDataSize  = i2d_Authenticode_SpcIndirectDataContent(indirectData, &indirectDataRaw);

    CHECK(indirectDataSize >= 0, false, "");
    CHECK(indirectDataRaw != nullptr, false, "");

    auto indirectDataPtr = OpenSSL_ptr(reinterpret_cast<char*>(indirectDataRaw), OpenSSL_free);

    const auto* signedDataSeq = reinterpret_cast<std::uint8_t*>(indirectDataPtr.get());
    long length               = 0;
    int tag                   = 0;
    int tagClass              = 0;
    ASN1_get_object(&signedDataSeq, &length, &tag, &tagClass, indirectDataSize);
    CHECK(tag == V_ASN1_SEQUENCE, false, "");

    BIO_ptr signedData(BIO_new_mem_buf(signedDataSeq, length), BIO_free);
    CHECK(signedData != nullptr, false, "");

    auto status = PKCS7_verify(pkcs7.data, certs, nullptr, signedData.get(), nullptr, PKCS7_NOVERIFY);
    CHECK(status == 1, false, "");

    // authenticode hash verification (embedded vs computed)
    const auto embeddedChecksum = GetChecksum(*indirectData);
    const auto computedChecksum =
          ComputeChecksum(std::get<0>(embeddedChecksum), cache, checksumOffset, certificateTableOffset, sizeOfHeaders, sVA, sSize);
    CHECK(std::get<1>(embeddedChecksum) == computedChecksum, false, "");

    // timestamp / counter signature
    STACK_OF(PKCS7_SIGNER_INFO)* sis = PKCS7_get_signer_info(pkcs7.data);
    const auto signersCount          = sk_PKCS7_SIGNER_INFO_num(sis);
    if (signersCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of signers!");
    }

    for (int32 i = 0; i < signersCount; i++)
    {
        PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(sis, i);

        const ASN1_OBJECT_ptr RFC3161_counterSign(OBJ_txt2obj("1.3.6.1.4.1.311.3.3.1", 1), ASN1_OBJECT_free);
        const ASN1_OBJECT_ptr RSA_counterSign(OBJ_txt2obj("1.2.840.113549.1.9.6", 1), ASN1_OBJECT_free);
        const ASN1_OBJECT_ptr NestedSignature(OBJ_txt2obj("1.3.6.1.4.1.311.2.4.1", 1), ASN1_OBJECT_free);

        STACK_OF(X509_ATTRIBUTE)* unauth_attr = si->unauth_attr;
        const auto unauthAttributesCount      = X509at_get_attr_count(unauth_attr);
        for (int32 i = 0; i < unauthAttributesCount; i++)
        {
            auto attribute = X509at_get_attr(unauth_attr, i);
            auto count     = X509_ATTRIBUTE_count(attribute);
            auto asn1Type  = X509_ATTRIBUTE_get0_type(attribute, i);
            if (count != 1)
            {
                throw std::runtime_error("Unsupported number of attributes!");
            }

            ASN1_OBJECT_ptr attributeObject(X509_ATTRIBUTE_get0_object(attribute), ASN1_OBJECT_free);

            // https://mta.openssl.org/pipermail/openssl-users/2015-September/002054.html
            if (OBJ_cmp(attributeObject.get(), RSA_counterSign.get()) == 0)
            {
                if (V_ASN1_SEQUENCE == asn1Type->type)
                {
                    ERR_clear_error();
                    WrapperBIO in{ BIO_new(BIO_s_mem()) };
                    CHECK(in.memory != nullptr, false, "");

                    const auto* data      = asn1Type->value.octet_string->data;
                    const auto length     = asn1Type->value.octet_string->length;
                    PKCS7_SIGNER_INFO* cs = d2i_PKCS7_SIGNER_INFO(NULL, &data, length);

                    auto aaa = OBJ_obj2nid(attributeObject.get());

                    STACK_OF(X509_ATTRIBUTE)* auth2 = cs->auth_attr;
                    const auto auth2Count           = X509at_get_attr_count(auth2);
                    for (int32 aa = 0; aa < auth2Count; aa++)
                    {
                        auto attribute = X509at_get_attr(auth2, aa);
                        auto count     = X509_ATTRIBUTE_count(attribute);
                        auto asn1Type  = X509_ATTRIBUTE_get0_type(attribute, aa);

                        ASN1_OBJECT_ptr attributeObject2(X509_ATTRIBUTE_get0_object(attribute), ASN1_OBJECT_free);
                        if (asn1Type == nullptr)
                        {
                            continue;
                        }
                        if (V_ASN1_OBJECT == asn1Type->type)
                        {
                            auto obj   = asn1Type->value.object;
                            auto name3 = OBJ_nid2sn(OBJ_obj2nid(obj));

                            ASN1_OBJECT* attrData = (ASN1_OBJECT*) X509_ATTRIBUTE_get0_data(attribute, aa, asn1Type->type, NULL);

                            int len     = i2t_ASN1_OBJECT(NULL, 0, attrData);
                            char* value = (char*) calloc(len, sizeof(char));
                            i2t_ASN1_OBJECT(value, len, attrData);

                            X509* cert = PKCS7_cert_from_signer_info(pkcs7.data, cs);

                            // TODO: and now what?
                        }
                    }
                }
            }

            if (OBJ_cmp(attributeObject.get(), RFC3161_counterSign.get()) == 0)
            {
                if (V_ASN1_SEQUENCE == asn1Type->type)
                {
                    const auto* data  = asn1Type->value.octet_string->data;
                    const auto length = asn1Type->value.octet_string->length;

                    String output;

                    WrapperBIO in{ BIO_new(BIO_s_mem()) };
                    CHECK((size_t) BIO_write(in.memory, data, (int32) length) == length, false, "");

                    WrapperCMS_ContentInfo cms{ d2i_CMS_bio(in.memory, nullptr) };
                    CHECK(cms.data != nullptr, false, "");

                    constexpr uint32 flags = CMS_BINARY | CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY;
                    CHECK(CMS_verify(cms.data, certs, NULL, NULL, NULL, flags) == 1, false, "");
                }
            }

            if (OBJ_cmp(attributeObject.get(), NestedSignature.get()) == 0)
            {
                // TODO: anything?
            }
        }
    }

    return true;
}

bool PKCS7VerifySignature(
      Utils::DataCache& cache,
      const Buffer& buffer,
      String& output,
      uint32 checksumOffset,
      uint32 certificateTableOffset,
      uint32 sizeOfHeaders,
      uint32 sVA,
      uint32 sSize)
{
    /*
     * with help from:
     * https://stackoverflow.com/questions/50976612/amended-code-to-retrieve-dual-signature-information-from-pe-executable-in-window
     * https://github.com/trailofbits/uthenticode/blob/master/src/uthenticode.cpp
     * https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows
     */

    CHECK(buffer.GetData() != nullptr, false, "Nullptr data provided!");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    CHECK(sVA + sSize <= cache.GetSize(), false, "");
    CHECK(certificateTableOffset + 8 <= sizeOfHeaders, false, "");

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperPKCS7 pkcs7{ d2i_PKCS7_bio(in.memory, nullptr) };
    GetError(error, output);
    CHECK(pkcs7.data != nullptr, false, output.GetText());

    CHECK(PKCS7VerifySignature(pkcs7, cache, checksumOffset, certificateTableOffset, sizeOfHeaders, sVA, sSize), false, "");

    Buffer bufferNested;
    auto nested_data = GetNestedSignedData(pkcs7, bufferNested);
    if (bufferNested.IsValid())
    {
        return PKCS7VerifySignature(cache, bufferNested, output, checksumOffset, certificateTableOffset, sizeOfHeaders, sVA, sSize);
    }

    return true;
}

bool PKCS7ToHumanReadable(const Buffer& buffer, String& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in{ BIO_new(BIO_s_mem()) };
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperPKCS7 pkcs7{ d2i_PKCS7_bio(in.memory, nullptr) };
    GetError(error, output);
    CHECK(pkcs7.data != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperBIO out{ BIO_new(BIO_s_mem()) };
    GetError(error, output);
    CHECK(out.memory != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperASN1_PCTX pctx{ ASN1_PCTX_new() };
    GetError(error, output);
    CHECK(pctx.data != nullptr, false, output.GetText());

    ASN1_PCTX_set_flags(pctx.data, ASN1_PCTX_FLAGS_SHOW_ABSENT);
    ASN1_PCTX_set_str_flags(pctx.data, ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_DUMP_ALL);
    ASN1_PCTX_set_oid_flags(pctx.data, 0);
    ASN1_PCTX_set_cert_flags(pctx.data, 0);

    ERR_clear_error();
    const auto ctxCode = PKCS7_print_ctx(out.memory, pkcs7.data, 4, pctx.data);
    GetError(error, output);
    CHECK(ctxCode == 1, false, output.GetText());

    BUF_MEM* buf{};
    ERR_clear_error();
    BIO_get_mem_ptr(out.memory, &buf);
    GetError(error, output);
    CHECK(output.Set(buf->data, (uint32) buf->length), false, "");

    ERR_clear_error();
    const auto type = OBJ_obj2nid(pkcs7.data->type);
    STACK_OF(X509) * certs{ nullptr };
    STACK_OF(X509_CRL) * crls{ nullptr };
    switch (type)
    {
    case NID_pkcs7_signed:
        certs = pkcs7.data->d.sign->cert;
        crls  = pkcs7.data->d.sign->crl;
        break;
    case NID_pkcs7_signedAndEnveloped:
        certs = pkcs7.data->d.signed_and_enveloped->cert;
        crls  = pkcs7.data->d.signed_and_enveloped->crl;
        break;
    }
    CHECK(certs != nullptr, false, "");

    // STACK_OF(X509) * cert;          /* [ 0 ] */
    auto certificatesCount = sk_X509_num(certs);
    if (certificatesCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (int32 i = 0; i < certificatesCount; i++)
    {
        ERR_clear_error();
        const auto cert = sk_X509_value(certs, i);
        GetError(error, output);
        CHECK(cert != nullptr, false, "");

        WrapperBIO out{ BIO_new(BIO_s_mem()) };
        GetError(error, output);
        CHECK(out.memory != nullptr, false, output.GetText());
        X509_print_ex(out.memory, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);

        BUF_MEM* buf{};
        ERR_clear_error();
        BIO_get_mem_ptr(out.memory, &buf);
        GetError(error, output);
        CHECK(output.Set(buf->data, (uint32) buf->length), false, "");
    }

    auto crlsCount = sk_X509_CRL_num(crls);
    if (crlsCount == 0xFFFFFFFF || crls == nullptr)
    {
        crlsCount = 0;
    }
    if (crlsCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (int32 i = 0; i < crlsCount; i++)
    {
        ERR_clear_error();
        const auto cert = sk_X509_CRL_value(crls, i);
        GetError(error, output);
        CHECK(cert != nullptr, false, "");

        WrapperBIO out{ BIO_new(BIO_s_mem()) };
        GetError(error, output);
        CHECK(out.memory != nullptr, false, output.GetText());
        X509_CRL_print_ex(out.memory, cert, XN_FLAG_COMPAT);

        BUF_MEM* buf{};
        ERR_clear_error();
        BIO_get_mem_ptr(out.memory, &buf);
        GetError(error, output);
        CHECK(output.Set(buf->data, (uint32) buf->length), false, "");
    }

    STACK_OF(PKCS7_SIGNER_INFO)* sis = PKCS7_get_signer_info(pkcs7.data);
    const auto signersCount          = sk_PKCS7_SIGNER_INFO_num(sis);
    if (signersCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of signers!");
    }
    for (int32 i = 0; i < signersCount; i++)
    {
        PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(sis, i);

        ASN1_INTEGER* version                      = si->version;
        PKCS7_ISSUER_AND_SERIAL* issuer_and_serial = si->issuer_and_serial;
        X509_ALGOR* digest_alg                     = si->digest_alg;
        STACK_OF(X509_ATTRIBUTE)* auth_attr        = si->auth_attr;
        X509_ALGOR* digest_enc_alg                 = si->digest_alg;
        ASN1_OCTET_STRING* enc_digest              = si->enc_digest;
        STACK_OF(X509_ATTRIBUTE)* unauth_attr      = si->unauth_attr;

        BIGNUM* versionBigNum = ASN1_INTEGER_to_BN(version, NULL);
        char* versionHex      = BN_bn2hex(versionBigNum);

        BIGNUM* serialBigNum = ASN1_INTEGER_to_BN(issuer_and_serial->serial, NULL);
        char* serialHex      = BN_bn2hex(serialBigNum);

        const auto issuer = X509_NAME_oneline(issuer_and_serial->issuer, 0, 0);

        char algorithm[20]{ 0 };
        int res = OBJ_obj2txt(algorithm, sizeof algorithm, digest_alg->algorithm, 0);

        std::string algorithmValue;
        switch (digest_alg->parameter->type)
        {
        case V_ASN1_NULL:
            break;
        default:
            throw std::runtime_error("Unsupported value type!");
        }

        std::vector<std::string> authAttrs;
        const auto authAttributesCount = X509at_get_attr_count(auth_attr);
        for (int32 i = 0; i < authAttributesCount; i++)
        {
            auto attribute      = X509at_get_attr(auth_attr, i);
            auto attributeCount = X509_ATTRIBUTE_count(attribute);
            if (attributeCount != 1)
            {
                throw std::runtime_error("Unsupported number of attributes!");
            }

            const auto attributeObject = X509_ATTRIBUTE_get0_object(attribute);

            const auto count = OBJ_obj2txt(nullptr, 0, attributeObject, 0);
            auto& s          = authAttrs.emplace_back();
            s.resize(count + 1ULL);
            OBJ_obj2txt(s.data(), count + 1, attributeObject, 0);
        }

        std::vector<std::string> unauthAttrs;
        const auto unauthAttributesCount = X509at_get_attr_count(unauth_attr);
        for (int32 i = 0; i < unauthAttributesCount; i++)
        {
            auto attribute      = X509at_get_attr(unauth_attr, i);
            auto attributeCount = X509_ATTRIBUTE_count(attribute);
            if (attributeCount != 1)
            {
                throw std::runtime_error("Unsupported number of attributes!");
            }

            const auto attributeObject = X509_ATTRIBUTE_get0_object(attribute);

            const auto count = OBJ_obj2txt(nullptr, 0, attributeObject, 0);
            auto& s          = unauthAttrs.emplace_back();
            s.resize(count + 1ULL);
            OBJ_obj2txt(s.data(), count + 1, attributeObject, 0);
        }
    }

    return true;
}

#ifdef BUILD_FOR_WINDOWS

#    include <Windows.h>
#    include <Softpub.h>
#    include <wincrypt.h>
#    include <wintrust.h>

// Link with the Wintrust.lib file.
#    pragma comment(lib, "wintrust")

// Link with the Crypt32.lib file.
#    pragma comment(lib, "Crypt32")

inline void SetErrorMessage(uint32 errorCode, String& message)
{
    std::string m;
    m.resize(1024);
    const auto length = FormatMessageA(
          FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
          NULL,
          errorCode,
          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
          (LPSTR) m.data(),
          (DWORD) m.size(),
          NULL);
    m.resize(length);

    if (length > 1 && length < 1024)
    {
        for (auto i = 2ULL; i < 4; i++)
        {
            auto a = m[length - i];
            if (m[length - i] == '\r' || m[length - i] == '\n')
            {
                m[length - i] = 0;
            }
        }
    }

    message.Set(m.c_str());
}

bool __VerifyEmbeddedSignature__(ConstString source, SignatureMZPE& data)
{
    LocalUnicodeStringBuilder<1024> ub;
    ub.Set(source);
    std::u16string sv{ ub.GetString(), ub.Len() };

    WINTRUST_FILE_INFO fileData{ .cbStruct       = sizeof(WINTRUST_FILE_INFO),
                                 .pcwszFilePath  = reinterpret_cast<LPCWSTR>(sv.data()),
                                 .hFile          = nullptr,
                                 .pgKnownSubject = nullptr };
    WINTRUST_DATA WinTrustData{ .cbStruct            = sizeof(WinTrustData),
                                .pPolicyCallbackData = nullptr,
                                .pSIPClientData      = nullptr,
                                .dwUIChoice          = WTD_UI_NONE,
                                .fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                                .dwUnionChoice       = WTD_CHOICE_FILE,
                                .pFile               = &fileData,
                                .dwStateAction       = WTD_STATEACTION_VERIFY,
                                .hWVTStateData       = nullptr,
                                .pwszURLReference    = nullptr,
                                .dwUIContext         = 0 };

    GUID WVTPolicyGUID      = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.winTrust.errorCode = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
    SetErrorMessage(data.winTrust.errorCode, data.winTrust.errorMessage);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return true;
}

#    define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

struct WrapperCertContext
{
    PCCERT_CONTEXT context = NULL;
    ~WrapperCertContext()
    {
        if (context != NULL)
        {
            CertFreeCertificateContext(context);
        }
    }
};

struct WrapperSignerInfo
{
    PCMSG_SIGNER_INFO info = NULL;
    ~WrapperSignerInfo()
    {
        if (info != NULL)
        {
            LocalFree(info);
        }
    }
};

struct WrapperHStore
{
    HCERTSTORE handle = NULL;
    ~WrapperHStore()
    {
        if (handle != NULL)
        {
            CertCloseStore(handle, 0);
        }
    }
};

struct WrapperHMsg
{
    HCRYPTMSG handle = NULL;
    ~WrapperHMsg()
    {
        if (handle != NULL)
        {
            CryptMsgClose(handle);
        }
    }
};

BOOL GetOpusInfo(PCMSG_SIGNER_INFO pSignerInfo, SignatureMZPE::Information::Certificate& certificate);
BOOL GetCertDate(const WrapperSignerInfo& signerInfo, SignatureMZPE::Information::Certificate& certificate);
BOOL GetCertificateInfo(
      const WrapperSignerInfo& signerInfo, const WrapperCertContext& certContext, SignatureMZPE::Information::Certificate& certificate);
BOOL GetCounterSigner(
      const WrapperSignerInfo& signer, WrapperSignerInfo& counterSigner, WrapperHStore& storeCounterSigner, CounterSignatureType& type);
BOOL Get2ndSignature(const WrapperSignerInfo& signer, SignatureMZPE::Information& info);

bool GetSignaturesInformation(ConstString source, SignatureMZPE& data)
{
    LocalUnicodeStringBuilder<1024> ub;
    ub.Set(source);
    std::u16string sv{ ub.GetString(), ub.Len() };

    WrapperHStore hStore{};
    WrapperHMsg hMsg{};
    CHECK(CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                sv.data(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                NULL,
                NULL,
                NULL,
                &hStore.handle,
                &hMsg.handle,
                NULL),
          false,
          "");

    DWORD dwCountSigners = 0;
    DWORD dwcbSz         = sizeof(dwCountSigners);
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, &dwCountSigners, &dwcbSz), false, "");
    CHECK(dwCountSigners > 0, false, "");

    DWORD dwSignerInfo{ 0 };
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo), false, "");

    WrapperSignerInfo signerInfo{ .info = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo) };
    CHECK(signerInfo.info != nullptr, false, "");

    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signerInfo.info, &dwSignerInfo), false, "");

    auto& signature0 = data.info.signatures.emplace_back();

    CHECK(GetOpusInfo(signerInfo.info, signature0), false, "");
    CHECK(GetCertDate(signerInfo, signature0), false, "");

    CERT_INFO certInfo{ .SerialNumber = signerInfo.info->SerialNumber, .Issuer = signerInfo.info->Issuer };

    WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                          hStore.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };
    CHECK(certContext.context != nullptr, false, "");

    signature0.signatureType = SignatureType::Signature;
    CHECK(GetCertificateInfo(signerInfo, certContext, signature0), false, "");

    WrapperSignerInfo counterSignerInfo{};
    WrapperHStore storeCounterSigner{};
    WrapperCertContext counterSignerCertContext{};
    CounterSignatureType counterSignatureType{ CounterSignatureType::None };
    if (GetCounterSigner(signerInfo, counterSignerInfo, storeCounterSigner, counterSignatureType))
    {
        if (counterSignerInfo.info != nullptr)
        {
            auto& counterSignature0                = data.info.signatures.emplace_back();
            counterSignature0.counterSignatureType = counterSignatureType;

            certInfo.Issuer       = counterSignerInfo.info->Issuer;
            certInfo.SerialNumber = counterSignerInfo.info->SerialNumber;

            const auto& scHandle = storeCounterSigner.handle != 0 ? storeCounterSigner.handle : hStore.handle;

            WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                                  scHandle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };

            CHECK(certContext.context != nullptr, false, "");

            GetCertificateInfo(counterSignerInfo, certContext, counterSignature0);
            GetCertDate(counterSignerInfo, counterSignature0);
            GetOpusInfo(counterSignerInfo.info, counterSignature0);
            counterSignature0.signatureType = SignatureType::CounterSignature;
        }
    }

    Get2ndSignature(signerInfo, data.info);

    return 0;
}

BOOL GetNameString(const WrapperCertContext& certContext, String& out, DWORD type, DWORD flag)
{
    const auto size = CertGetNameStringA(certContext.context, type, flag, NULL, NULL, 0);
    std::unique_ptr<char> name(new char[size]);
    CHECK(CertGetNameStringA(certContext.context, type, flag, NULL, (LPSTR) name.get(), size) == size, false, "");
    CHECK(out.Set(name.get()), false, "");

    return true;
}

BOOL GetCertificateInfo(
      const WrapperSignerInfo& signerInfo, const WrapperCertContext& certContext, SignatureMZPE::Information::Certificate& certificate)
{
    LocalString<1024> ls;
    const auto serialNumberSize = certContext.context->pCertInfo->SerialNumber.cbData;
    for (DWORD n = 0; n < serialNumberSize; n++)
    {
        ls.AddFormat("%02x", certContext.context->pCertInfo->SerialNumber.pbData[serialNumberSize - (n + 1)]);
    }
    certificate.serialNumber.Set(ls);

    CHECK(GetNameString(certContext, certificate.issuer, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG), false, "");
    CHECK(GetNameString(certContext, certificate.subject, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0), false, "");
    CHECK(GetNameString(certContext, certificate.email, CERT_NAME_EMAIL_TYPE, 0), false, "");

    const auto& digestAlgorithm = signerInfo.info->HashAlgorithm;
    if (digestAlgorithm.pszObjId)
    {
        PCCRYPT_OID_INFO pCOI = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, digestAlgorithm.pszObjId, 0);
        if (pCOI)
        {
            if (pCOI->pwszName)
            {
                certificate.digestAlgorithm.Set(u16string_view{ reinterpret_cast<const char16_t*>(pCOI->pwszName) });
            }
            else
            {
                const auto algorithmName = CertAlgIdToOID(pCOI->Algid);
                if (algorithmName)
                {
                    certificate.digestAlgorithm.Set(reinterpret_cast<const char*>(algorithmName));
                }
            }
        }
    }

    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    SYSTEMTIME st{ 0 };

    const auto& dateNotAfter = certContext.context->pCertInfo->NotAfter;
    FileTimeToSystemTime(&dateNotAfter, &st);
    certificate.dateNotAfter.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    const auto& dateNotBefore = certContext.context->pCertInfo->NotBefore;
    FileTimeToSystemTime(&dateNotBefore, &st);
    certificate.dateNotBefore.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    return true;
}

BOOL GetOpusInfo(PCMSG_SIGNER_INFO signerInfo, SignatureMZPE::Information::Certificate& certificate)
{
    for (auto n = 0U; n < signerInfo->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, signerInfo->AuthAttrs.rgAttr[n].pszObjId) != 0)
        {
            continue;
        }

        DWORD size{ 0 };
        CHECK(CryptDecodeObject(
                    ENCODING,
                    SPC_SP_OPUS_INFO_OBJID,
                    signerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    signerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    NULL,
                    &size),
              false,
              "");

        std::unique_ptr<char> opusInfoBuffer(new char[size]);
        auto opusInfoRaw = (PSPC_SP_OPUS_INFO) opusInfoBuffer.get();
        CHECK(opusInfoRaw != nullptr, false, "");

        CHECK(CryptDecodeObject(
                    ENCODING,
                    SPC_SP_OPUS_INFO_OBJID,
                    signerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    signerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    opusInfoRaw,
                    &size),
              false,
              "");

        if (opusInfoRaw->pwszProgramName)
        {
            certificate.programName.Set(std::u16string_view{ reinterpret_cast<const char16_t*>(opusInfoRaw->pwszProgramName) });
        }

        constexpr auto populate = [](const SPC_LINK_* link, String& out)
        {
            CHECKRET(link != nullptr, "");
            switch (link->dwLinkChoice)
            {
            case SPC_URL_LINK_CHOICE:
                out.Set(std::u16string_view{ reinterpret_cast<char16_t*>(link->pwszUrl) });
                break;

            case SPC_FILE_LINK_CHOICE:
                out.Set(std::u16string_view{ reinterpret_cast<char16_t*>(link->pwszFile) });
                break;

            default:
                break;
            }
        };

        populate(opusInfoRaw->pPublisherInfo, certificate.publishLink);
        populate(opusInfoRaw->pMoreInfo, certificate.moreInfoLink);

        break;
    }

    return true;
}

BOOL GetCertDate(const WrapperSignerInfo& signer, SignatureMZPE::Information::Certificate& certificate)
{
    for (DWORD n = 0; n < signer.info->AuthAttrs.cAttr; n++)
    {
        PCCRYPT_OID_INFO pCOI = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, signer.info->AuthAttrs.rgAttr[n].pszObjId, 0);

        if (lstrcmpA(szOID_RSA_signingTime, signer.info->AuthAttrs.rgAttr[n].pszObjId) != 0)
        {
            continue;
        }

        FILETIME ft{ 0 };
        DWORD size = sizeof(ft);
        CHECK(CryptDecodeObject(
                    ENCODING,
                    szOID_RSA_signingTime,
                    signer.info->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    signer.info->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    (PVOID) &ft,
                    &size),
              false,
              "");

        FILETIME lft{ 0 };
        FileTimeToLocalFileTime(&ft, &lft);

        SYSTEMTIME st{ 0 };
        FileTimeToSystemTime(&lft, &st);

        certificate.date.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

        break;
    }

    return true;
}

BOOL GetCounterSigner(
      const WrapperSignerInfo& signer, WrapperSignerInfo& counterSigner, WrapperHStore& storeCounterSigner, CounterSignatureType& type)
{
    for (DWORD n = 0; n < signer.info->UnauthAttrs.cAttr; n++)
    {
        // Authenticode
        if (lstrcmpA(signer.info->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
        {
            DWORD dwSize{ 0 };
            CHECK(CryptDecodeObject(
                        ENCODING,
                        PKCS7_SIGNER_INFO,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        NULL,
                        &dwSize),
                  false,
                  "");

            counterSigner.info = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSize);
            CHECK(counterSigner.info != nullptr, false, "");

            CHECK(CryptDecodeObject(
                        ENCODING,
                        PKCS7_SIGNER_INFO,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID) counterSigner.info,
                        &dwSize),
                  false,
                  "");

            type = CounterSignatureType::Authenticode;

            return true;
        }

        // RFC3161
        if (lstrcmpA(signer.info->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign) == 0)
        {
            WrapperHMsg hMsg{ .handle = CryptMsgOpenToDecode(ENCODING, 0, 0, NULL, NULL, NULL) };
            CHECK(hMsg.handle != NULL, false, "");

            CHECK(CryptMsgUpdate(
                        hMsg.handle,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue->pbData,
                        signer.info->UnauthAttrs.rgAttr[n].rgValue->cbData,
                        TRUE),
                  false,
                  "");

            DWORD dwSize{ 0 };
            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSize), false, "");
            CHECK(dwSize != 0, false, "");

            counterSigner.info = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSize);

            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, counterSigner.info, &dwSize), false, "");

            CRYPT_DATA_BLOB c7Data{ 0 };
            c7Data.pbData = signer.info->UnauthAttrs.rgAttr[n].rgValue->pbData;
            c7Data.cbData = signer.info->UnauthAttrs.rgAttr[n].rgValue->cbData;

            storeCounterSigner.handle = CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, &c7Data);

            type = CounterSignatureType::RFC3161;

            return true;
        }
    }

    return false;
}

BOOL Get2ndSignature(const WrapperSignerInfo& signer, SignatureMZPE::Information& info)
{
    for (DWORD i = 0; i < signer.info->UnauthAttrs.cAttr; i++)
    {
        if (signer.info->UnauthAttrs.rgAttr[i].pszObjId &&
            lstrcmpA(signer.info->UnauthAttrs.rgAttr[i].pszObjId, szOID_NESTED_SIGNATURE) == 0)
        {
            WrapperHMsg hMsg{ .handle = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL, NULL) };
            CHECK(hMsg.handle != 0, false, "");

            CHECK(CryptMsgUpdate(
                        hMsg.handle,
                        signer.info->UnauthAttrs.rgAttr[i].rgValue->pbData,
                        signer.info->UnauthAttrs.rgAttr[i].rgValue->cbData,
                        TRUE),
                  false,
                  "");

            DWORD dwSignerInfo = 0;
            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo), false, "");
            CHECK(dwSignerInfo != 0, false, "");

            WrapperSignerInfo signerInfo1{ .info = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo) };
            CHECK(signerInfo1.info != nullptr, false, "");

            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signerInfo1.info, &dwSignerInfo), false, "");

            auto& signature1 = info.signatures.emplace_back();

            GetCertDate(signerInfo1, signature1);
            GetOpusInfo(signerInfo1.info, signature1);

            CRYPT_DATA_BLOB data{ 0 };
            data.pbData = signer.info->UnauthAttrs.rgAttr[i].rgValue->pbData;
            data.cbData = signer.info->UnauthAttrs.rgAttr[i].rgValue->cbData;

            WrapperHStore store{ .handle = CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, &data) };

            CERT_INFO certInfo{ .SerialNumber = signerInfo1.info->SerialNumber, .Issuer = signerInfo1.info->Issuer };

            WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                                  store.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };

            GetCertificateInfo(signerInfo1, certContext, signature1);
            signature1.signatureType = SignatureType::Signature;

            WrapperSignerInfo counterSignerInfo{};
            WrapperHStore storeCounterSigner{};
            WrapperCertContext counterSignerCertContext{};
            auto& counterSignature1 = info.signatures.emplace_back();
            if (GetCounterSigner(signerInfo1, counterSignerInfo, storeCounterSigner, counterSignature1.counterSignatureType))
            {
                if (counterSignerInfo.info != nullptr)
                {
                    certInfo.Issuer       = counterSignerInfo.info->Issuer;
                    certInfo.SerialNumber = counterSignerInfo.info->SerialNumber;

                    const auto& scHandle = storeCounterSigner.handle != 0 ? storeCounterSigner.handle : store.handle;

                    WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                                          scHandle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };

                    CHECK(certContext.context != nullptr, false, "");

                    GetCertificateInfo(counterSignerInfo, certContext, counterSignature1);
                    GetCertDate(counterSignerInfo, counterSignature1);
                    GetOpusInfo(counterSignerInfo.info, counterSignature1);
                    counterSignature1.signatureType = SignatureType::CounterSignature;
                }
            }

            break;
        }
    }

    return TRUE;
}

#endif

std::optional<SignatureMZPE> VerifyEmbeddedSignature(ConstString source)
{
    SignatureMZPE data{};
#ifdef BUILD_FOR_WINDOWS
    data.winTrust.callSuccessful = __VerifyEmbeddedSignature__(source, data);

    constexpr auto SIGNATURE_NOT_FOUND = 0x800B0100;
    CHECK(data.winTrust.errorCode != SIGNATURE_NOT_FOUND, std::nullopt, "");

    GetSignaturesInformation(source, data);

    return data;
#endif

    RETURNERROR(std::nullopt, "Not implemented");
}

} // namespace GView::DigitalSignature
