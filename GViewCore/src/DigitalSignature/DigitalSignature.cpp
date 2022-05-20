#include "Internal.hpp"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

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
    WrapperBIO in(BIO_new(BIO_s_mem()));
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperCMS_ContentInfo cms(d2i_CMS_bio(in.memory, nullptr));
    GetError(error, output);
    CHECK(cms.data != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperBIO out(BIO_new(BIO_s_mem()));
    GetError(error, output);
    CHECK(out.memory != nullptr, false, output.GetText());

    ERR_clear_error();
    WrapperASN1_PCTX pctx(ASN1_PCTX_new());
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
    WrapperBIO in(BIO_new(BIO_s_mem()));
    uint32 error = 0;
    GetError(error, current);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperCMS_ContentInfo cms(d2i_CMS_bio(in.memory, NULL));
    GetError(error, current);

    ERR_clear_error();
    WrapperSTACK_OF_X509 certs(CMS_get1_certs(cms.data));
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
        WrapperBIO bioCert(BIO_new(BIO_s_mem()));
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

bool CMSToStructure(const Buffer& buffer, Signature& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in(BIO_new(BIO_s_mem()));
    uint32 error = 0;
    GetError(error, output.errorMessage);

    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(),
          false,
          output.errorMessage.GetText());

    ERR_clear_error();
    WrapperCMS_ContentInfo cms(d2i_CMS_bio(in.memory, nullptr));
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
    WrapperSTACK_OF_X509 certs(CMS_get1_certs(cms.data));
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
            WrapperBIGNUM num(ASN1_INTEGER_to_BN(serialNumber, nullptr));
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

        WrapperEVP_PKEY pubkey(X509_get_pubkey(cert));
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
        WrapperEVP_PKEY pkey(X509_get_pubkey(cert));
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
        if (signer.count >= MAX_SIZE_IN_CONTAINER)
        {
            throw std::runtime_error("Unable to parse this number of signers!");
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

            if (attribute.count >= MAX_SIZE_IN_CONTAINER)
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
            OBJ_obj2txt((char*) attribute.contentType.GetText(), objLen, obj, 1);
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
                WrapperBIO bio(BIO_new(BIO_s_mem()));
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
                        WrapperBIO in(BIO_new(BIO_s_mem()));
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
                                subString = { subString.data() + subString.find(startMarker) + startMarker.length(), subString.find('\n') };

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
} // namespace GView::DigitalSignature
