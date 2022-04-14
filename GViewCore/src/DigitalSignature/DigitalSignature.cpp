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
        if (memory != nullptr)
        {
            BIO_free(memory);
        }
    }
};

struct WrapperCMS_ContentInfo
{
    CMS_ContentInfo* data = nullptr;

    ~WrapperCMS_ContentInfo()
    {
        if (data != nullptr)
        {
            CMS_ContentInfo_free(data);
        }
    }
};

const std::string ASN1TIMEtoString(const ASN1_TIME* time)
{
    WrapperBIO out(BIO_new(BIO_s_mem()));
    CHECK(out.memory, "", "");

    ASN1_TIME_print(out.memory, time);
    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(out.memory, &bptr);
    CHECK(bptr, "", "");

    return { bptr->data, bptr->length };
};

bool PKCS7ToHumanReadable(const Buffer& buffer, std::string& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &data, (int32) buffer.GetLength());
    auto error   = ERR_get_error();
    output       = ERR_error_string(error, nullptr);
    CHECK(pkcs7 != nullptr, false, output.c_str());

    WrapperBIO out(BIO_new(BIO_s_mem()));
    error = ERR_get_error();
    if (error != 0)
    {
        output = ERR_error_string(error, nullptr);
    }
    CHECK(out.memory != nullptr, false, output.c_str());

    ERR_clear_error();
    ASN1_PCTX* pctx = ASN1_PCTX_new();
    error           = ERR_get_error();
    if (error != 0)
    {
        output = ERR_error_string(error, nullptr);
    }
    CHECK(pctx != nullptr, false, output.c_str());

    /* TODO: do we actually need these?
    // ASN1_PCTX_set_flags(
    //       pctx,
    //       ASN1_PCTX_FLAGS_SHOW_ABSENT | ASN1_PCTX_FLAGS_SHOW_SEQUENCE | ASN1_PCTX_FLAGS_SHOW_SSOF | ASN1_PCTX_FLAGS_SHOW_TYPE |
    //             ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME);
    // ASN1_PCTX_set_str_flags(pctx, ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_DUMP_ALL);
    // const auto ctxCode = ASN1_item_print(out.memory, (ASN1_VALUE*)pkcs7, 4, ASN1_ITEM_rptr(PKCS7), nullptr);
    */
    ASN1_PCTX_set_flags(pctx, ASN1_PCTX_FLAGS_SHOW_ABSENT);
    ASN1_PCTX_set_str_flags(pctx, 0);
    ASN1_PCTX_set_oid_flags(pctx, 0);
    ASN1_PCTX_set_cert_flags(pctx, 0);

    const auto ctxCode = PKCS7_print_ctx(out.memory, pkcs7, 4, pctx);
    error              = ERR_get_error();
    if (error != 0)
    {
        output = ERR_error_string(error, nullptr);
    }
    CHECK(ctxCode == 1, false, output.c_str());

    BUF_MEM* buf{};
    BIO_get_mem_ptr(out.memory, &buf);
    output = std::string{ buf->data, buf->length };

    return true;
}

bool CMSToPEMCerts(const Buffer& buffer, std::vector<std::string>& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    output.clear();
    auto& first = output.emplace_back();

    ERR_clear_error();
    WrapperBIO in(BIO_new(BIO_s_mem()));
    auto error = ERR_get_error();
    first      = ERR_error_string(error, nullptr);
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    WrapperCMS_ContentInfo cms(d2i_CMS_bio(in.memory, NULL));
    error = ERR_get_error();
    first = ERR_error_string(error, nullptr);

    ERR_clear_error();
    STACK_OF(X509)* certs = CMS_get1_certs(cms.data);
    error                 = ERR_get_error();
    first                 = ERR_error_string(error, nullptr);

    CHECK(certs != nullptr, false, "");

    output.clear();
    for (int i = 0; i < sk_X509_num(certs); i++)
    {
        const auto cert = sk_X509_value(certs, i);

        WrapperBIO bioCert(BIO_new(BIO_s_mem()));
        PEM_write_bio_X509(bioCert.memory, cert);

        BUF_MEM* buf{};
        BIO_get_mem_ptr(bioCert.memory, &buf);
        output.emplace_back(std::string{ buf->data, buf->length });
    }

    return true;
}

bool CMSToStructure(const Buffer& buffer, Signature& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    WrapperBIO in(BIO_new(BIO_s_mem()));
    auto error = ERR_get_error();
    if (error != 0)
    {
        output.errorMessage = ERR_error_string(error, nullptr);
    }
    CHECK((size_t) BIO_write(in.memory, buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(),
          false,
          output.errorMessage.c_str());

    ERR_clear_error();
    WrapperCMS_ContentInfo cms(d2i_CMS_bio(in.memory, nullptr));
    error = ERR_get_error();
    if (error != 0)
    {
        output.errorMessage = ERR_error_string(error, nullptr);
    }
    CHECK(cms.data, false, output.errorMessage.c_str());

    output.isDetached = CMS_is_detached(cms.data);

    const ASN1_OBJECT* obj = CMS_get0_type(cms.data);
    output.sn              = OBJ_nid2ln(OBJ_obj2nid(obj));
    ERR_clear_error();
    ASN1_OCTET_STRING** pos = CMS_get0_content(cms.data);
    error                   = ERR_get_error();
    if (error != 0)
    {
        output.errorMessage = ERR_error_string(error, nullptr);
    }
    if (pos)
    {
        if ((*pos))
        {
            output.snContent.Resize((*pos)->length);
            memcpy(output.snContent.GetData(), (*pos)->data, (*pos)->length);
        }
    }

    STACK_OF(X509)* certs = CMS_get1_certs(cms.data);
    for (int i = 0; i < sk_X509_num(certs); i++)
    {
        const auto cert = sk_X509_value(certs, i);

        // WrapperBIO bio(BIO_new(BIO_s_mem()));
        // X509_print(bio.memory, cert);
        // BUF_MEM* bptr = NULL;
        // BIO_get_mem_ptr(bio.memory, &bptr);
        // BIO_set_close(bio.memory, BIO_NOCLOSE);
        //
        // std::string a;
        // a.append(bptr->data, bptr->length);

        auto& sigCert = output.certificates.emplace_back();

        sigCert.version = X509_get_version(cert);

        ASN1_INTEGER* asn1_i = X509_get_serialNumber(cert);
        if (asn1_i)
        {
            BIGNUM* bignum       = ASN1_INTEGER_to_BN(asn1_i, NULL);
            sigCert.serialNumber = BN_bn2hex(bignum);
        }

        sigCert.signatureAlgorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

        EVP_PKEY* pubkey           = X509_get_pubkey(cert);
        sigCert.publicKeyAlgorithm = OBJ_nid2ln(EVP_PKEY_id(pubkey));
        EVP_PKEY_free(pubkey);

        sigCert.validityNotBefore = ASN1TIMEtoString(X509_get0_notBefore(cert));
        sigCert.validityNotAfter  = ASN1TIMEtoString(X509_get0_notAfter(cert));

        sigCert.issuer  = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        sigCert.subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);

        EVP_PKEY* pkey = X509_get_pubkey(cert);
        ERR_clear_error();
        sigCert.verify = X509_verify(cert, pkey);
        if (sigCert.verify != 1)
        {
            error = ERR_get_error();
            if (error != 0)
            {
                sigCert.errorVerify = ERR_error_string(error, nullptr);
            }
        }
        EVP_PKEY_free(pkey);

        STACK_OF(CMS_SignerInfo)* siStack = CMS_get0_SignerInfos(cms.data);
        for (int32 i = 0; i < sk_CMS_SignerInfo_num(siStack); i++)
        {
            CMS_SignerInfo* si = sk_CMS_SignerInfo_value(siStack, i);
            ERR_clear_error();
            sigCert.signerVerify = CMS_SignerInfo_cert_cmp(si, cert);
            if (sigCert.signerVerify != 0)
            {
                error = ERR_get_error();
                if (error != 0)
                {
                    sigCert.errorSignerVerify = ERR_error_string(error, nullptr);
                }
            }
            else
            {
                break;
            }
        }
    }

    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms.data);
    for (int i = 0; i < sk_CMS_SignerInfo_num(sis); i++)
    {
        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(sis, i);
        const auto sig     = CMS_SignerInfo_get0_signature(si);

        auto& signer = output.signers.emplace_back();

        signer.count = CMS_signed_get_attr_count(si);
        for (int j = 0; j < signer.count; j++)
        {
            X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, j);
            if (!attr)
            {
                continue;
            }

            auto& attribute = signer.attributes.emplace_back();

            attribute.count = X509_ATTRIBUTE_count(attr);
            if (attribute.count <= 0)
            {
                continue;
            }

            ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
            if (!obj)
            {
                continue;
            }

            attribute.name = OBJ_nid2ln(OBJ_obj2nid(obj));

            auto objLen = OBJ_obj2txt(nullptr, -1, obj, 1) + 1;
            attribute.contentType.resize(objLen);
            OBJ_obj2txt((char*) attribute.contentType.c_str(), objLen, obj, 1);
            attribute.contentType.resize(objLen - 1);

            ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
            if (av == nullptr)
            {
                continue;
            }
            auto& asnType = attribute.types.emplace_back((ASN1TYPE) av->type);

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

                attribute.contentTypeData = ls.GetText();
                attribute.CDHashes.emplace_back().append(ls.GetText());
            }
            else if (asnType == ASN1TYPE::UTCTIME)
            {
                WrapperBIO bio(BIO_new(BIO_s_mem()));
                ASN1_UTCTIME_print(bio.memory, av->value.utctime);
                BUF_MEM* bptr = NULL;
                BIO_get_mem_ptr(bio.memory, &bptr);
                BIO_set_close(bio.memory, BIO_NOCLOSE);

                attribute.contentTypeData.append(bptr->data, bptr->length);
            }
            else if (asnType == ASN1TYPE::SEQUENCE)
            {
                attribute.types.clear();
                for (int32 m = 0; m < attribute.count; m++)
                {
                    av = X509_ATTRIBUTE_get0_type(attr, m);
                    if (av != nullptr)
                    {
                        WrapperBIO in(BIO_new(BIO_s_mem()));

                        ASN1_STRING* sequence = av->value.sequence;
                        attribute.types.emplace_back((ASN1TYPE) av->type);
                        ASN1_parse_dump(in.memory, sequence->data, sequence->length, 2, 0);
                        BUF_MEM* buf = nullptr;
                        BIO_get_mem_ptr(in.memory, &buf);
                        BIO_set_close(in.memory, BIO_NOCLOSE);
                        attribute.contentTypeData.append(buf->data, buf->length);

                        auto& hash        = attribute.CDHashes.emplace_back();
                        const auto posHex = attribute.contentTypeData.find("[HEX DUMP]:");
                        if (std::string::npos != posHex)
                        {
                            const auto posEndLine = attribute.contentTypeData.find("\n", posHex);
                            if (std::string::npos != posEndLine)
                            {
                                hash = attribute.contentTypeData.substr(posHex + 11, posEndLine - posHex - 11);
                            }
                        }
                    }
                }
            }
            else
            {
                throw "Unknown hash!";
            }
        }
    }

    output.error = false;

    return true;
}
} // namespace GView::DigitalSignature
