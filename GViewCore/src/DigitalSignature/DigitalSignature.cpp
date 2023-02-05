#include "Internal.hpp"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/asn1t.h>

#include "Authenticode.hpp"

namespace GView::DigitalSignature
{
void OpenSSL_free(void* ptr)
{
    OPENSSL_free(ptr);
}

void SK_X509_free(stack_st_X509* ptr)
{
    sk_X509_free(ptr);
}

void SK_X509_pop_free(STACK_OF(X509) * ptr)
{
    sk_X509_pop_free(ptr, X509_free);
}

/* Convenient self-releasing aliases for libcrypto and custom ASN.1 types. */
using BIO_ptr             = std::unique_ptr<BIO, decltype(&BIO_free)>;
using ASN1_OBJECT_ptr     = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using ASN1_TYPE_ptr       = std::unique_ptr<ASN1_TYPE, decltype(&ASN1_TYPE_free)>;
using OpenSSL_ptr         = std::unique_ptr<char, decltype(&OpenSSL_free)>;
using BN_ptr              = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using X509_ptr            = std::unique_ptr<X509, decltype(&SK_X509_free)>;
using PKCS7_ptr           = std::unique_ptr<PKCS7, decltype(&PKCS7_free)>;
using CMS_ContentInfo_ptr = std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>;
using ASN1_PCTX_ptr       = std::unique_ptr<ASN1_PCTX, decltype(&ASN1_PCTX_free)>;
using STACK_OF_X509_ptr   = std::unique_ptr<STACK_OF(X509), decltype(&SK_X509_pop_free)>;
using EVP_PKEY_ptr        = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BUF_MEM_ptr         = std::unique_ptr<BUF_MEM, decltype(&BUF_MEM_free)>;

/**
 * A convenience union for representing the kind of checksum returned, as
 * well as its actual digest data.
 */
inline static bool ASN1TIMEtoString(const ASN1_TIME* time, String& output)
{
    BIO_ptr out(BIO_new(BIO_s_mem()), BIO_free);
    CHECK(out != nullptr, false, "");

    ASN1_TIME_print(out.get(), time);
    BUF_MEM* buf{};
    BIO_get_mem_ptr(out.get(), &buf);
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
    CHECK(buffer.GetData() != nullptr, false, "");

    ERR_clear_error();
    BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.get(), buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    CMS_ContentInfo_ptr cms(d2i_CMS_bio(in.get(), nullptr), CMS_ContentInfo_free);
    GetError(error, output);
    CHECK(cms != nullptr, false, output.GetText());

    ERR_clear_error();
    BIO_ptr out(BIO_new(BIO_s_mem()), BIO_free);
    GetError(error, output);
    CHECK(out != nullptr, false, output.GetText());

    ERR_clear_error();
    ASN1_PCTX_ptr pctx(ASN1_PCTX_new(), ASN1_PCTX_free);
    GetError(error, output);
    CHECK(pctx != nullptr, false, output.GetText());

    ASN1_PCTX_set_flags(pctx.get(), ASN1_PCTX_FLAGS_SHOW_ABSENT);
    ASN1_PCTX_set_str_flags(pctx.get(), ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_DUMP_ALL);
    ASN1_PCTX_set_oid_flags(pctx.get(), 0);
    ASN1_PCTX_set_cert_flags(pctx.get(), 0);

    ERR_clear_error();
    const auto ctxCode = CMS_ContentInfo_print_ctx(out.get(), cms.get(), 4, pctx.get());
    GetError(error, output);
    CHECK(ctxCode == 1, false, output.GetText());

    BUF_MEM* buf{};
    ERR_clear_error();
    BIO_get_mem_ptr(out.get(), &buf);
    GetError(error, output);
    CHECK(output.Set(buf->data, (uint32) buf->length), false, "");

    return true;
}

bool CMSToPEMCerts(const Buffer& buffer, String output[32], uint32& count)
{
    CHECK(buffer.GetData() != nullptr, false, "");
    count         = 1;
    auto& current = output[0];

    ERR_clear_error();
    BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
    uint32 error = 0;
    GetError(error, current);
    CHECK((size_t) BIO_write(in.get(), buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    CMS_ContentInfo_ptr cms(d2i_CMS_bio(in.get(), nullptr), CMS_ContentInfo_free);
    GetError(error, current);
    CHECK(cms != nullptr, false, "");

    ERR_clear_error();
    STACK_OF_X509_ptr certs(CMS_get1_certs(cms.get()), SK_X509_pop_free);
    GetError(error, current);
    CHECK(certs != nullptr, false, "");

    count = static_cast<uint32>(sk_X509_num(certs.get()));
    if (count >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (uint32 i = 0; i < count; i++)
    {
        auto& current = output[i];

        ERR_clear_error();
        const auto cert = sk_X509_value(certs.get(), i);
        GetError(error, current);
        CHECK(cert != nullptr, false, "");

        ERR_clear_error();
        BIO_ptr bioCert(BIO_new(BIO_s_mem()), BIO_free);
        GetError(error, current);
        CHECK(bioCert != nullptr, false, "");

        ERR_clear_error();
        const auto bioWrite = PEM_write_bio_X509(bioCert.get(), cert);
        GetError(error, current);
        CHECK(bioWrite == 1, false, "");

        BUF_MEM* buf{};
        ERR_clear_error();
        BIO_get_mem_ptr(bioCert.get(), &buf);
        GetError(error, current);
        CHECK(buf != nullptr, false, "");
        current.Set(buf->data, (uint32) buf->length);
    }

    return true;
}

bool CMSToStructure(const Buffer& buffer, SignatureMachO& output)
{
    CHECK(buffer.GetData() != nullptr, false, "");

    ERR_clear_error();
    BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
    uint32 error = 0;
    GetError(error, output.errorMessage);

    CHECK((size_t) BIO_write(in.get(), buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(),
          false,
          output.errorMessage.GetText());

    ERR_clear_error();
    CMS_ContentInfo_ptr cms(d2i_CMS_bio(in.get(), nullptr), CMS_ContentInfo_free);
    GetError(error, output.errorMessage);
    CHECK(cms, false, output.errorMessage.GetText());

    output.isDetached = CMS_is_detached(cms.get());

    const ASN1_OBJECT* obj = CMS_get0_type(cms.get()); // no need to free (pointer from CMS structure)
    output.sn              = OBJ_nid2ln(OBJ_obj2nid(obj));

    ERR_clear_error();
    ASN1_OCTET_STRING** pos = CMS_get0_content(cms.get()); // no need to free (pointer from CMS structure)
    GetError(error, output.errorMessage);
    if (pos && (*pos))
    {
        output.snContent.Resize((*pos)->length);
        memcpy(output.snContent.GetData(), (*pos)->data, (*pos)->length);
    }

    ERR_clear_error();
    STACK_OF_X509_ptr certs(CMS_get1_certs(cms.get()), SK_X509_pop_free);
    GetError(error, output.errorMessage);
    CHECK(certs != nullptr, false, "");

    output.certificatesCount = sk_X509_num(certs.get());
    if (output.certificatesCount >= MAX_SIZE_IN_CONTAINER)
    {
        throw std::runtime_error("Unable to parse this number of certificates!");
    }
    for (auto i = 0U; i < output.certificatesCount; i++)
    {
        ERR_clear_error();
        const auto cert = sk_X509_value(certs.get(), i);
        GetError(error, output.errorMessage);
        CHECK(cert != nullptr, false, "");

        auto& sigCert = output.certificates[i];

        sigCert.version = X509_get_version(cert);

        const auto serialNumber = X509_get_serialNumber(cert);
        if (serialNumber)
        {
            BN_ptr num{ ASN1_INTEGER_to_BN(serialNumber, nullptr), BN_free };
            if (num != nullptr)
            {
                OpenSSL_ptr hex(BN_bn2hex(num.get()), OpenSSL_free);
                if (hex != nullptr)
                {
                    sigCert.serialNumber.Set(hex.get());
                }
            }
        }

        sigCert.signatureAlgorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

        EVP_PKEY_ptr pubkey{ X509_get_pubkey(cert), EVP_PKEY_free };
        sigCert.publicKeyAlgorithm = OBJ_nid2ln(EVP_PKEY_id(pubkey.get()));

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
        EVP_PKEY_ptr pkey{ X509_get_pubkey(cert), EVP_PKEY_free };
        GetError(error, output.errorMessage);
        CHECK(pkey != nullptr, false, "");

        ERR_clear_error();
        sigCert.verify = X509_verify(cert, pkey.get());
        if (sigCert.verify != 1)
        {
            GetError(error, sigCert.errorVerify);
        }

        STACK_OF(CMS_SignerInfo)* siStack = CMS_get0_SignerInfos(cms.get()); // no need to free (pointer from CMS structure)
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

    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms.get());
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
                BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
                GetError(error, output.errorMessage);
                CHECK(bio != nullptr, false, "");

                ASN1_UTCTIME_print(bio.get(), av->value.utctime);
                BUF_MEM* bptr = nullptr; // no need to free (pointer from BIO structure)
                BIO_get_mem_ptr(bio.get(), &bptr);
                BIO_set_close(bio.get(), BIO_NOCLOSE);

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
                        BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
                        GetError(error, output.errorMessage);
                        CHECK(in != nullptr, false, "");

                        ASN1_STRING* sequence = av->value.sequence;
                        attribute.types[m]    = (ASN1TYPE) av->type;
                        ASN1_parse_dump(in.get(), sequence->data, sequence->length, 2, 0);
                        BUF_MEM* buf = nullptr;
                        BIO_get_mem_ptr(in.get(), &buf);
                        BIO_set_close(in.get(), BIO_NOCLOSE);
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

const std::string TimeToHumanReadable(time_t input)
{
    struct tm t;
    try
    {
#if BUILD_FOR_WINDOWS
        localtime_s(&t, &input);
#elif BUILD_FOR_OSX
        localtime_r(&input, &t);
#elif BUILD_FOR_UNIX
        localtime_r(&input, &t);
#endif
    }
    catch (...)
    {
        return "";
    }

    char buffer[32];
    std::strftime(buffer, 32, "%a, %d.%m.%Y %H:%M:%S", &t);
    return buffer;
}

bool AuthenticodeVerifySignature(Utils::DataCache& cache, AuthenticodeMS& output)
{
    /*
     * with help from:
     * https://stackoverflow.com/questions/50976612/amended-code-to-retrieve-dual-signature-information-from-pe-executable-in-window
     * https://github.com/trailofbits/uthenticode/blob/master/src/uthenticode.cpp
     * https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows
     */

    Buffer b = cache.CopyEntireFile(true);
    Authenticode::AuthenticodeParser parser;
    bool result = parser.AuthenticodeParse(b.GetData(), b.GetLength());

    for (const auto& signature : parser.GetSignatures())
    {
        if (signature.verifyFlags != 0)
        {
            output.openssl.errorMessage.Add(parser.GetSignatureFlags(signature.verifyFlags).c_str());
            result = false;
        }

        for (const auto& counter : signature.counterSignatures)
        {
            if (counter.verifyFlags != 0)
            {
                output.openssl.errorMessage.Add(parser.GetSignatureFlags(signature.verifyFlags).c_str());
                result = false;
            }
        }

        for (const auto& certificate : signature.certs)
        {
            output.data.pemCerts.emplace_back().Set(certificate.pem);
        }
    }

#ifndef BUILD_FOR_WINDOWS // this gets filled in PE Type plugin
    for (const auto& oSignature : parser.GetSignatures())
    {
        auto& signature = output.data.signatures.emplace_back();

        signature.signer.programName.Set(oSignature.signer.programName);
        signature.signer.publishLink.Set(oSignature.signer.publishLink);
        signature.signer.moreInfoLink.Set(oSignature.signer.moreInfoLink);

        for (const auto& oCertificate : oSignature.certs)
        {
            auto& certificate = signature.certificates.emplace_back();

            certificate.version = (uint32_t) oCertificate.version;
            certificate.issuer.Set(oCertificate.issuer);
            certificate.subject.Set(oCertificate.subject);
            certificate.email.Set(oCertificate.issuerAttributes.emailAddress);
            certificate.serialNumber.Set(oCertificate.serial);
            certificate.digestAlgorithm.Set(oCertificate.keyAlg);
            certificate.notAfter.Set(TimeToHumanReadable(oCertificate.notAfter));
            certificate.notBefore.Set(TimeToHumanReadable(oCertificate.notBefore));
            certificate.crlPoint = "";

            if (oSignature.counterSignatures.empty())
            {
                signature.signatureType = SignatureType::Signature;
            }
            else
            {
                signature.signatureType = SignatureType::CounterSignature;

                const auto& cs                 = oSignature.counterSignatures.at(0);
                signature.counterSignatureType = (CounterSignatureType) cs.type;
                signature.signingTime.Set(TimeToHumanReadable(cs.signTime));
                for (const auto& oCsCertificate : cs.chain)
                {
                    certificate.issuer.Set(oCsCertificate.issuer);
                    certificate.subject.Set(oCsCertificate.subject);
                    certificate.email.Set(oCsCertificate.issuerAttributes.emailAddress);
                    certificate.serialNumber.Set(oCsCertificate.serial);
                    certificate.digestAlgorithm.Set(oCsCertificate.keyAlg);
                    certificate.notAfter.Set(TimeToHumanReadable(oCsCertificate.notAfter));
                    certificate.notBefore.Set(TimeToHumanReadable(oCsCertificate.notBefore));
                    certificate.crlPoint = "";
                }
            }
        }
    }

#endif

    return result;
}

bool AuthenticodeToHumanReadable(const Buffer& buffer, String& output)
{
    CHECK(buffer.GetData() != nullptr, false, "");

    ERR_clear_error();
    BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
    uint32 error = 0;
    GetError(error, output);
    CHECK((size_t) BIO_write(in.get(), buffer.GetData(), (int32) buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    PKCS7_ptr pkcs7(d2i_PKCS7_bio(in.get(), nullptr), PKCS7_free);
    GetError(error, output);
    CHECK(pkcs7 != nullptr, false, output.GetText());

    ERR_clear_error();
    BIO_ptr out(BIO_new(BIO_s_mem()), BIO_free);
    GetError(error, output);
    CHECK(out.get() != nullptr, false, output.GetText());

    ERR_clear_error();
    ASN1_PCTX_ptr pctx(ASN1_PCTX_new(), ASN1_PCTX_free);
    GetError(error, output);
    CHECK(pctx != nullptr, false, output.GetText());

    ASN1_PCTX_set_flags(pctx.get(), ASN1_PCTX_FLAGS_SHOW_ABSENT);
    ASN1_PCTX_set_str_flags(pctx.get(), ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_DUMP_ALL);
    ASN1_PCTX_set_oid_flags(pctx.get(), 0);
    ASN1_PCTX_set_cert_flags(pctx.get(), 0);

    ERR_clear_error();
    const auto ctxCode = PKCS7_print_ctx(out.get(), pkcs7.get(), 4, pctx.get());
    GetError(error, output);
    CHECK(ctxCode == 1, false, output.GetText());

    BUF_MEM* buf{};
    ERR_clear_error();
    BIO_get_mem_ptr(out.get(), &buf);
    GetError(error, output);
    CHECK(output.Set(buf->data, (uint32) buf->length), false, "");

    return true;
}

bool VerifyEmbeddedSignature(AuthenticodeMS& data, Utils::DataCache& cache)
{
    data.openssl.verified = AuthenticodeVerifySignature(cache, data);
    return true;
}

} // namespace GView::DigitalSignature
