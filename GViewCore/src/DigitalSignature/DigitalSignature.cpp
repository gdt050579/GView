#include "Internal.hpp"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/asn1t.h>

#include "Authenticode.hpp"

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

bool AuthenticodeVerifySignature(Utils::DataCache& cache, String& output)
{
    /*
     * with help from:
     * https://stackoverflow.com/questions/50976612/amended-code-to-retrieve-dual-signature-information-from-pe-executable-in-window
     * https://github.com/trailofbits/uthenticode/blob/master/src/uthenticode.cpp
     * https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows
     */

    Buffer b = cache.CopyEntireFile(true);
    Authenticode::AuthenticodeParser parser;
    parser.AuthenticodeParse(b.GetData(), b.GetLength());
    std::string output2;
    parser.Dump(output2);

    return true;
}

bool AuthenticodeToHumanReadable(const Buffer& buffer, String& output)
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

    return true;
}

bool AuthenticodeToStructure(const Buffer& buffer, AuthenticodeMS& output)
{
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

bool __VerifyEmbeddedSignature__(ConstString source, AuthenticodeMS& data)
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

constexpr uint32 ENCODING = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

using CMSG_SIGNER_INFO_ptr = std::unique_ptr<CMSG_SIGNER_INFO, decltype(&LocalFree)>;
using CERT_CONTEXT_ptr     = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;

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

BOOL GetOpusInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature::Signer& signer);
BOOL GetCertificateSigningTime(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature& signature);
BOOL GetCertificateCRLPoint(const CERT_CONTEXT_ptr& certContext, AuthenticodeMS::Data::Signature::Certificate& certificate);
BOOL GetCertificateInfo(
      const CMSG_SIGNER_INFO_ptr& signerInfo,
      const CERT_CONTEXT_ptr& certContext,
      AuthenticodeMS::Data::Signature::Certificate& certificate);
BOOL GetCounterSigner(
      const CMSG_SIGNER_INFO_ptr& signer,
      CMSG_SIGNER_INFO_ptr& counterSigner,
      WrapperHStore& storeCounterSigner,
      CounterSignatureType& type);

BOOL Get_szOID_RSA_counterSign_Signer(const CMSG_SIGNER_INFO_ptr& signer, uint32 attributeIndex, CMSG_SIGNER_INFO_ptr& counterSigner)
{
    DWORD dwSize{ 0 };
    CHECK(CryptDecodeObject(
                ENCODING,
                PKCS7_SIGNER_INFO,
                signer.get()->UnauthAttrs.rgAttr[attributeIndex].rgValue[0].pbData,
                signer.get()->UnauthAttrs.rgAttr[attributeIndex].rgValue[0].cbData,
                0,
                NULL,
                &dwSize),
          false,
          "");

    counterSigner.reset((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSize));
    CHECK(counterSigner.get() != nullptr, false, "");

    CHECK(CryptDecodeObject(
                ENCODING,
                PKCS7_SIGNER_INFO,
                signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[0].pbData,
                signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[0].cbData,
                0,
                (PVOID) counterSigner.get(),
                &dwSize),
          false,
          "");

    return TRUE;
}

BOOL GetInfoThroughSigner(
      AuthenticodeMS& container,
      const CMSG_SIGNER_INFO_ptr& signer,
      const WrapperHStore& store,
      SignatureType signatureType,
      CounterSignatureType counterSignatureType)
{
    auto& signature                = container.data.signatures.emplace_back();
    signature.signatureType        = signatureType;
    signature.counterSignatureType = counterSignatureType;
    CHECK(GetOpusInfo(signer, signature.signer), false, "");

    CERT_INFO signerCertInfo{ .SerialNumber = signer->SerialNumber, .Issuer = signer->Issuer };
    CERT_CONTEXT_ptr certContext(
          CertFindCertificateInStore(store.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &signerCertInfo, NULL),
          CertFreeCertificateContext);
    CHECK(certContext != nullptr, false, "");

    auto& certificate = signature.certificates.emplace_back();
    CHECK(GetCertificateInfo(signer, certContext, certificate), false, "");
    CHECK(GetCertificateSigningTime(signer, signature), false, "");

    return TRUE;
}

BOOL Get_szOID_NESTED_SIGNATURE_Signer(
      const CMSG_SIGNER_INFO_ptr& signer, uint32 attributeIndex, std::vector<CMSG_SIGNER_INFO_ptr>& nestedSigners)
{
    uint32 offset = 0;
    for (uint32 j = 0; j < signer->UnauthAttrs.rgAttr[attributeIndex].cValue; j++)
    {
        WrapperHMsg hMsg{ .handle = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL, NULL) };
        CHECK(hMsg.handle != 0, false, "");

        CHECK(CryptMsgUpdate(
                    hMsg.handle,
                    signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[j].pbData,
                    signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[j].cbData,
                    TRUE),
              false,
              "");

        DWORD dwSignerCount = 0;
        CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, NULL, &dwSignerCount), false, "");
        CHECK(dwSignerCount == sizeof(DWORD), false, "");

        DWORD signersCount = 0;
        CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, &signersCount, &dwSignerCount), false, "");
        CHECK(dwSignerCount == sizeof(DWORD), false, "");

        for (uint32 i = 0; i < signersCount; i++)
        {
            DWORD dwSignerInfo = 0;
            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, i, NULL, &dwSignerInfo), false, "");
            CHECK(dwSignerInfo != 0, false, "");

            auto& nestedSigner = nestedSigners.emplace_back(
                  std::move(CMSG_SIGNER_INFO_ptr((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo), LocalFree)));
            CHECK(nestedSigner.get() != nullptr, false, "");

            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, i, (PVOID) nestedSigner.get(), &dwSignerInfo), false, "");
            CHECK(dwSignerInfo != 0, false, "");
        }
    }

    return TRUE;
}

BOOL ParseSigner(const CMSG_SIGNER_INFO_ptr& signer, AuthenticodeMS& container, const WrapperHStore& initialStore)
{
    CHECK(signer != nullptr, false, "");

    for (DWORD n = 0; n < signer->UnauthAttrs.cAttr; n++)
    {
        if (signer->UnauthAttrs.rgAttr[n].pszObjId && lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_NESTED_SIGNATURE) == 0)
        {
            std::vector<CMSG_SIGNER_INFO_ptr> nestedSigners;
            CHECK(Get_szOID_NESTED_SIGNATURE_Signer(signer, n, nestedSigners), false, "");

            auto i = 0;
            for (const auto& nestedSigner : nestedSigners)
            {
                CRYPT_DATA_BLOB data{ 0 };
                data.pbData = signer->UnauthAttrs.rgAttr[n].rgValue[i].pbData;
                data.cbData = signer->UnauthAttrs.rgAttr[n].rgValue[i++].cbData;

                WrapperHStore store{ .handle = CertOpenStore(CERT_STORE_PROV_PKCS7, ENCODING, NULL, 0, &data) };

                CHECK(GetInfoThroughSigner(container, nestedSigner, store, SignatureType::Signature, CounterSignatureType::Unknown),
                      false,
                      "");
                CHECK(ParseSigner(nestedSigner, container, initialStore), false, "");
            }
        }

        // Authenticode
        if (signer->UnauthAttrs.rgAttr[n].pszObjId && lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
        {
            CMSG_SIGNER_INFO_ptr counterSigner(nullptr, LocalFree);
            CHECK(Get_szOID_RSA_counterSign_Signer(signer, n, counterSigner), false, "");
            CHECK(GetInfoThroughSigner(
                        container, counterSigner, initialStore, SignatureType::CounterSignature, CounterSignatureType::Authenticode),
                  false,
                  "");
            CHECK(ParseSigner(counterSigner, container, initialStore), false, "");
        }

        // RFC3161
        if (signer->UnauthAttrs.rgAttr[n].pszObjId && lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign) == 0)
        {
            std::vector<CMSG_SIGNER_INFO_ptr> counterSigners;
            CHECK(Get_szOID_NESTED_SIGNATURE_Signer(signer, n, counterSigners), false, "");

            auto i = 0;
            for (const auto& counterSigner : counterSigners)
            {
                CRYPT_DATA_BLOB data{ 0 };
                data.pbData = signer->UnauthAttrs.rgAttr[n].rgValue[i].pbData;
                data.cbData = signer->UnauthAttrs.rgAttr[n].rgValue[i++].cbData;

                WrapperHStore store{ .handle = CertOpenStore(CERT_STORE_PROV_PKCS7, ENCODING, NULL, 0, &data) };

                CHECK(GetInfoThroughSigner(container, counterSigner, store, SignatureType::CounterSignature, CounterSignatureType::RFC3161),
                      false,
                      "");
                CHECK(ParseSigner(counterSigner, container, initialStore), false, "");
            }
        }
    }

    return TRUE;
}

bool GetSignaturesInformation(ConstString source, AuthenticodeMS& container)
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

    CMSG_SIGNER_INFO_ptr signerInfo((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo), LocalFree);
    CHECK(signerInfo != nullptr, false, "");

    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signerInfo.get(), &dwSignerInfo), false, "");

    auto& pkSignature = container.data.signatures.emplace_back();
    auto& pkSigner    = pkSignature.signer;
    CHECK(GetOpusInfo(signerInfo, pkSigner), false, "");

    CERT_INFO signerCertInfo{ .SerialNumber = signerInfo->SerialNumber, .Issuer = signerInfo->Issuer };
    CERT_CONTEXT_ptr certContext(
          CertFindCertificateInStore(hStore.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &signerCertInfo, NULL),
          CertFreeCertificateContext);
    CHECK(certContext != nullptr, false, "");

    auto& ceritficate = pkSignature.certificates.emplace_back();
    CHECK(GetCertificateInfo(signerInfo, certContext, ceritficate), false, "");
    CHECK(GetCertificateSigningTime(signerInfo, pkSignature), false, "");
    pkSignature.signatureType = SignatureType::Signature;

    CHECK(ParseSigner(signerInfo, container, hStore), false, "");

    return true;
}

BOOL GetNameString(const CERT_CONTEXT_ptr& certContext, String& out, DWORD type, DWORD flag)
{
    const auto size = CertGetNameStringA(certContext.get(), type, flag, NULL, NULL, 0);
    std::unique_ptr<char> name(new char[size]);
    CHECK(CertGetNameStringA(certContext.get(), type, flag, NULL, (LPSTR) name.get(), size) == size, false, "");
    CHECK(out.Set(name.get()), false, "");

    return true;
}

BOOL GetCertificateInfo(
      const CMSG_SIGNER_INFO_ptr& signerInfo,
      const CERT_CONTEXT_ptr& certContext,
      AuthenticodeMS::Data::Signature::Certificate& certificate)
{
    LocalString<1024> ls;
    const auto serialNumberSize = certContext->pCertInfo->SerialNumber.cbData;
    for (DWORD n = 0; n < serialNumberSize; n++)
    {
        ls.AddFormat("%02x", certContext->pCertInfo->SerialNumber.pbData[serialNumberSize - (n + 1)]);
    }
    certificate.serialNumber.Set(ls);

    CHECK(GetNameString(certContext, certificate.issuer, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG), false, "");
    CHECK(GetNameString(certContext, certificate.subject, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0), false, "");
    CHECK(GetNameString(certContext, certificate.email, CERT_NAME_EMAIL_TYPE, 0), false, "");

    const auto& digestAlgorithm = signerInfo->HashAlgorithm;
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

    const auto& dateNotAfter = certContext->pCertInfo->NotAfter;
    FileTimeToSystemTime(&dateNotAfter, &st);
    certificate.dateNotAfter.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    const auto& dateNotBefore = certContext->pCertInfo->NotBefore;
    FileTimeToSystemTime(&dateNotBefore, &st);
    certificate.dateNotBefore.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    CHECK(GetCertificateCRLPoint(certContext, certificate), false, "");

    return true;
}

BOOL GetOpusInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature::Signer& signer)
{
    for (auto n = 0U; n < signerInfo->AuthAttrs.cAttr; n++)
    {
        const auto& objID = signerInfo->AuthAttrs.rgAttr[n].pszObjId;
        if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, objID) != 0)
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
            signer.programName.Set(std::u16string_view{ reinterpret_cast<const char16_t*>(opusInfoRaw->pwszProgramName) });
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

        populate(opusInfoRaw->pPublisherInfo, signer.publishLink);
        populate(opusInfoRaw->pMoreInfo, signer.moreInfoLink);

        break;
    }

    return true;
}

BOOL GetCertificateCRLPoint(const CERT_CONTEXT_ptr& certContext, AuthenticodeMS::Data::Signature::Certificate& certificate)
{
    PCERT_EXTENSION pe = CertFindExtension(szOID_CRL_DIST_POINTS, certContext->pCertInfo->cExtension, certContext->pCertInfo->rgExtension);
    CHECK(pe, FALSE, "");

    BYTE btData[512]   = { 0 };
    auto pCRLDistPoint = (PCRL_DIST_POINTS_INFO) btData;
    ULONG dataLength   = 512;
    CHECK(CryptDecodeObject(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                szOID_CRL_DIST_POINTS,
                pe->Value.pbData,
                pe->Value.cbData,
                CRYPT_DECODE_NOCOPY_FLAG,
                pCRLDistPoint,
                &dataLength),
          FALSE,
          "");

    WCHAR url[512] = { 0 };
    for (ULONG idx = 0; idx < pCRLDistPoint->cDistPoint; idx++)
    {
        PCRL_DIST_POINT_NAME dpn = &pCRLDistPoint->rgDistPoint[idx].DistPointName;
        for (ULONG ulAltEntry = 0; ulAltEntry < dpn->FullName.cAltEntry; ulAltEntry++)
        {
            if (wcslen(url) > 0)
            {
                wcscat_s(url, 512, L";");
            }
            wcscat_s(url, 512, dpn->FullName.rgAltEntry[ulAltEntry].pwszURL);
        }
    }

    certificate.crlPoint.Set(std::u16string_view{ reinterpret_cast<char16_t*>(url) });

    return TRUE;
}

BOOL GetCertificateSigningTime(const CMSG_SIGNER_INFO_ptr& signer, AuthenticodeMS::Data::Signature& signature)
{
    for (DWORD n = 0; n < signer->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(szOID_RSA_signingTime, signer->AuthAttrs.rgAttr[n].pszObjId) != 0)
        {
            continue;
        }

        FILETIME ft{ 0 };
        DWORD size = sizeof(ft);
        CHECK(CryptDecodeObject(
                    ENCODING,
                    szOID_RSA_signingTime,
                    signer->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    signer->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    (PVOID) &ft,
                    &size),
              false,
              "");

        FILETIME lft{ 0 };
        FileTimeToLocalFileTime(&ft, &lft);

        SYSTEMTIME st{ 0 };
        FileTimeToSystemTime(&lft, &st);

        signature.signingTime.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

        break;
    }

    return true;
}

BOOL GetCounterSigner(
      const CMSG_SIGNER_INFO_ptr& signer,
      CMSG_SIGNER_INFO_ptr& counterSigner,
      WrapperHStore& storeCounterSigner,
      CounterSignatureType& type)
{
    for (DWORD n = 0; n < signer->UnauthAttrs.cAttr; n++)
    {
        // Authenticode
        if (lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
        {
            DWORD dwSize{ 0 };
            CHECK(CryptDecodeObject(
                        ENCODING,
                        PKCS7_SIGNER_INFO,
                        signer->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        signer->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        NULL,
                        &dwSize),
                  false,
                  "");

            counterSigner.reset((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSize));
            CHECK(counterSigner != nullptr, false, "");

            CHECK(CryptDecodeObject(
                        ENCODING,
                        PKCS7_SIGNER_INFO,
                        signer->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        signer->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID) counterSigner.get(),
                        &dwSize),
                  false,
                  "");

            type = CounterSignatureType::Authenticode;

            return true;
        }

        // RFC3161
        if (lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign) == 0)
        {
            WrapperHMsg hMsg{ .handle = CryptMsgOpenToDecode(ENCODING, 0, 0, NULL, NULL, NULL) };
            CHECK(hMsg.handle != NULL, false, "");

            CHECK(CryptMsgUpdate(
                        hMsg.handle, signer->UnauthAttrs.rgAttr[n].rgValue->pbData, signer->UnauthAttrs.rgAttr[n].rgValue->cbData, TRUE),
                  false,
                  "");

            DWORD dwSize{ 0 };
            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSize), false, "");
            CHECK(dwSize != 0, false, "");

            counterSigner.reset((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSize));

            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, counterSigner.get(), &dwSize), false, "");

            CRYPT_DATA_BLOB c7Data{ 0 };
            c7Data.pbData = signer->UnauthAttrs.rgAttr[n].rgValue->pbData;
            c7Data.cbData = signer->UnauthAttrs.rgAttr[n].rgValue->cbData;

            storeCounterSigner.handle = CertOpenStore(CERT_STORE_PROV_PKCS7, ENCODING, NULL, 0, &c7Data);

            type = CounterSignatureType::RFC3161;

            return true;
        }
    }

    return false;
}

#endif

std::optional<AuthenticodeMS> VerifyEmbeddedSignature(ConstString source)
{
    AuthenticodeMS data{};
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
