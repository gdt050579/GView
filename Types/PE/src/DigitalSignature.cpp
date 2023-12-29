#include "DigitalSignature.hpp"

#include <fstream>

#if defined(BUILD_FOR_WINDOWS)
#    if defined(_M_ARM) || defined(_M_ARM64) || defined(_M_HYBRID_X86_ARM64) || defined(_M_ARM64EC) || __arm__ || __aarch64__
#        include <Windows.h>
#        include <Softpub.h>
#        include <wincrypt.h>
#        include <wintrust.h>

// Link with the Wintrust.lib file.
#        pragma comment(lib, "wintrust")

// Link with the Crypt32.lib file.
#        pragma comment(lib, "Crypt32")
#    endif
#endif

namespace GView::DigitalSignature
{
#if defined(BUILD_FOR_WINDOWS)
#    if !(defined(_M_ARM) || defined(_M_ARM64) || defined(_M_HYBRID_X86_ARM64) || defined(_M_ARM64EC) || __arm__ || __aarch64__)
#        include <Windows.h>
#        include <Softpub.h>
#        include <wincrypt.h>
#        include <wintrust.h>

// Link with the Wintrust.lib file.
#        pragma comment(lib, "wintrust")

// Link with the Crypt32.lib file.
#        pragma comment(lib, "Crypt32")
#    endif

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

constexpr uint32 ENCODING = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

using Buffer_ptr             = std::unique_ptr<uint8, decltype(&LocalFree)>;
using CMSG_SIGNER_INFO_ptr   = std::unique_ptr<CMSG_SIGNER_INFO, decltype(&LocalFree)>;
using CERT_CONTEXT_ptr       = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;
using CERT_CHAIN_CONTEXT_ptr = std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&CertFreeCertificateChain)>;

inline void SetErrorMessage(uint32 errorCode, String& message, bool append = false)
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

    if (append)
    {
        if (message.Len() > 0)
        {
            message.Add(" | ");
            message.Add(m.c_str());
        }
    }
    else
    {
        message.Set(m.c_str());
    }
    message.AddFormat(" (0x%x)", errorCode);
}

void ChainErrorStatusToMessage(uint32 status, String& message)
{
    if (status == CERT_TRUST_NO_ERROR)
    {
        message.Add("OK");
        return;
    }

    if ((status & CERT_TRUST_IS_NOT_TIME_VALID) != 0)
    {
        message.Add("This certificate or one of the certificates in the certificate chain is not time-valid.\n");
    }
    if ((status & CERT_TRUST_IS_REVOKED) != 0)
    {
        message.Add("Trust for this certificate or one of the certificates in the certificate chain has been revoked.\n");
    }
    if ((status & CERT_TRUST_IS_NOT_SIGNATURE_VALID) != 0)
    {
        message.Add("The certificate or one of the certificates in the certificate chain does not have a valid signature.\n");
    }
    if ((status & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) != 0)
    {
        message.Add("The certificate or certificate chain is not valid in its proposed usage.");
    }
    if ((status & CERT_TRUST_IS_UNTRUSTED_ROOT) != 0)
    {
        message.Add("The certificate or certificate chain is based on an untrusted root.\n");
    }
    if ((status & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) != 0)
    {
        message.Add("The revocation status of the certificate or one of the certificates in the certificate chain is unknown.\n");
    }
    if ((status & CERT_TRUST_IS_CYCLIC) != 0)
    {
        message.Add("One of the certificates in the chain was issued by a certification authority that the original certificate had "
                    "certified.\n");
    }
    if ((status & CERT_TRUST_IS_PARTIAL_CHAIN) != 0)
    {
        message.Add("The certificate chain is not complete.\n");
    }
    if ((status & CERT_TRUST_CTL_IS_NOT_TIME_VALID) != 0)
    {
        message.Add("A CTL used to create this chain was not time-valid.\n");
    }
    if ((status & CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID) != 0)
    {
        message.Add("A CTL used to create this chain did not have a valid signature.\n");
    }
    if ((status & CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE) != 0)
    {
        message.Add("A CTL used to create this chain did not have a valid signature.\n");
    }
    if ((status & CERT_TRUST_NO_ERROR) != 0)
    {
        message.Add("No error found for this certificate or chain.\n");
    }

    message.Truncate(message.Len() - 1);
}

bool VerifySignatureForPE(ConstString source, Utils::DataCache& cache, AuthenticodeMS& data)
{
    LocalUnicodeStringBuilder<1024> ub;
    ub.Set(source);
    std::u16string sv{ ub.GetString(), ub.Len() };

    std::filesystem::path fullpath{ sv };
    if (!std::filesystem::exists(fullpath)) // must be a memory file from a container => drop it on disk
    {
        auto parent = fullpath.parent_path();
        std::vector<std::filesystem::path> filenames{};
        bool regularFileFound{ (std::filesystem::is_regular_file(parent) && std::filesystem::is_directory(parent) == false) };

        while (parent != parent.parent_path())
        {
            filenames.emplace(filenames.begin(), parent.filename());
            parent = parent.parent_path();
            regularFileFound |= (std::filesystem::is_regular_file(parent) && std::filesystem::is_directory(parent) == false);
        };

        parent = std::filesystem::path(LR"(\\?\)" + parent.lexically_normal().native());

        if (regularFileFound)
        {
            for (const auto& filename : filenames)
            {
                parent /= filename;
                if (std::filesystem::exists(parent) && (std::filesystem::is_regular_file(parent) && std::filesystem::is_directory(parent) == false))
                {
                    parent.replace_filename(filename.u8string() + u8".drop");
                }
            }

            const auto actualFilename = fullpath.filename();
            fullpath                  = parent;
            fullpath /= actualFilename;
        }

        if (!std::filesystem::exists(parent))
        {
            std::error_code ec{};
            if (!std::filesystem::create_directories(parent, ec))
            {
                data.winTrust.errorCode = -1;
                data.winTrust.errorMessage.Set(ec.message());
                return false;
            }
        }

        std::ofstream ofs(fullpath, std::ios::binary);
        if (ofs.is_open())
        {
            const auto buffer = cache.GetEntireFile();
            ofs.write((const char*) buffer.GetData(), buffer.GetLength());
            ofs.close();
        }
        else
        {
            data.winTrust.errorCode = -1;
            data.winTrust.errorMessage.Set("Unable to drop extracted file from container!");
            return false;
        }
    }

    const auto path = fullpath.wstring();
    WINTRUST_FILE_INFO fileData{
        .cbStruct = sizeof(WINTRUST_FILE_INFO), .pcwszFilePath = reinterpret_cast<LPCWSTR>(path.c_str()), .hFile = nullptr, .pgKnownSubject = nullptr
    };

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
                                .dwProvFlags         = WTD_REVOCATION_CHECK_CHAIN,
                                .dwUIContext         = 0 };

    GUID WVTPolicyGUID      = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.winTrust.errorCode = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
    SetErrorMessage(data.winTrust.errorCode, data.winTrust.errorMessage);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    WrapperHStore store{};
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
                &store.handle,
                &hMsg.handle,
                NULL),
          false,
          "");

    DWORD signersNo   = 0;
    DWORD signersSize = sizeof(signersNo);
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, &signersNo, &signersSize), false, "");
    CHECK(signersNo > 0, false, "");

    DWORD signerInfoSize{ 0 };
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize), false, "");

    CMSG_SIGNER_INFO_ptr signerInfo((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, signerInfoSize), LocalFree);
    CHECK(signerInfo != nullptr, false, "");
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signerInfo.get(), &signerInfoSize), false, "");

    CERT_INFO signer{ .SerialNumber = signerInfo->SerialNumber, .Issuer = signerInfo->Issuer };
    CERT_CONTEXT_ptr context(CertFindCertificateInStore(store.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &signer, NULL), CertFreeCertificateContext);
    CHECK(context.get() != nullptr, false, "");

    PCCERT_CHAIN_CONTEXT chainRaw{ nullptr };
    CERT_CHAIN_PARA chainPara{ .cbSize         = sizeof(CERT_CHAIN_PARA),
                               .RequestedUsage = CERT_USAGE_MATCH{ .dwType = USAGE_MATCH_TYPE_AND,
                                                                   .Usage  = CERT_ENHKEY_USAGE{ .cUsageIdentifier = 0, .rgpszUsageIdentifier = NULL } } };
    DWORD certChainFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    CHECK(CertGetCertificateChain(NULL, context.get(), NULL, store.handle, &chainPara, certChainFlags, NULL, &chainRaw), false, "");
    CERT_CHAIN_CONTEXT_ptr chain(chainRaw, CertFreeCertificateChain);
    CHECK(chain.get() != nullptr, false, "");

    data.winTrust.chainErrorCode = chain->TrustStatus.dwErrorStatus;
    ChainErrorStatusToMessage(chain->TrustStatus.dwErrorStatus, data.winTrust.chainErrorMessage);

    CERT_CHAIN_POLICY_PARA chainPolicy    = { .cbSize = sizeof(chainPolicy) };
    CERT_CHAIN_POLICY_STATUS policyStatus = { .cbSize = sizeof(policyStatus) };
    CHECK(CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chain.get(), &chainPolicy, &policyStatus), false, "");

    if (policyStatus.dwError != S_OK)
    {
        data.winTrust.policyErrorCode = policyStatus.dwError;
        SetErrorMessage(policyStatus.dwError, data.winTrust.policyErrorMessage);
    }

    return true;
}

#    pragma pack(push, 1)
struct RFC3161TimestampInfo
{
    void* unknown[9];
    FILETIME timestamp;
};
#    pragma pack(pop)

BOOL GetSignerInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature::Signer& signer);
BOOL GetSignatureSigningTime(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature& signature);
BOOL GetCertificateCRLPoint(const CERT_CONTEXT_ptr& certContext, AuthenticodeMS::Data::Signature::Certificate& certificate);
BOOL GetCertificateInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, const CERT_CONTEXT_ptr& certContext, AuthenticodeMS::Data::Signature::Certificate& certificate);

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
      CounterSignatureType counterSignatureType,
      String& signingTime)
{
    auto& signature                = container.data.signatures.emplace_back();
    signature.signatureType        = signatureType;
    signature.counterSignatureType = counterSignatureType;
    CHECK(GetSignerInfo(signer, signature.signer), false, "");

    CERT_INFO cert{ .SerialNumber = signer->SerialNumber, .Issuer = signer->Issuer };
    CERT_CONTEXT_ptr leaf(CertFindCertificateInStore(store.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &cert, NULL), CertFreeCertificateContext);
    CHECK(leaf != nullptr, false, "");

    PCCERT_CHAIN_CONTEXT chainRaw{ nullptr };
    CERT_CHAIN_PARA chainPara{ .cbSize         = sizeof(CERT_CHAIN_PARA),
                               .RequestedUsage = CERT_USAGE_MATCH{ .dwType = USAGE_MATCH_TYPE_AND,
                                                                   .Usage  = CERT_ENHKEY_USAGE{ .cUsageIdentifier = 0, .rgpszUsageIdentifier = NULL } } };
    DWORD certChainFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    CHECK(CertGetCertificateChain(NULL, leaf.get(), NULL, store.handle, &chainPara, certChainFlags, NULL, &chainRaw), false, "");
    CERT_CHAIN_CONTEXT_ptr chain(chainRaw, CertFreeCertificateChain);
    CHECK(chain.get() != nullptr, false, "");

    std::vector<CERT_CONTEXT_ptr> certs{};
    std::vector<uint32> revocations;
    for (auto i = 0U; i < chain->cChain; i++)
    {
        const auto& simpleChain = chain->rgpChain[i];

        signature.statusCode = simpleChain->TrustStatus.dwErrorStatus;
        ChainErrorStatusToMessage(simpleChain->TrustStatus.dwErrorStatus, signature.status);

        for (auto j = 0U; j < simpleChain->cElement; j++)
        {
            const auto& element = simpleChain->rgpElement[j];
            certs.emplace_back(CertDuplicateCertificateContext(element->pCertContext), CertFreeCertificateContext);

            if (element->pRevocationInfo)
            {
                revocations.push_back(element->pRevocationInfo->dwRevocationResult);
            }
            else
            {
                revocations.push_back(CERT_TRUST_REVOCATION_STATUS_UNKNOWN);
            }
        }
    }

    auto i = 0;
    for (const auto& cert : certs)
    {
        auto& certificate = signature.certificates.emplace_back();
        CHECK(GetCertificateInfo(signer, cert, certificate), false, "");

        const auto& rev = revocations.at(i++);
        if (rev == CERT_TRUST_REVOCATION_STATUS_UNKNOWN || rev == CERT_TRUST_IS_REVOKED || rev == CERT_TRUST_NO_ERROR)
        {
            certificate.revocationResult.Set(
                  rev != CERT_TRUST_REVOCATION_STATUS_UNKNOWN ? rev != CERT_TRUST_IS_REVOKED ? "CERT_TRUST_NO_ERROR" : "CERT_TRUST_IS_REVOKED"
                                                              : "CERT_TRUST_REVOCATION_STATUS_UNKNOWN");
        }
        else
        {
            SetErrorMessage(rev, certificate.revocationResult);
        }
    }

    if (signature.counterSignatureType == CounterSignatureType::RFC3161 && signingTime.Len() > 0)
    {
        signature.signingTime = signingTime;
    }
    else
    {
        CHECK(GetSignatureSigningTime(signer, signature), false, "");
    }

    return TRUE;
}

BOOL Get_szOID_NESTED_SIGNATURE_Signer(const CMSG_SIGNER_INFO_ptr& signer, uint32 attributeIndex, std::vector<CMSG_SIGNER_INFO_ptr>& nestedSigners)
{
    for (uint32 j = 0; j < signer->UnauthAttrs.rgAttr[attributeIndex].cValue; j++)
    {
        WrapperHMsg hMsg{ .handle = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL, NULL) };
        CHECK(hMsg.handle != 0, false, "");

        const auto pbData = signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[j].pbData;
        const auto cbData = signer->UnauthAttrs.rgAttr[attributeIndex].rgValue[j].cbData;
        CHECK(CryptMsgUpdate(hMsg.handle, pbData, cbData, TRUE), false, "");

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

            auto& nestedSigner = nestedSigners.emplace_back(std::move(CMSG_SIGNER_INFO_ptr((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo), LocalFree)));
            CHECK(nestedSigner.get() != nullptr, false, "");

            CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, i, (PVOID) nestedSigner.get(), &dwSignerInfo), false, "");
            CHECK(dwSignerInfo != 0, false, "");
        }
    }

    return TRUE;
}

BOOL ParseSigner(const CMSG_SIGNER_INFO_ptr& signer, AuthenticodeMS& container, const WrapperHStore& store)
{
    CHECK(signer != nullptr, false, "");

    for (DWORD n = 0; n < signer->UnauthAttrs.cAttr; n++)
    {
        if (signer->UnauthAttrs.rgAttr[n].pszObjId == nullptr)
        {
            continue;
        }

        // Authenticode
        if (lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
        {
            CMSG_SIGNER_INFO_ptr cSigner(nullptr, LocalFree);
            CHECK(Get_szOID_RSA_counterSign_Signer(signer, n, cSigner), false, "");
            String signingTime;
            CHECK(GetInfoThroughSigner(container, cSigner, store, SignatureType::CounterSignature, CounterSignatureType::Authenticode, signingTime), false, "");
            CHECK(ParseSigner(cSigner, container, store), false, "");
        }

        // RFC3161
        else if (lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign) == 0)
        {
            std::vector<CMSG_SIGNER_INFO_ptr> cSigners;
            CHECK(Get_szOID_NESTED_SIGNATURE_Signer(signer, n, cSigners), false, "");

            auto i = 0;
            for (const auto& cSigner : cSigners)
            {
                WrapperHMsg msg{ .handle = CryptMsgOpenToDecode(ENCODING, 0, 0, NULL, NULL, NULL) };
                const auto pbData = signer->UnauthAttrs.rgAttr[n].rgValue[i].pbData;
                const auto cbData = signer->UnauthAttrs.rgAttr[n].rgValue[i].cbData;
                CHECK(CryptMsgUpdate(msg.handle, pbData, cbData, TRUE), false, "");

                DWORD contentSize{ 0 };
                CHECK(CryptMsgGetParam(msg.handle, CMSG_CONTENT_PARAM, 0, NULL, &contentSize), false, "");

                Buffer_ptr content((uint8*) LocalAlloc(NULL, contentSize), LocalFree);
                CHECK(content != nullptr, false, "");
                CHECK(CryptMsgGetParam(msg.handle, CMSG_CONTENT_PARAM, 0, content.get(), &contentSize), false, "");

                DWORD size{ 0 };
                uint8* rt = NULL;
                CHECK(CryptDecodeObjectEx(ENCODING, TIMESTAMP_INFO, content.get(), contentSize, CRYPT_DECODE_ALLOC_FLAG, NULL, &rt, &size), false, "");
                Buffer_ptr timestampBuffer(rt, LocalFree);

                const auto timestamp = reinterpret_cast<RFC3161TimestampInfo*>(rt);

                SYSTEMTIME st{ 0 };
                FileTimeToSystemTime(&timestamp->timestamp, &st);
                String signingTime;
                signingTime.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

                CRYPT_DATA_BLOB data{ 0 };
                data.pbData = signer->UnauthAttrs.rgAttr[n].rgValue[i].pbData;
                data.cbData = signer->UnauthAttrs.rgAttr[n].rgValue[i++].cbData;

                WrapperHStore store{ .handle = CertOpenStore(CERT_STORE_PROV_PKCS7, ENCODING, NULL, 0, &data) };

                CHECK(GetInfoThroughSigner(container, cSigner, store, SignatureType::CounterSignature, CounterSignatureType::RFC3161, signingTime), false, "");
                CHECK(ParseSigner(cSigner, container, store), false, "");
            }
        }

        else if (lstrcmpA(signer->UnauthAttrs.rgAttr[n].pszObjId, szOID_NESTED_SIGNATURE) == 0)
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
                String signingTime;
                CHECK(GetInfoThroughSigner(container, nestedSigner, store, SignatureType::Signature, CounterSignatureType::Unknown, signingTime), false, "");
                CHECK(ParseSigner(nestedSigner, container, store), false, "");
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

    WrapperHStore store{};
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
                &store.handle,
                &hMsg.handle,
                NULL),
          false,
          "");

    DWORD signersNo   = 0;
    DWORD signersSize = sizeof(signersNo);
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, &signersNo, &signersSize), false, "");
    CHECK(signersNo > 0, false, "");

    DWORD signerInfoSize{ 0 };
    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize), false, "");

    CMSG_SIGNER_INFO_ptr signer((PCMSG_SIGNER_INFO) LocalAlloc(LPTR, signerInfoSize), LocalFree);
    CHECK(signer != nullptr, false, "");

    CHECK(CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signer.get(), &signerInfoSize), false, "");

    auto& pkSignature = container.data.signatures.emplace_back();
    auto& pkSigner    = pkSignature.signer;
    CHECK(GetSignerInfo(signer, pkSigner), false, "");

    CERT_INFO cert{ .SerialNumber = signer->SerialNumber, .Issuer = signer->Issuer };
    const CERT_CONTEXT_ptr leaf(CertFindCertificateInStore(store.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &cert, NULL), CertFreeCertificateContext);
    CHECK(leaf != nullptr, false, "");

    PCCERT_CHAIN_CONTEXT chainRaw{ nullptr };
    CERT_CHAIN_PARA chainPara{ .cbSize         = sizeof(CERT_CHAIN_PARA),
                               .RequestedUsage = CERT_USAGE_MATCH{ .dwType = USAGE_MATCH_TYPE_AND,
                                                                   .Usage  = CERT_ENHKEY_USAGE{ .cUsageIdentifier = 0, .rgpszUsageIdentifier = NULL } } };
    DWORD certChainFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    CHECK(CertGetCertificateChain(NULL, leaf.get(), NULL, store.handle, &chainPara, certChainFlags, NULL, &chainRaw), false, "");
    CERT_CHAIN_CONTEXT_ptr chain(chainRaw, CertFreeCertificateChain);
    CHECK(chain.get() != nullptr, false, "");

    std::vector<CERT_CONTEXT_ptr> certs{};
    std::vector<uint32> revocations;
    for (auto i = 0U; i < chain->cChain; i++)
    {
        const auto& simpleChain = chain->rgpChain[i];

        pkSignature.statusCode = simpleChain->TrustStatus.dwErrorStatus;
        ChainErrorStatusToMessage(simpleChain->TrustStatus.dwErrorStatus, pkSignature.status);

        for (auto j = 0U; j < simpleChain->cElement; j++)
        {
            const auto& element = simpleChain->rgpElement[j];
            certs.emplace_back(CertDuplicateCertificateContext(element->pCertContext), CertFreeCertificateContext);

            if (element->pRevocationInfo)
            {
                revocations.push_back(element->pRevocationInfo->dwRevocationResult);
            }
            else
            {
                revocations.push_back(CERT_TRUST_REVOCATION_STATUS_UNKNOWN);
            }
        }
    }

    auto i = 0;
    for (const auto& cert : certs)
    {
        auto& certificate = pkSignature.certificates.emplace_back();
        CHECK(GetCertificateInfo(signer, cert, certificate), false, "");

        const auto& rev = revocations.at(i++);
        if (rev == CERT_TRUST_REVOCATION_STATUS_UNKNOWN || rev == CERT_TRUST_IS_REVOKED || rev == CERT_TRUST_NO_ERROR)
        {
            const auto result = rev != CERT_TRUST_REVOCATION_STATUS_UNKNOWN ? (rev != CERT_TRUST_IS_REVOKED ? "CERT_TRUST_NO_ERROR" : "CERT_TRUST_IS_REVOKED")
                                                                            : "CERT_TRUST_REVOCATION_STATUS_UNKNOWN";
            certificate.revocationResult.Set(result);
        }
        else
        {
            SetErrorMessage(rev, certificate.revocationResult);
        }
    }

    CHECK(GetSignatureSigningTime(signer, pkSignature), false, "");
    pkSignature.signatureType = SignatureType::Signature;

    CHECK(ParseSigner(signer, container, store), false, "");

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

BOOL GetCertificateInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, const CERT_CONTEXT_ptr& certContext, AuthenticodeMS::Data::Signature::Certificate& certificate)
{
    LocalString<1024> ls;
    const auto serialNumberSize = certContext->pCertInfo->SerialNumber.cbData;
    for (DWORD n = 0; n < serialNumberSize; n++)
    {
        CHECK(ls.AddFormat("%02x", certContext->pCertInfo->SerialNumber.pbData[serialNumberSize - (n + 1)]), false, "");
    }
    certificate.serialNumber.Set(ls.GetText(), ls.Len());

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

    SYSTEMTIME st{ 0 };

    const auto& dateNotAfter = certContext->pCertInfo->NotAfter;
    FileTimeToSystemTime(&dateNotAfter, &st);
    certificate.notAfter.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    const auto& dateNotBefore = certContext->pCertInfo->NotBefore;
    FileTimeToSystemTime(&dateNotBefore, &st);
    certificate.notBefore.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

    CHECK(GetCertificateCRLPoint(certContext, certificate), false, "");

    return true;
}

BOOL GetSignerInfo(const CMSG_SIGNER_INFO_ptr& signerInfo, AuthenticodeMS::Data::Signature::Signer& signer)
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
    const auto cExtension     = certContext->pCertInfo->cExtension;
    const auto rgExtension    = certContext->pCertInfo->rgExtension;
    PCERT_EXTENSION extension = CertFindExtension(szOID_CRL_DIST_POINTS, cExtension, rgExtension);
    CHECK(extension, TRUE, "");

    constexpr uint32 DATA_SIZE = 512;
    BYTE btData[DATA_SIZE]     = { 0 };
    auto pCRLDistPoint         = (PCRL_DIST_POINTS_INFO) btData;
    ULONG dataLength           = DATA_SIZE;
    const auto pbData          = extension->Value.pbData;
    const auto cbData          = extension->Value.cbData;
    CHECK(CryptDecodeObject(ENCODING, szOID_CRL_DIST_POINTS, pbData, cbData, CRYPT_DECODE_NOCOPY_FLAG, pCRLDistPoint, &dataLength), FALSE, "");

    WCHAR url[DATA_SIZE] = { 0 };
    for (ULONG idx = 0; idx < pCRLDistPoint->cDistPoint; idx++)
    {
        PCRL_DIST_POINT_NAME dpn = &pCRLDistPoint->rgDistPoint[idx].DistPointName;
        for (ULONG ulAltEntry = 0; ulAltEntry < dpn->FullName.cAltEntry; ulAltEntry++)
        {
            if (wcslen(url) > 0)
            {
                wcscat_s(url, DATA_SIZE, L";");
            }
            wcscat_s(url, DATA_SIZE, dpn->FullName.rgAltEntry[ulAltEntry].pwszURL);
        }
    }

    certificate.crlPoint.Set(std::u16string_view{ reinterpret_cast<char16_t*>(url) });

    return TRUE;
}

BOOL GetSignatureSigningTime(const CMSG_SIGNER_INFO_ptr& signer, AuthenticodeMS::Data::Signature& signature)
{
    for (DWORD n = 0; n < signer->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(szOID_RSA_signingTime, signer->AuthAttrs.rgAttr[n].pszObjId) != 0)
        {
            continue;
        }

        FILETIME ft{ 0 };
        DWORD size        = sizeof(ft);
        const auto pbData = signer->AuthAttrs.rgAttr[n].rgValue[0].pbData;
        const auto cbData = signer->AuthAttrs.rgAttr[n].rgValue[0].cbData;
        CHECK(CryptDecodeObject(ENCODING, szOID_RSA_signingTime, pbData, cbData, 0, (PVOID) &ft, &size), false, "");

        FILETIME lft{ 0 };
        CHECK(FileTimeToLocalFileTime(&ft, &lft), false, "");

        SYSTEMTIME st{ 0 };
        CHECK(FileTimeToSystemTime(&lft, &st), false, "");

        signature.signingTime.Format("%02d/%02d/%04d %02d:%02d:%02d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

        break;
    }

    return true;
}

#endif
} // namespace GView::DigitalSignature
