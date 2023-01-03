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

struct WrapperPKCS7
{
    PKCS7* data = nullptr;

    ~WrapperPKCS7()
    {
        PKCS7_free(data);
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

bool PKCS7ToStructure(const Buffer& buffer, Signature& output)
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
    // ASN1_OCTET_STRING** pos = &pkcs7.data->d.data; // no need to free (pointer from CMS structure)
    // GetError(error, output.errorMessage);
    // if (pos && (*pos))
    //{
    //     output.snContent.Resize((*pos)->length);
    //     memcpy(output.snContent.GetData(), (*pos)->data, (*pos)->length);
    // }

    PKCS7_ISSUER_AND_SERIAL* issuerAndSerial = PKCS7_get_issuer_and_serial(pkcs7.data, 0);
    if (issuerAndSerial != nullptr)
    {
        WrapperBIGNUM bnser{ .data = ASN1_INTEGER_to_BN(issuerAndSerial->serial, nullptr) };
        output.sn = BN_bn2hex(bnser.data);
    }

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

            // PKCS7_dataVerify(cert_store, &cert_ctx, mybio, p7, si);
            // if (PKCS7_signatureVerify(pkcs7bio, s->reply_p7, si, cert_cacert) <= 0)
            /*

                rc = PKCS7_dataVerify(cert_store, &vctx.x509_ctx, p7bio,p7, si);
        if (rc <= 0 || vctx.err != X509_V_OK)
        {
            char tbuf[120];

            if (rc <= 0)
            {
                fz_strlcpy(ebuf, ERR_error_string(ERR_get_error(), tbuf), ebufsize);
            }
            else
            {
                // / Error while checking the certificate chain /
            snprintf(ebuf, ebufsize, "%s(%d): %s", X509_verify_cert_error_string(vctx.err), vctx.err, vctx.certdesc);
            }

            res = 0;
            goto exit;
        }
            */

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
            else
            {
                throw std::runtime_error("Unknown hash!");
            }
        }
    }

    output.error = false;

    return true;
}

bool PKCS7VerifySignature(const Buffer& buffer, String& output)
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
    uint32 ContentSize{ 0 };
    if ((asn1Byte & 0x80) == 0)
    {
        //
        // Short Form of Length Encoding (Length < 128)
        //
        ContentSize = (uint32) (asn1Byte & 0x7F);
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
        ContentSize = (uint32) (*(uint8*) (spcIndirectDataContent + 2));
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
        ContentSize = (uint32) (*(uint8*) (spcIndirectDataContent + 2));
        ContentSize = (ContentSize << 8) + (uint32) (*(uint8*) (spcIndirectDataContent + 3));
        //
        // Skip the SEQUENCE Tag;
        //
        spcIndirectDataContent += 4;
    }
    else
    {
        RETURNERROR(false, "");
    }

    //
    // Compare the original file hash value to the digest retrieve from SpcIndirectDataContent
    // defined in Authenticode
    // NOTE: Need to double-check HashLength here!
    //
    // if (memcmp(spcIndirectDataContent + ContentSize - HashSize, ImageHash, HashSize) != 0)
    // {
    //     //
    //     // Un-matched PE/COFF Hash Value
    //     //
    //     goto _Exit;
    // }

    //
    // Verifies the PKCS#7 Signed Data in PE/COFF Authenticode Signature
    //
    // Status = (BOOLEAN) Pkcs7Verify(OrigAuthData, DataSize, TrustedCert, CertSize, SpcIndirectDataContent, ContentSize);

    return true;
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
        std::vector<std::string> authAttrs2;
    }

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

bool CMSToStructure(const Buffer& buffer, Signature& output)
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

bool __VerifyEmbeddedSignature__(ConstString source, SignatureData& data)
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

BOOL GetOpusInfo(PCMSG_SIGNER_INFO pSignerInfo, SignatureData::Information::Certificate& certificate);
BOOL GetCertDate(const WrapperSignerInfo& signerInfo, SignatureData::Information::Certificate& certificate);
BOOL GetCertificateInfo(
      const WrapperSignerInfo& signerInfo, const WrapperCertContext& certContext, SignatureData::Information::Certificate& certificate);
BOOL GetCounterSigner(
      const WrapperSignerInfo& signer, WrapperSignerInfo& counterSigner, WrapperHStore& storeCounterSigner, CounterSignatureType& type);
BOOL Get2ndSignature(const WrapperSignerInfo& signer, SignatureData::Information& info);

bool GetSignaturesInformation(ConstString source, SignatureData& data)
{
    LocalUnicodeStringBuilder<1024> ub;
    ub.Set(source);
    std::u16string sv{ ub.GetString(), ub.Len() };

    WrapperHStore hStore{};
    WrapperHMsg hMsg{};
    data.information.callSuccessful = CryptQueryObject(
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
          NULL);

    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.winTrust.errorMessage);
        RETURNERROR(false, "");
    }

    DWORD dwCountSigners            = 0;
    DWORD dwcbSz                    = sizeof(dwCountSigners);
    data.information.callSuccessful = CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_COUNT_PARAM, 0, &dwCountSigners, &dwcbSz);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.winTrust.errorMessage);
        RETURNERROR(false, "");
    }
    CHECK(dwCountSigners > 0, false, "");

    DWORD dwSignerInfo{ 0 };
    data.information.callSuccessful = CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.winTrust.errorMessage);
        RETURNERROR(false, "");
    }

    WrapperSignerInfo signerInfo{ .info = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo) };
    data.information.callSuccessful = (signerInfo.info != nullptr);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.winTrust.errorMessage);
        RETURNERROR(false, "");
    }

    data.information.callSuccessful = CryptMsgGetParam(hMsg.handle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID) signerInfo.info, &dwSignerInfo);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.information.errorMessage);
        RETURNERROR(false, "");
    }

    auto& signature0 = data.information.signatures.emplace_back();

    data.information.callSuccessful = GetOpusInfo(signerInfo.info, signature0);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode    = GetLastError();
        data.information.errorMessage = "GetProgAndPublisherInfo call failed!";
        RETURNERROR(false, "");
    }

    data.information.callSuccessful = GetCertDate(signerInfo, signature0);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode    = GetLastError();
        data.information.errorMessage = "GetCertDate call failed!";
        RETURNERROR(false, "");
    }

    CERT_INFO certInfo{ .SerialNumber = signerInfo.info->SerialNumber, .Issuer = signerInfo.info->Issuer };

    WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                          hStore.handle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };
    data.information.callSuccessful = (certContext.context != nullptr);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode = GetLastError();
        SetErrorMessage(data.information.errorCode, data.information.errorMessage);
        RETURNERROR(false, "");
    }

    signature0.signatureType        = SignatureType::Signature;
    data.information.callSuccessful = GetCertificateInfo(signerInfo, certContext, signature0);
    if (!data.information.callSuccessful)
    {
        data.information.errorCode    = GetLastError();
        data.information.errorMessage = "GetCertificateInfo call failed!";
        RETURNERROR(false, "");
    }

    WrapperSignerInfo counterSignerInfo{};
    WrapperHStore storeCounterSigner{};
    WrapperCertContext counterSignerCertContext{};
    CounterSignatureType counterSignatureType{ CounterSignatureType::None };
    if (GetCounterSigner(signerInfo, counterSignerInfo, storeCounterSigner, counterSignatureType))
    {
        if (counterSignerInfo.info != nullptr)
        {
            auto& counterSignature0                = data.information.signatures.emplace_back();
            counterSignature0.counterSignatureType = counterSignatureType;

            certInfo.Issuer       = counterSignerInfo.info->Issuer;
            certInfo.SerialNumber = counterSignerInfo.info->SerialNumber;

            const auto& scHandle = storeCounterSigner.handle != 0 ? storeCounterSigner.handle : hStore.handle;

            WrapperCertContext certContext{ .context = CertFindCertificateInStore(
                                                  scHandle, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID) &certInfo, NULL) };

            data.information.callSuccessful = (certContext.context != nullptr);
            if (!data.information.callSuccessful)
            {
                data.information.errorCode = GetLastError();
                SetErrorMessage(data.information.errorCode, data.information.errorMessage);
                RETURNERROR(false, "");
            }

            GetCertificateInfo(counterSignerInfo, certContext, counterSignature0);
            GetCertDate(counterSignerInfo, counterSignature0);
            GetOpusInfo(counterSignerInfo.info, counterSignature0);
            counterSignature0.signatureType = SignatureType::CounterSignature;
        }
    }

    Get2ndSignature(signerInfo, data.information);

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
      const WrapperSignerInfo& signerInfo, const WrapperCertContext& certContext, SignatureData::Information::Certificate& certificate)
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

BOOL GetOpusInfo(PCMSG_SIGNER_INFO signerInfo, SignatureData::Information::Certificate& certificate)
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

BOOL GetCertDate(const WrapperSignerInfo& signer, SignatureData::Information::Certificate& certificate)
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

BOOL Get2ndSignature(const WrapperSignerInfo& signer, SignatureData::Information& info)
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

std::optional<SignatureData> VerifyEmbeddedSignature(ConstString source)
{
    SignatureData data{};
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
