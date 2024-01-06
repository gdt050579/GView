#include "Authenticode.hpp"

namespace Authenticode
{
// clang-format off
ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcPeImageData) = {
	ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
	ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)
IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)
IMPLEMENT_ASN1_FUNCTIONS(SpcLink)
IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)
IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)
IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)
IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)
IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)
IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)


struct SIGNATURE
{
    PKCS7* p7;
    int md_nid;
    ASN1_STRING* digest;
    time_t signtime;
    char* url;
    char* desc;
    const unsigned char* purpose;
    const unsigned char* level;
    CMS_ContentInfo* timestamp;
    time_t time;
    ASN1_STRING* blob;
} ;

DEFINE_STACK_OF(SIGNATURE)
DECLARE_ASN1_FUNCTIONS(SIGNATURE)

/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
 */
typedef struct
{
    AlgorithmIdentifier* digestAlgorithm;
    ASN1_OCTET_STRING* digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = { ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
                                  ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING) } ASN1_SEQUENCE_END(MessageImprint)

      IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

            typedef struct
{
    ASN1_INTEGER* seconds;
    ASN1_INTEGER* millis;
    ASN1_INTEGER* micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

ASN1_SEQUENCE(TimeStampAccuracy) = { ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
                                     ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
                                     ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1) } ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)

struct TimeStampToken
{
    ASN1_INTEGER* version;
    ASN1_OBJECT* policy_id;
    MessageImprint* messageImprint;
    ASN1_INTEGER* serial;
    ASN1_GENERALIZEDTIME* time;
    TimeStampAccuracy* accuracy;
    ASN1_BOOLEAN ordering;
    ASN1_INTEGER* nonce;
    GENERAL_NAME* tsa;
    STACK_OF(X509_EXTENSION) * extensions;
} ;

DECLARE_ASN1_FUNCTIONS(TimeStampToken)

ASN1_SEQUENCE(
      TimeStampToken) = { ASN1_SIMPLE(TimeStampToken, version, ASN1_INTEGER),
                          ASN1_SIMPLE(TimeStampToken, policy_id, ASN1_OBJECT),
                          ASN1_SIMPLE(TimeStampToken, messageImprint, MessageImprint),
                          ASN1_SIMPLE(TimeStampToken, serial, ASN1_INTEGER),
                          ASN1_SIMPLE(TimeStampToken, time, ASN1_GENERALIZEDTIME),
                          ASN1_OPT(TimeStampToken, accuracy, TimeStampAccuracy),
                          ASN1_OPT(TimeStampToken, ordering, ASN1_FBOOLEAN),
                          ASN1_OPT(TimeStampToken, nonce, ASN1_INTEGER),
                          ASN1_EXP_OPT(TimeStampToken, tsa, GENERAL_NAME, 0),
                          ASN1_IMP_SEQUENCE_OF_OPT(TimeStampToken, extensions, X509_EXTENSION, 1) } ASN1_SEQUENCE_END(TimeStampToken)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampToken)
;
/* clang-format on */

constexpr auto MAX_NESTED_COUNT = 16;

static SpcIndirectDataContent* GetContent(PKCS7* content)
{
    if (!content)
        return nullptr;

    if (OBJ_obj2nid(content->type) != OBJ_txt2nid(NID_spc_indirect_data))
        return nullptr;

    SpcIndirectDataContent* spcContent = SpcIndirectDataContent_new();
    if (!spcContent)
        return nullptr;

    int len             = content->d.other->value.sequence->length;
    const uint8_t* data = content->d.other->value.sequence->data;

    d2i_SpcIndirectDataContent(&spcContent, &data, len);

    return spcContent;
}

bool ParseOpusInfo(ASN1_TYPE* spcAttr, Signer signer)
{
    const auto* sdata      = spcAttr->value.sequence->data;
    SpcSpOpusInfo* spcInfo = d2i_SpcSpOpusInfo(nullptr, &sdata, spcAttr->value.sequence->length);
    if (!spcInfo)
        return false;

    uint8_t* dataRaw = nullptr;
    OpenSSL_ptr data(dataRaw, My_OpenSSL_free);

    if (spcInfo->programName)
    {
        /* Should be Windows UTF16..., try to convert it to UTF8 */
        int nameLen = ASN1_STRING_to_UTF8(&dataRaw, spcInfo->programName->value.unicode);
        data.reset(dataRaw);
        if (nameLen >= 0 && nameLen < spcAttr->value.sequence->length)
        {
            signer.programName.resize(nameLen + 1);
            memcpy(signer.programName.data(), data.get(), nameLen);
            signer.programName.data()[nameLen] = 0;
        }
    }

    if (spcInfo->moreInfo)
    {
        if (spcInfo->moreInfo->type == (uint32_t) SPCLinkChoice::SPC_URL_LINK_CHOICE)
        {
            /* Should be Windows UTF16..., try to convert it to UTF8 */
            int nameLen = ASN1_STRING_to_UTF8(&dataRaw, spcInfo->moreInfo->value.url);
            data.reset(dataRaw);
            if (nameLen >= 0 && nameLen < spcInfo->moreInfo->value.url->length)
            {
                signer.moreInfoLink.resize(nameLen + 1ULL);
                memcpy(signer.moreInfoLink.data(), data.get(), nameLen);
                signer.moreInfoLink.data()[nameLen] = 0;
            }
        }
        else if (spcInfo->moreInfo->type == (uint32_t) SPCLinkChoice::SPC_FILE_LINK_CHOICE)
        {
            /* Should be Windows UTF16..., try to convert it to UTF8 */
            int nameLen = ASN1_STRING_to_UTF8(&dataRaw, spcInfo->moreInfo->value.file->value.unicode);
            data.reset(dataRaw);
            if (nameLen >= 0 && nameLen < spcInfo->moreInfo->value.file->value.unicode->length)
            {
                signer.moreInfoLink.resize(nameLen + 1ULL);
                memcpy(signer.moreInfoLink.data(), data.get(), nameLen);
                signer.moreInfoLink.data()[nameLen] = 0;
            }
        }
    }

    if (spcInfo->publisherInfo)
    {
        if (spcInfo->publisherInfo->type == (uint32_t) SPCLinkChoice::SPC_URL_LINK_CHOICE)
        {
            /* Should be Windows UTF16..., try to convert it to UTF8 */
            int nameLen = ASN1_STRING_to_UTF8(&dataRaw, spcInfo->publisherInfo->value.url);
            data.reset(dataRaw);
            if (nameLen >= 0 && nameLen < spcInfo->publisherInfo->value.url->length)
            {
                signer.publishLink.resize(nameLen + 1ULL);
                memcpy(signer.publishLink.data(), data.get(), nameLen);
                signer.publishLink.data()[nameLen] = 0;
            }
        }
        else if (spcInfo->publisherInfo->type == (uint32_t) SPCLinkChoice::SPC_FILE_LINK_CHOICE)
        {
            /* Should be Windows UTF16..., try to convert it to UTF8 */
            int nameLen = ASN1_STRING_to_UTF8(&dataRaw, spcInfo->publisherInfo->value.file->value.unicode);
            data.reset(dataRaw);
            if (nameLen >= 0 && nameLen < spcInfo->publisherInfo->value.file->value.unicode->length)
            {
                signer.publishLink.resize(nameLen + 1ULL);
                memcpy(signer.publishLink.data(), data.get(), nameLen);
                signer.publishLink.data()[nameLen] = 0;
            }
        }
    }

    SpcSpOpusInfo_free(spcInfo);
    return true;
}

static void ParseCertificates(const STACK_OF(X509) * certs, std::vector<Certificate>& result)
{
    for (int i = 0; i < sk_X509_num(certs); ++i)
    {
        result.emplace_back().Parse(sk_X509_value(certs, i));
    }
}

void AuthenticodeParser::ParseNestedAuthenticode(PKCS7_SIGNER_INFO* si, std::vector<AuthenticodeSignature>& auth)
{
    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);
    int idx                         = X509at_get_attr_by_NID(attrs, OBJ_txt2nid(NID_spc_nested_signature), -1);
    X509_ATTRIBUTE* attr            = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    /* Limit the maximum amount of nested attributes to be safe from malformed samples */
    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i)
    {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == nullptr)
            break;
        int len             = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;
        AuthenticodeParseSignature(data, len, auth);
    }
}

static void ParsePKCS9Countersignature(PKCS7_ptr& p7, AuthenticodeSignature& auth)
{
    PKCS7_SIGNER_INFO* si(sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7.get()), 0));

    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);

    int idx = X509at_get_attr_by_NID(attrs, NID_pkcs9_countersignature, -1);
    if (idx == -1) // failure, try by object
    {
        const ASN1_OBJECT_ptr RFC3161_counterSign(OBJ_txt2obj("1.3.6.1.4.1.311.3.3.1", 1), ASN1_OBJECT_free);
        idx = X509at_get_attr_by_OBJ(attrs, RFC3161_counterSign.get(), -1);
    }
    X509_ATTRIBUTE* attr = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i)
    {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == nullptr)
            break;
        int len             = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;

        auth.counterSignatures.emplace_back().ParsePKCS9(data, len, p7->d.sign->cert, si->enc_digest, si);
    }
}

static void ExtractCertificatesFromMSCountersignature(const uint8_t* data, int len, std::vector<Certificate>& result)
{
    PKCS7_ptr p7(d2i_PKCS7(nullptr, &data, len), PKCS7_free);
    if (!p7)
        return;

    STACK_OF(X509)* certs = p7->d.sign->cert;
    ParseCertificates(certs, result);
}

static void ParseMSCountersignature(PKCS7_ptr& p7, AuthenticodeSignature& auth)
{
    PKCS7_SIGNER_INFO* si           = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7.get()), 0);
    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);

    int idx = X509at_get_attr_by_NID(attrs, OBJ_txt2nid(NID_spc_ms_countersignature), -1);

    const ASN1_OBJECT_ptr RSA_counterSign(OBJ_txt2obj("1.2.840.113549.1.9.6", 1), ASN1_OBJECT_free);
    const ASN1_OBJECT_ptr NestedSignature(OBJ_txt2obj("1.3.6.1.4.1.311.2.4.1", 1), ASN1_OBJECT_free);

    X509_ATTRIBUTE* attr = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i)
    {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == nullptr)
            break;
        int len             = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;

        /* Because MS TimeStamp countersignature has it's own SET of certificates
         * extract it back into parent signature for consistency with PKCS9 */
        auth.counterSignatures.emplace_back().ParseMS(data, len, si->enc_digest);
        ExtractCertificatesFromMSCountersignature(data, len, auth.certs);
    }
}

static bool AuthenticodeVerify(PKCS7_ptr& p7, PKCS7_SIGNER_INFO* si, X509* signCert)
{
    const uint8_t* contentData = p7->d.sign->contents->d.other->value.sequence->data;
    long contentLen             = p7->d.sign->contents->d.other->value.sequence->length;

    uint64_t version = 0;
    ASN1_INTEGER_get_uint64(&version, p7->d.sign->version);
    if (version == 1)
    {
        /* Move the pointer to the actual contents - skip OID and length */
        int pclass = 0, ptag = 0;
        ASN1_get_object(&contentData, &contentLen, &ptag, &pclass, contentLen);
    }

    BIO* contentBio = BIO_new_mem_buf(contentData, static_cast<int>(contentLen));
    /* Create `digest` type BIO to calculate content digest for verification */
    BIO* p7bio = PKCS7_dataInit(p7.get(), contentBio);

    char buf[4096];
    /* We now have to 'read' from p7bio to calculate content digest */
    while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
        continue;

    /* Pass it to the PKCS7_signatureVerify, to do the hard work for us */
    bool isValid = PKCS7_signatureVerify(p7bio, p7.get(), si, signCert) == 1;

    BIO_free_all(p7bio);

    return isValid;
}

AuthenticodeParser::AuthenticodeParser() : signatures()
{
    OBJ_create(NID_spc_info, "spcSpOpusInfo", "SPC_SP_OPUS_INFO_OBJID");
    OBJ_create(NID_spc_ms_countersignature, "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE");
    OBJ_create(NID_spc_nested_signature, "spcNestedSignature", "SPC_NESTED_SIGNATUREs");
    OBJ_create(NID_spc_indirect_data, "spcIndirectData", "SPC_INDIRECT_DATA");
}

bool AuthenticodeParser::AuthenticodeParseSignature(const uint8_t* data, long len, std::vector<AuthenticodeSignature>& result)
{
    if (!data || len == 0)
        return false;

    AuthenticodeSignature auth{};

    /* Let openssl parse the PKCS7 structure */
    PKCS7_ptr p7(d2i_PKCS7(nullptr, &data, len), PKCS7_free);
    if (!p7)
    {
        auth.verifyFlags = (int) AuthenticodeVFY::CantParse;
        return false;
    }

    /* We expect SignedData type of PKCS7 */
    if (!PKCS7_type_is_signed(p7))
    {
        auth.verifyFlags = (int) AuthenticodeVFY::WrongPKCS7Type;
        return false;
    }

    PKCS7_SIGNED* p7data = p7->d.sign;

    uint64_t version = 0;
    if (ASN1_INTEGER_get_uint64(&version, p7data->version))
        auth.version = version;

    STACK_OF(X509)* certs = p7data->cert;
    ParseCertificates(certs, auth.certs);

    /* Get Signature content that contains the message digest and it's algorithm */
    SpcIndirectDataContent* dataContent = GetContent(p7data->contents);
    if (!dataContent)
    {
        auth.verifyFlags = (int) AuthenticodeVFY::BadContent;
        return false;
    }

    DigestInfo* messageDigest = dataContent->messageDigest;

    int digestnid = OBJ_obj2nid(messageDigest->digestAlgorithm->algorithm);
    auth.digestAlg.assign(OBJ_nid2ln(digestnid));

    int digestLen             = messageDigest->digest->length;
    const uint8_t* digestData = messageDigest->digest->data;
    auth.digest.insert(auth.digest.end(), digestData, digestData + digestLen);

    SpcIndirectDataContent_free(dataContent);

    /* Authenticode is supposed to have only one SignerInfo value
     * that contains all information for actual signing purposes
     * and nested signatures or countersignatures */
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7.get()), 0);
    if (!si)
    {
        auth.verifyFlags = (int) AuthenticodeVFY::NoSignerInfo;
        return false;
    }

    /* Authenticode can contain SET of nested Authenticode signatures
     * and countersignatures in unauthenticated attributes */
    ParseNestedAuthenticode(si, result);
    ParsePKCS9Countersignature(p7, auth);
    // ParseMSCountersignature(p7, auth);

    /* Get the signing certificate for the first SignerInfo */
    STACK_OF(X509)* signCertStack = PKCS7_get0_signers(p7.get(), certs, 0);

    X509* signCert = sk_X509_value(signCertStack, 0);
    if (!signCert)
    {
        auth.verifyFlags = (int) AuthenticodeVFY::NoSignerCert;
        sk_X509_free(signCertStack);
        return false;
    }

    sk_X509_free(signCertStack);

    auth.signer.chain = ParseSignerChain(signCert, certs);

    /* Get the Signers digest of Authenticode content */
    ASN1_TYPE* digest = PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
    if (!digest)
    {
        auth.verifyFlags = (int) AuthenticodeVFY::DigestMissing;
        return false;
    }

    digestnid = OBJ_obj2nid(si->digest_alg->algorithm);
    auth.signer.digestAlg.assign(OBJ_nid2ln(digestnid));

    digestLen  = digest->value.asn1_string->length;
    digestData = digest->value.asn1_string->data;
    auth.signer.digest.insert(auth.signer.digest.end(), digestData, digestData + digestLen);

    /* Authenticode stores optional programName in non-optional SpcSpOpusInfo attribute */
    ASN1_TYPE* spcInfo = PKCS7_get_signed_attribute(si, OBJ_txt2nid(NID_spc_info));
    if (spcInfo)
    {
        ParseOpusInfo(spcInfo, auth.signer);
    }

    /* If we got to this point, we got all we need to start verifying */
    bool isValid = AuthenticodeVerify(p7, si, signCert);
    if (!isValid)
        auth.verifyFlags = (int) AuthenticodeVFY::Invalid;

    result.emplace_back(std::move(auth));

    return true;
}

static bool AuthenticodeDigest(
      const EVP_MD* md, const uint8_t* pe_data, uint32_t pe_hdr_offset, bool is_64bit, uint32_t cert_table_addr, uint8_t* digest)
{
    uint32_t buffer_size = 0xFFFF;
    uint8_t* buffer      = (uint8_t*) malloc(buffer_size);

    /* BIO with the file data */
    BIO* bio = BIO_new_mem_buf(pe_data, cert_table_addr);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!buffer || !bio || !mdctx)
    {
        return false;
    }

    if (!EVP_DigestInit(mdctx, md))
    {
        return false;
    }

    /* Calculate size of the space between file start and PE header */
    /* Checksum starts at 0x58th byte of the header */
    uint32_t pe_checksum_offset = pe_hdr_offset + 0x58;
    /* Space between DOS and PE header could have arbitrary amount of data, read in chunks */
    uint32_t fpos = 0;
    while (fpos < pe_checksum_offset)
    {
        uint32_t len_to_read = pe_checksum_offset - fpos;
        if (len_to_read > buffer_size)
            len_to_read = buffer_size;

        int rlen = BIO_read(bio, buffer, len_to_read);
        if (rlen <= 0)
        {
            return false;
        }

        if (!EVP_DigestUpdate(mdctx, buffer, rlen))
        {
            return false;
        };

        fpos += rlen;
    }

    /* Skip the checksum */
    if (BIO_read(bio, buffer, 4) <= 0)
    {
        return false;
    }

    /* 64bit PE file is larger than 32bit */
    uint32_t pe64_extra = is_64bit ? 16 : 0;

    /* Read up to certificate table*/
    uint32_t cert_table_offset = 0x3c + pe64_extra;

    if (BIO_read(bio, buffer, cert_table_offset) <= 0)
    {
        return false;
    }

    if (!EVP_DigestUpdate(mdctx, buffer, cert_table_offset))
    {
        return false;
    };

    /* Skip certificate table */
    if (BIO_read(bio, buffer, 8) <= 0)
    {
        return false;
    }

    /* PE header with check sum + checksum + cert table offset + cert table len */
    fpos = pe_checksum_offset + 4 + cert_table_offset + 8;

    /* Hash everything up to the signature (assuming signature is stored in the
     * end of the file) */
    /* Read chunks of the file in case the file is large */
    while (fpos < cert_table_addr)
    {
        uint32_t len_to_read = cert_table_addr - fpos;
        if (len_to_read > buffer_size)
            len_to_read = buffer_size;

        int rlen = BIO_read(bio, buffer, len_to_read);
        if (rlen <= 0)
        {
            return false;
        }

        if (!EVP_DigestUpdate(mdctx, buffer, rlen))
        {
            return false;
        }
        fpos += rlen;
    }

    bool status = EVP_DigestFinal(mdctx, digest, nullptr);

    EVP_MD_CTX_free(mdctx);
    BIO_free_all(bio);
    free(buffer);

    return status;
}

bool AuthenticodeParser::AuthenticodeParse(const uint8_t* peData, uint64_t pe_len)
{
    const uint64_t dos_hdr_size = 0x40;
    if (pe_len < dos_hdr_size)
        return false;

    /* Check if it has DOS signature, so we don't parse random gibberish */
    unsigned char dos_prefix[] = { 0x4d, 0x5a };
    if (memcmp(peData, dos_prefix, sizeof(dos_prefix)) != 0)
        return false;

    /* offset to pointer in DOS header, that points to PE header */
    const int pe_hdr_ptr_offset = 0x3c;
    /* Read the PE offset */
    uint32_t peOffset = letoh32(*(const uint32_t*) (peData + pe_hdr_ptr_offset));

    /* Offset to Magic, to know the PE class (32/64bit) */
    uint32_t magic_addr = peOffset + 0x18;
    if (pe_len < magic_addr + sizeof(uint16_t))
        return false;

    /* Read the magic and check if we have 64bit PE */
    uint16_t magic = letoh16(*(const uint16_t*) (peData + magic_addr));
    bool is64      = (magic == 0x20b);
    /* If PE is 64bit, header is 16 bytes larger */
    uint8_t pe64_extra = is64 ? 16 : 0;

    /* Calculate offset to certificate table directory */
    uint32_t pe_cert_table_addr = peOffset + pe64_extra + 0x98;

    if (pe_len < pe_cert_table_addr + 2 * sizeof(uint32_t))
        return false;

    /* Use 64bit type due to the potential overflow in crafted binaries */
    uint64_t certAddress = letoh32(*(const uint32_t*) (peData + pe_cert_table_addr));
    uint64_t certLength  = letoh32(*(const uint32_t*) (peData + pe_cert_table_addr + 4));

    /* we need atleast 8 bytes to read dwLength, revision and certType */
    if (certLength < 8 || pe_len < certAddress + 8)
        return false;

    uint32_t dwLength = letoh32(*(const uint32_t*) (peData + certAddress));
    if (pe_len < certAddress + dwLength)
        return false;
    /* dwLength = offsetof(WIN_CERTIFICATE, bCertificate) + (size of the variable-length binary array contained within bCertificate) */
    AuthenticodeParseSignature(peData + certAddress + 0x8, dwLength - 0x8, signatures);

    /* Compare valid signatures file digests to actual file digest, to complete verification */
    for (auto& sig : signatures)
    {
        const EVP_MD* md = EVP_get_digestbyname(sig.digestAlg.data());
        if (!md || sig.digest.empty())
        {
            if (sig.verifyFlags == (int) AuthenticodeVFY::Valid)
                sig.verifyFlags = (int) AuthenticodeVFY::UnknownAlgorithm;

            continue;
        }

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
        int mdlen = EVP_MD_get_size(md);
#else
        int mdlen = EVP_MD_size(md);
#endif
        sig.fileDigest.resize(mdlen);

        if (AuthenticodeDigest(
                  md, peData, peOffset, is64, static_cast<uint32_t>(certAddress), reinterpret_cast<uint8_t*>(sig.fileDigest.data())) ==
            false)
        {
            if (sig.verifyFlags == (int) AuthenticodeVFY::Valid)
                sig.verifyFlags = (int) AuthenticodeVFY::InternalError;
            break;
        }

        if (memcmp(sig.fileDigest.data(), sig.digest.data(), mdlen) != 0)
            sig.verifyFlags = (int) AuthenticodeVFY::WrongFileDigest;
    }

    return true;
}

static void ParseNameAttributes(X509_NAME* raw, Attributes& attr)
{
    int entryCount = X509_NAME_entry_count(raw);
    for (int i = entryCount - 1; i >= 0; --i)
    {
        X509_NAME_ENTRY* entryName = X509_NAME_get_entry(raw, i);
        ASN1_STRING* asn1String    = X509_NAME_ENTRY_get_data(entryName);

        const char* key = OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(entryName)));
        std::string_view array{ reinterpret_cast<char*>(asn1String->data), static_cast<size_t>(asn1String->length) };

        if (strcmp(key, "C") == 0 && attr.country.empty())
            attr.country.assign(array);
        else if (strcmp(key, "O") == 0 && attr.organization.empty())
            attr.organization.assign(array);
        else if (strcmp(key, "OU") == 0 && attr.organizationalUnit.empty())
            attr.organizationalUnit.assign(array);
        else if (strcmp(key, "dnQualifier") == 0 && attr.nameQualifier.empty())
            attr.nameQualifier.assign(array);
        else if (strcmp(key, "ST") == 0 && attr.state.empty())
            attr.state.assign(array);
        else if (strcmp(key, "CN") == 0 && attr.commonName.empty())
            attr.commonName.assign(array);
        else if (strcmp(key, "serialNumber") == 0 && attr.serialNumber.empty())
            attr.serialNumber.assign(array);
        else if (strcmp(key, "L") == 0 && attr.locality.empty())
            attr.locality.assign(array);
        else if (strcmp(key, "title") == 0 && attr.title.empty())
            attr.title.assign(array);
        else if (strcmp(key, "SN") == 0 && attr.surname.empty())
            attr.surname.assign(array);
        else if (strcmp(key, "GN") == 0 && attr.givenName.empty())
            attr.givenName.assign(array);
        else if (strcmp(key, "initials") == 0 && attr.initials.empty())
            attr.initials.assign(array);
        else if (strcmp(key, "pseudonym") == 0 && attr.pseudonym.empty())
            attr.pseudonym.assign(array);
        else if (strcmp(key, "generationQualifier") == 0 && attr.generationQualifier.empty())
            attr.generationQualifier.assign(array);
        else if (strcmp(key, "emailAddress") == 0 && attr.emailAddress.empty())
            attr.emailAddress.assign(array);
    }
}

/* Reconstructs signers certificate chain */
std::vector<Certificate> AuthenticodeParser::ParseSignerChain(X509* signCert, STACK_OF(X509) * certs)
{
    if (!signCert || !certs)
        return {};

    X509_STORE* store = X509_STORE_new();
    if (!store)
        return {};

    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    if (!storeCtx)
    {
        X509_STORE_CTX_free(storeCtx);
        return {};
    }

    X509_STORE_CTX_init(storeCtx, store, signCert, certs);

    /* I can't find ability to use this function for static verification with missing trust anchors,
     * because roots are generally not part of the PKCS7 signatures, so the return value is
     * currently ignored and the function is only used to build the certificate chain */
    X509_verify_cert(storeCtx);

    STACK_OF(X509)* chain = X509_STORE_CTX_get_chain(storeCtx);

    int certCount = sk_X509_num(chain);

    std::vector<Certificate> result;
    result.reserve(certCount);

    /* Convert each certificate to internal representation */
    for (int i = 0; i < certCount; ++i)
    {
        result.emplace_back().Parse(sk_X509_value(chain, i));
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    return result;
}

/* Taken from YARA for compatibility */
static char* IntegerToSerial(ASN1_INTEGER* serial)
{
    int bytes = i2d_ASN1_INTEGER(serial, nullptr);

    char* res = nullptr;
    /* According to X.509 specification the maximum length for the
     * serial number is 20 octets. Add two bytes to account for
     * DER type and length information. */
    if (bytes < 2 || bytes > 22)
        return nullptr;

    /* Now that we know the size of the serial number allocate enough
     * space to hold it, and use i2d_ASN1_INTEGER() one last time to
     * hold it in the allocated buffer. */
    uint8_t* serial_der = (uint8_t*) malloc(bytes);
    if (!serial_der)
        return nullptr;

    uint8_t* serial_bytes;

    bytes = i2d_ASN1_INTEGER(serial, &serial_der);

    /* i2d_ASN1_INTEGER() moves the pointer as it writes into
       serial_bytes. Move it back. */
    serial_der -= bytes;

    /* Skip over DER type, length information */
    serial_bytes = serial_der + 2;
    bytes -= 2;

    /* Also allocate space to hold the "common" string format:
     * 00:01:02:03:04...
     *
     * For each byte in the serial to convert to hexlified format we
     * need three bytes, two for the byte itself and one for colon.
     * The last one doesn't have the colon, but the extra byte is used
     * for the NULL terminator. */
    res = (char*) malloc(bytes * 3);
    if (res)
    {
        for (int i = 0; i < bytes; i++)
        {
            /* Don't put the colon on the last one. */
            if (i < bytes - 1)
                snprintf(res + 3 * i, 4, "%02x:", serial_bytes[i]);
            else
                snprintf(res + 3 * i, 3, "%02x", serial_bytes[i]);
        }
    }
    free(serial_der);

    return (char*) res;
}

/* Converts the pubkey to pem, which is just
 * Base64 encoding of the DER representation */
static char* PubkeyToPEM(EVP_PKEY* pubkey)
{
    uint8_t* der = nullptr;
    int len      = i2d_PUBKEY(pubkey, &der); /* Convert to DER */
    if (len <= 0)
        return nullptr;

    /* Approximate the result length (padding, newlines, 4 out bytes for every 3 in) */
    uint8_t* result = (uint8_t*) malloc(len * 3 / 2);
    if (!result)
    {
        OPENSSL_free(der);
        return nullptr;
    }

    /* Base64 encode the DER data */
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
    {
        OPENSSL_free(der);
        free(result);
        return nullptr;
    }

    size_t resultLen = 0;
    int tmp       = 0;
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, result, &tmp, der, len);
    resultLen += tmp;
    EVP_EncodeFinal(ctx, result + resultLen, &tmp);
    resultLen += tmp;

    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_free(der);

    /* Remove all newlines from the encoded base64
     * resultLen is excluding NULL terminator */
    for (int i = 0; result[i] != 0; i++)
    {
        if (result[i] == '\n')
            memmove(result + i, result + i + 1, resultLen - i);
    }

    return (char*) result;
}

bool Certificate::Parse(X509* x509)
{
    /* Calculate SHA1 and SHA256 digests of the X509 structure */
    sha1.resize(SHA_DIGEST_LENGTH);
    X509_digest(x509, EVP_sha1(), sha1.data(), nullptr);

    sha256.resize(SHA256_DIGEST_LENGTH);
    X509_digest(x509, EVP_sha256(), sha256.data(), nullptr);

    X509_NAME* issuerName  = X509_get_issuer_name(x509);
    X509_NAME* subjectName = X509_get_subject_name(x509);

    BIO_ptr out(BIO_new(BIO_s_mem()), BIO_free);
    BUF_MEM* buf{ nullptr };

    X509_NAME_print_ex(out.get(), issuerName, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    BIO_get_mem_ptr(out.get(), &buf);
    issuer.assign(std::string_view{ buf->data, buf->length });

    out.reset(BIO_new(BIO_s_mem()));
    X509_NAME_print_ex(out.get(), subjectName, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    BIO_get_mem_ptr(out.get(), &buf);
    subject.assign(std::string_view{ buf->data, buf->length });

    ParseNameAttributes(issuerName, issuerAttributes);
    ParseNameAttributes(subjectName, subjectAttributes);

    version = X509_get_version(x509);
    serial.assign(IntegerToSerial(X509_get_serialNumber(x509)));
    notAfter    = ASN1_TIME_to_time_t(X509_get0_notAfter(x509));
    notBefore   = ASN1_TIME_to_time_t(X509_get0_notBefore(x509));
    int sig_nid = X509_get_signature_nid(x509);
    sigAlg.assign(OBJ_nid2ln(sig_nid));

    char buffer[256];
    OBJ_obj2txt(buffer, sizeof(buffer), OBJ_nid2obj(sig_nid), 1);
    sidAlgOID.assign(buffer);

    EVP_PKEY* pkey = X509_get0_pubkey(x509);
    if (pkey)
    {
        key.assign(PubkeyToPEM(pkey));
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
        keyAlg.assign(OBJ_nid2sn(EVP_PKEY_get_base_id(pkey)));
#else
        keyAlg.assign(OBJ_nid2sn(EVP_PKEY_base_id(pkey)));
#endif
    }

    out.reset(BIO_new(BIO_s_mem()));

    const auto bioWrite = PEM_write_bio_X509(out.get(), x509);
    if (bioWrite == 1)
    {
        BIO_get_mem_ptr(out.get(), &buf);
        if (buf != nullptr)
        {
            this->pem.assign(buf->data, (uint32_t) buf->length);
        }
    }

    return true;
}

static void ToHex(const unsigned char* v, char* b, int len)
{
    int i, j = 0;
    for (i = 0; i < len; i++)
    {
#ifdef WIN32
        size_t size = EVP_MAX_MD_SIZE * 2 + 1;
        j += sprintf_s(b + j, size - j, "%02X", v[i]);
#else
        j += sprintf(b + j, "%02X", v[i]);
#endif /* WIN32 */
    }
}

static bool GetTimeFromCMS(CMS_ContentInfo* cms, time_t& time)
{
    ASN1_OCTET_STRING** pos = CMS_get0_content(cms);
    if (pos == nullptr || *pos == nullptr)
    {
        return false;
    }

    const unsigned char* p = (*pos)->data;
    TimeStampToken* token  = d2i_TimeStampToken(nullptr, &p, (*pos)->length);
    if (token == nullptr)
    {
        return false;
    }

    ASN1_GENERALIZEDTIME* asn1 = token->time;
    time                       = ASN1_TIME_to_time_t(asn1);
    TimeStampToken_free(token);

    return true;
}

bool CounterSignature::ParsePKCS9(
      const uint8_t* data, long size, STACK_OF(X509) * certs, ASN1_STRING* enc_digest, PKCS7_SIGNER_INFO* counter)
{
    this->type = CounterSignatureType::RFC3161;

    PKCS7_SIGNER_INFO* si = d2i_PKCS7_SIGNER_INFO(nullptr, &data, size);
    if (!si)
    {
        BIO_ptr in(BIO_new(BIO_s_mem()), BIO_free);
        BIO_write(in.get(), data, static_cast<int>(size));

        CMS_ContentInfo_ptr cms(d2i_CMS_bio(in.get(), nullptr), CMS_ContentInfo_free);
        if (cms.get() == nullptr)
        {
            verifyFlags = (int32_t) CountersignatureVFY::CantParse;
            return false;
        }

        constexpr uint32_t flags = CMS_BINARY | CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY;
        if (CMS_verify(cms.get(), certs, nullptr, nullptr, nullptr, flags) != 1)
        {
            verifyFlags = (int) CountersignatureVFY::DoesntMatchSignature;
            return false;
        }

        STACK_OF(CMS_SignerInfo)* cmsSigners = CMS_get0_SignerInfos(cms.get());
        int32_t cmsSignersCount              = sk_CMS_SignerInfo_num(cmsSigners);
        if (cmsSignersCount == 0)
        {
            return false;
        }

        CMS_SignerInfo* siCMS = sk_CMS_SignerInfo_value(cmsSigners, 0);

        int32_t idx                  = CMS_signed_get_attr_by_NID(siCMS, NID_pkcs9_signingTime, -1);
        X509_ATTRIBUTE* signTimeAttr = CMS_signed_get_attr(siCMS, idx);
        if (!signTimeAttr)
        {
            if (GetTimeFromCMS(cms.get(), this->signTime) == false)
            {
                verifyFlags = (int) CountersignatureVFY::TimeMissing;
                return false;
            }
        }
        else
        {
            ASN1_TYPE* signTime = X509_ATTRIBUTE_get0_type(signTimeAttr, 0);
            if (!signTime)
            {
                verifyFlags = (int) CountersignatureVFY::TimeMissing;
                return false;
            }

            this->signTime = ASN1_TIME_to_time_t(signTime->value.utctime);
        }

        STACK_OF(X509)* allCerts = CMS_get1_certs(cms.get());
        if (!allCerts)
        {
            verifyFlags = (int) CountersignatureVFY::NoSignerCert;
            return false;
        }
        auto certsCount = sk_X509_num(allCerts);
        if (!certsCount)
        {
            verifyFlags = (int) CountersignatureVFY::NoSignerCert;
            return false;
        }

        STACK_OF(X509)* signCerts = CMS_get0_signers(cms.get());
        auto signCertsCount       = sk_X509_num(signCerts);
        if (!signCertsCount)
        {
            verifyFlags = (int) CountersignatureVFY::NoSignerCert;
            return false;
        }
        const auto signCert = sk_X509_value(signCerts, 0);

        /* PKCS9 stores certificates in the corresponding PKCS7 it countersigns */
        chain = AuthenticodeParser::ParseSignerChain(signCert, allCerts);

        ASN1_OCTET_STRING** pos = CMS_get0_content(cms.get());
        if (pos == nullptr || *pos == nullptr)
        {
            verifyFlags = (int) CountersignatureVFY::DigestMissing;
            return false;
        }

        const unsigned char* p = (*pos)->data;
        TimeStampToken* token  = d2i_TimeStampToken(nullptr, &p, (*pos)->length);
        if (token == nullptr)
        {
            verifyFlags = (int) CountersignatureVFY::DigestMissing;
            return false;
        }

        /* compute a hash from the encrypted message digest value of the file */
        int digestnid = OBJ_obj2nid(token->messageImprint->digestAlgorithm->algorithm);
        digestAlg.assign(OBJ_nid2ln(digestnid));

        const EVP_MD* md  = EVP_get_digestbynid(digestnid);
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!EVP_DigestInit(mdctx, md))
        {
            EVP_MD_CTX_free(mdctx);
            verifyFlags = (int) CountersignatureVFY::DigestMissing;
            return false;
        }

        EVP_DigestUpdate(mdctx, counter->enc_digest->data, (size_t) counter->enc_digest->length);
        unsigned char mdbuf[EVP_MAX_MD_SIZE];
        EVP_DigestFinal(mdctx, mdbuf, nullptr);
        EVP_MD_CTX_free(mdctx);

        /* compare the provided hash against the computed hash */
        ASN1_OCTET_STRING* hash = token->messageImprint->digest;
        /* hash->length == EVP_MD_size(md) */

        bool result = (memcmp(mdbuf, hash->data, (size_t) hash->length) == 0);

        TimeStampToken_free(token);

        const uint8_t* digestData = counter->enc_digest->data;
        digest.insert(digest.end(), digestData, digestData + counter->enc_digest->length);

        if (result == false)
        {
            verifyFlags = (int) CountersignatureVFY::DoesntMatchSignature;
            return false;
        }

        return true;
    }

    int digestnid = OBJ_obj2nid(si->digest_alg->algorithm);
    digestAlg.assign(OBJ_nid2ln(digestnid));

    const ASN1_TYPE* signTime = PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime);
    if (!signTime)
    {
        verifyFlags = (int) CountersignatureVFY::TimeMissing;
        return false;
    }

    this->signTime = ASN1_TIME_to_time_t(signTime->value.utctime);

    X509* signCert = X509_find_by_issuer_and_serial(certs, si->issuer_and_serial->issuer, si->issuer_and_serial->serial);
    if (!signCert)
    {
        verifyFlags = (int) CountersignatureVFY::NoSignerCert;
        return false;
    }

    /* PKCS9 stores certificates in the corresponding PKCS7 it countersigns */
    chain = AuthenticodeParser::ParseSignerChain(signCert, certs);

    /* Get digest that corresponds to decrypted encrypted digest in signature */
    ASN1_TYPE* messageDigest = PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
    if (!messageDigest)
    {
        verifyFlags = (int) CountersignatureVFY::DigestMissing;
        return false;
    }

    size_t digestLen = messageDigest->value.octet_string->length;

    if (!digestLen)
    {
        verifyFlags = (int) CountersignatureVFY::DigestMissing;
    }

    const EVP_MD* md = EVP_get_digestbynid(digestnid);
    if (!md)
    {
        verifyFlags = (int) CountersignatureVFY::UnknownAlgorithm;
    }

    const uint8_t* digestData = messageDigest->value.octet_string->data;
    digest.insert(digest.end(), digestData, digestData + digestLen);

    /* By this point we all necessary things for verification
     * Get DER representation of the authenticated attributes to calculate its
     * digest that should correspond with the one encrypted in SignerInfo */
    uint8_t* authAttrsData = nullptr;
    int authAttrsLen       = ASN1_item_i2d((ASN1_VALUE*) si->auth_attr, &authAttrsData, ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));

    uint8_t calc_digest[EVP_MAX_MD_SIZE];
    CalculateDigest(md, authAttrsData, authAttrsLen, calc_digest);
    OPENSSL_free(authAttrsData);

    /* Get public key to decrypt encrypted digest of auth attrs */
    EVP_PKEY* pkey    = X509_get0_pubkey(signCert);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    /* TODO try to get rid of hardcoded length bound */
    size_t decLen = 65536;
    std::unique_ptr<uint8_t> decData((uint8_t*) malloc(decLen));
    if (!decData)
    {
        EVP_PKEY_CTX_free(ctx);
        verifyFlags = (int) CountersignatureVFY::InternalError;
    }

    uint8_t* encData = si->enc_digest->data;
    size_t encLen    = si->enc_digest->length;

    /* Decrypt the encrypted digest */
    EVP_PKEY_verify_recover_init(ctx);
    bool isDecrypted = EVP_PKEY_verify_recover(ctx, decData.get(), &decLen, encData, encLen) == 1;
    EVP_PKEY_CTX_free(ctx);

    if (!isDecrypted)
    {
        verifyFlags = (int) CountersignatureVFY::CantDecryptDigest;
    }

    /* compare the encrypted digest and calculated digest */
    bool isValid = false;

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    size_t mdLen = EVP_MD_get_size(md);
#else
    size_t mdLen = EVP_MD_size(md);
#endif
    /* Sometimes signed data contains DER encoded DigestInfo structure which contains hash of
     * authenticated attributes (39c9d136f026a9ad18fb9f41a64f76dd8418e8de625dce5d3a372bd242fc5edd)
     * but other times it is just purely and I didn't find another way to  distinguish it but only
     * based on the length of data we get. Found mention of this in openssl mailing list:
     * https://mta.openssl.org/pipermail/openssl-users/2015-September/002054.html */
    if (mdLen == decLen)
    {
        isValid = !memcmp(calc_digest, decData.get(), mdLen);
    }
    else
    {
        const uint8_t* data = decData.get();
        DigestInfo* info    = d2i_DigestInfo(nullptr, &data, static_cast<uint32_t>(decLen));
        if (info)
        {
            isValid = !memcmp(info->digest->data, calc_digest, mdLen);
            DigestInfo_free(info);
        }
        else
        {
            isValid = false;
        }
    }

    if (!isValid)
    {
        verifyFlags = (int) CountersignatureVFY::Invalid;
    }

    /* Now check the countersignature message-digest that should correspond
     * to Signatures encrypted digest it countersigns */
    CalculateDigest(md, enc_digest->data, enc_digest->length, calc_digest);

    /* Check if calculated one matches the stored one */
    if (digestLen != mdLen || memcmp(calc_digest, digestData, mdLen) != 0)
    {
        verifyFlags = (int) CountersignatureVFY::DoesntMatchSignature;
    }

    PKCS7_SIGNER_INFO_free(si);
    return true;
}

bool CounterSignature::ParseMS(const uint8_t* data, long size, ASN1_STRING* enc_digest)
{
    this->type = CounterSignatureType::Authenticode;

    PKCS7* p7 = d2i_PKCS7(nullptr, &data, size);
    if (!p7)
    {
        verifyFlags = (int) CountersignatureVFY::CantParse;
        return false;
    }

    TS_TST_INFO* ts = PKCS7_to_TS_TST_INFO(p7);
    if (!ts)
    {
        verifyFlags = (int) CountersignatureVFY::CantParse;
        PKCS7_free(p7);
        return false;
    }

    const ASN1_TIME* rawTime = TS_TST_INFO_get_time(ts);
    if (!rawTime)
    {
        verifyFlags = (int) CountersignatureVFY::TimeMissing;
        TS_TST_INFO_free(ts);
        PKCS7_free(p7);
        return false;
    }

    signTime = ASN1_TIME_to_time_t(rawTime);

    STACK_OF(X509)* sigs = PKCS7_get0_signers(p7, p7->d.sign->cert, 0);
    X509* signCert       = sk_X509_value(sigs, 0);
    if (!signCert)
    {
        verifyFlags = (int) CountersignatureVFY::NoSignerCert;
    }

    chain = AuthenticodeParser::ParseSignerChain(signCert, p7->d.sign->cert);

    /* Imprint == digest */
    TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(ts);
    if (!imprint)
    {
        verifyFlags = (int) CountersignatureVFY::DigestMissing;
    }

    X509_ALGOR* digestAlg = TS_MSG_IMPRINT_get_algo(imprint);
    int digestnid         = OBJ_obj2nid(digestAlg->algorithm);
    this->digestAlg.assign(OBJ_nid2ln(digestnid));

    ASN1_STRING* rawDigest = TS_MSG_IMPRINT_get_msg(imprint);

    int digestLen       = rawDigest->length;
    uint8_t* digestData = rawDigest->data;

    digest.insert(digest.end(), digestData, digestData + digestLen);

    if (!digestLen)
    {
        verifyFlags = (int) CountersignatureVFY::DigestMissing;
    }

    const EVP_MD* md = EVP_get_digestbynid(digestnid);
    if (!md)
    {
        verifyFlags = (int) CountersignatureVFY::UnknownAlgorithm;
    }

    uint8_t calc_digest[EVP_MAX_MD_SIZE];
    CalculateDigest(md, enc_digest->data, enc_digest->length, calc_digest);

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    int mdLen = EVP_MD_get_size(md);
#else
    int mdLen = EVP_MD_size(md);
#endif

    if (digestLen != mdLen || memcmp(calc_digest, digestData, mdLen) != 0)
    {
        verifyFlags = (int) CountersignatureVFY::DoesntMatchSignature;
    }

    TS_VERIFY_CTX* ctx = TS_VERIFY_CTX_new();
    X509_STORE* store  = X509_STORE_new();
    TS_VERIFY_CTX_init(ctx);

    TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION | TS_VFY_IMPRINT);
    TS_VERIFY_CTX_set_store(ctx, store);
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    TS_VERIFY_CTX_set_certs(ctx, p7->d.sign->cert);
#else
    TS_VERIFY_CTS_set_certs(ctx, p7->d.sign->cert);
#endif
    TS_VERIFY_CTX_set_imprint(ctx, calc_digest, mdLen);

    bool isValid = TS_RESP_verify_token(ctx, p7) == 1;

    X509_STORE_free(store);
    OPENSSL_free(ctx);

    if (!isValid)
    {
        verifyFlags = (int) CountersignatureVFY::Invalid;
    }

    /* Verify signature with PKCS7_signatureVerify
     because TS_RESP_verify_token would try to verify
     chain and without trust anchors it always fails */
    BIO* p7bio = PKCS7_dataInit(p7, nullptr);

    char buf[4096];
    /* We now have to 'read' from p7bio to calculate digests etc. */
    while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
        continue;

    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);

    isValid = PKCS7_signatureVerify(p7bio, p7, si, signCert) == 1;

    BIO_free_all(p7bio);

    if (!isValid)
        verifyFlags = (int) CountersignatureVFY::Invalid;

    sk_X509_free(sigs);
    PKCS7_free(p7);
    TS_TST_INFO_free(ts);

    return true;
}

uint16_t BSwap16(uint16_t d)
{
    return (d << 8) | (d >> 8);
}

uint32_t BSwap32(uint32_t d)
{
    return (((d) &0xff000000) >> 24) | (((d) &0x00ff0000) >> 8) | (((d) &0x0000ff00) << 8) | (((d) &0x000000ff) << 24);
}

int CalculateDigest(const EVP_MD* md, const uint8_t* data, size_t len, uint8_t* digest)
{
    unsigned int outLen = 0;

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
        goto end;

    if (!EVP_DigestInit_ex(mdCtx, md, nullptr) || !EVP_DigestUpdate(mdCtx, data, len) || !EVP_DigestFinal_ex(mdCtx, digest, &outLen))
        goto end;

end:
    EVP_MD_CTX_free(mdCtx);
    return (int) outLen;
}

#ifdef _WIN32
#    define timegm _mkgmtime
#endif

time_t ASN1_TIME_to_time_t(const ASN1_TIME* time)
{
    struct tm t = { 0 };
    if (!time)
        return timegm(&t);

    ASN1_TIME_to_tm(time, &t);
    return timegm(&t);
}

const std::vector<AuthenticodeSignature>& AuthenticodeParser::GetSignatures() const
{
    return signatures;
}

static inline std::string_view GetSignatureFlagName(AuthenticodeVFY flag)
{
    switch (flag)
    {
    case AuthenticodeVFY::Valid:
        return "Valid";
    case AuthenticodeVFY::CantParse:
        return "CantParse";
    case AuthenticodeVFY::NoSignerCert:
        return "NoSignerCert";
    case AuthenticodeVFY::DigestMissing:
        return "DigestMissing";
    case AuthenticodeVFY::InternalError:
        return "InternalError";
    case AuthenticodeVFY::NoSignerInfo:
        return "NoSignerInfo";
    case AuthenticodeVFY::WrongPKCS7Type:
        return "WrongPKCS7Type";
    case AuthenticodeVFY::BadContent:
        return "BadContent";
    case AuthenticodeVFY::Invalid:
        return "Invalid";
    case AuthenticodeVFY::WrongFileDigest:
        return "WrongFileDigest";
    case AuthenticodeVFY::UnknownAlgorithm:
        return "UnknownAlgorithm";
    default:
        return "Unknown";
    }
}

std::string AuthenticodeParser::GetSignatureFlags(uint32_t flags)
{
    static constexpr std::initializer_list<AuthenticodeVFY> types{
        AuthenticodeVFY::Valid,         AuthenticodeVFY::CantParse,       AuthenticodeVFY::NoSignerCert,    AuthenticodeVFY::DigestMissing,
        AuthenticodeVFY::InternalError, AuthenticodeVFY::NoSignerInfo,    AuthenticodeVFY::WrongPKCS7Type,  AuthenticodeVFY::BadContent,
        AuthenticodeVFY::Invalid,       AuthenticodeVFY::WrongFileDigest, AuthenticodeVFY::UnknownAlgorithm
    };

    if (flags == static_cast<uint32_t>(AuthenticodeVFY::Valid))
    {
        return "Valid";
    }

    std::string output;
    for (const auto& t : types)
    {
        if ((flags & static_cast<uint32_t>(t)) == static_cast<uint32_t>(t) && t != AuthenticodeVFY::Valid)
        {
            if (!output.empty())
            {
                output += " | ";
            }
            output += GetSignatureFlagName(t);
        }
    }

    return output;
}

static inline std::string_view GetCounterSignatureFlagName(CountersignatureVFY flag)
{
    switch (flag)
    {
    case CountersignatureVFY::Valid:
        return "Valid";
    case CountersignatureVFY::CantParse:
        return "CantParse";
    case CountersignatureVFY::NoSignerCert:
        return "NoSignerCert";
    case CountersignatureVFY::UnknownAlgorithm:
        return "UnknownAlgorithm";
    case CountersignatureVFY::Invalid:
        return "Invalid";
    case CountersignatureVFY::CantDecryptDigest:
        return "CantDecryptDigest";
    case CountersignatureVFY::DigestMissing:
        return "DigestMissing";
    case CountersignatureVFY::DoesntMatchSignature:
        return "DoesntMatchSignature";
    case CountersignatureVFY::InternalError:
        return "InternalError";
    case CountersignatureVFY::TimeMissing:
        return "TimeMissing";
    default:
        return "Unknown";
    }
}

std::string AuthenticodeParser::GetCounterSignatureFlags(uint32_t flags)
{
    static constexpr std::initializer_list<CountersignatureVFY> types{
        CountersignatureVFY::Valid,         CountersignatureVFY::CantParse,
        CountersignatureVFY::NoSignerCert,  CountersignatureVFY::UnknownAlgorithm,
        CountersignatureVFY::Invalid,       CountersignatureVFY::CantDecryptDigest,
        CountersignatureVFY::DigestMissing, CountersignatureVFY::DoesntMatchSignature,
        CountersignatureVFY::InternalError, CountersignatureVFY::TimeMissing
    };

    if (flags == static_cast<uint32_t>(CountersignatureVFY::Valid))
    {
        return "Valid";
    }

    std::string output;
    for (const auto& t : types)
    {
        if ((flags & static_cast<uint32_t>(t)) == static_cast<uint32_t>(t) && t != CountersignatureVFY::Valid)
        {
            if (!output.empty())
            {
                output += " | ";
            }
            output += GetCounterSignatureFlagName(t);
        }
    }

    return output;
}
} // namespace Authenticode
