#include "Internal.hpp"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

namespace GView::DigitalSignature
{
bool BufferToHumanReadable(const Buffer& buffer, std::string& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    auto data = reinterpret_cast<const unsigned char*>(buffer.GetData());

    ERR_clear_error();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &data, buffer.GetLength());
    auto error   = ERR_get_error();
    output       = ERR_error_string(error, nullptr);
    CHECK(pkcs7 != nullptr, false, output.c_str());

    BIO* out = BIO_new(BIO_s_mem());

    ERR_clear_error();
    const auto ctxCode = PKCS7_print_ctx(out, pkcs7, 4, nullptr);
    error              = ERR_get_error();
    output             = ERR_error_string(error, nullptr);
    CHECK(ctxCode == 1, false, output.c_str());

    BUF_MEM* buf{};
    BIO_get_mem_ptr(out, &buf);
    output = std::string{ buf->data, buf->length };
    BIO_free(out);

    return true;
}

bool BufferToPEMCerts(const Buffer& buffer, std::vector<std::string>& output)
{
    CHECK(buffer.GetData() != nullptr, "Nullptr data provided!", "");
    output.clear();
    auto& first = output.emplace_back();

    ERR_clear_error();
    BIO* in    = BIO_new(BIO_s_mem());
    auto error = ERR_get_error();
    first      = ERR_error_string(error, nullptr);
    CHECK((size_t) BIO_write(in, buffer.GetData(), buffer.GetLength()) == buffer.GetLength(), false, "");

    ERR_clear_error();
    CMS_ContentInfo* cms = d2i_CMS_bio(in, NULL);
    error                = ERR_get_error();
    first                = ERR_error_string(error, nullptr);

    ERR_clear_error();
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    error                 = ERR_get_error();
    first                 = ERR_error_string(error, nullptr);

    CHECK(certs != nullptr, false, "");

    output.clear();
    for (int i = 0; i < sk_X509_num(certs); i++)
    {
        const auto cert = sk_X509_value(certs, i);

        BIO* bioCert = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bioCert, cert);

        BUF_MEM* buf{};
        BIO_get_mem_ptr(bioCert, &buf);
        output.emplace_back(std::string{ buf->data, buf->length });
        BIO_free(bioCert);
    }

    BIO_free(in);

    return true;
}
} // namespace GView::DigitalSignature
