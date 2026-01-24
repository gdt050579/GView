/**
 * - AES-256-GCM encryption/decryption for sensitive content
 * - Secure key derivation (HKDF)
 * - SHA-256 hashing for plugin verification
 * - Protected memory utilities
 */

#include "GView.hpp"
#include <cstring>
#include <memory>
#include <fstream>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// Platform-specific headers for protected memory
#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#elif defined(BUILD_FOR_OSX) || defined(BUILD_FOR_UNIX)
#    include <sys/mman.h>
#endif

namespace GView::Security::Crypto
{

namespace
{
    constexpr size_t AES_256_KEY_SIZE = 32;
    constexpr size_t AES_GCM_IV_SIZE = 12;
    constexpr size_t AES_GCM_TAG_SIZE = 16;

    // RAII wrapper for EVP_CIPHER_CTX
    struct CipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const noexcept
        {
            if (ctx != nullptr)
                EVP_CIPHER_CTX_free(ctx);
        }
    };
    using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

    // Secure memory operations
    void SecureZero(void* ptr, size_t size) noexcept
    {
        if (ptr == nullptr || size == 0)
            return;

#ifdef BUILD_FOR_WINDOWS
        SecureZeroMemory(ptr, size);
#else
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (size--)
        {
            *p++ = 0;
        }
#endif
    }

    std::string GetOpenSSLError() noexcept
    {
        unsigned long err = ERR_get_error();
        if (err == 0)
            return "Unknown OpenSSL error";

        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(buf);
    }

} // anonymous namespace

/**
 * @brief Encrypted blob structure for storing encrypted content
 */
struct EncryptedBlob {
    std::vector<uint8_t> iv;         // 12 bytes for AES-GCM
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;        // 16 bytes for AES-GCM
    std::vector<uint8_t> aad;        // Additional authenticated data (optional)
};

namespace Internal
{

/**
 * @brief Encrypt data using AES-256-GCM
 *
 * @param plaintext Data to encrypt
 * @param key 32-byte encryption key
 * @param aad Additional authenticated data (optional, for context binding)
 * @param outBlob Output encrypted blob
 * @return GStatus indicating success or failure
 */
Utils::GStatus EncryptAES256GCM(
      const std::vector<uint8_t>& plaintext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& aad,
      EncryptedBlob& outBlob) noexcept
{
    if (key.size() != AES_256_KEY_SIZE)
    {
        return Utils::GStatus::Error("Invalid key size (expected 32 bytes)");
    }

    if (plaintext.empty())
    {
        return Utils::GStatus::Error("Empty plaintext");
    }

    // Generate random IV
    outBlob.iv.resize(AES_GCM_IV_SIZE);
    if (RAND_bytes(outBlob.iv.data(), static_cast<int>(AES_GCM_IV_SIZE)) != 1)
    {
        return Utils::GStatus::Error("Failed to generate random IV: " + GetOpenSSLError());
    }

    // Create cipher context
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
    {
        return Utils::GStatus::Error("Failed to create cipher context");
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        return Utils::GStatus::Error("EVP_EncryptInit_ex failed: " + GetOpenSSLError());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_GCM_IV_SIZE), nullptr) != 1)
    {
        return Utils::GStatus::Error("Failed to set IV length: " + GetOpenSSLError());
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), outBlob.iv.data()) != 1)
    {
        return Utils::GStatus::Error("Failed to set key/IV: " + GetOpenSSLError());
    }

    // Process AAD if provided
    outBlob.aad = aad;
    if (!aad.empty())
    {
        int aadLen = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aadLen, aad.data(), static_cast<int>(aad.size())) != 1)
        {
            return Utils::GStatus::Error("Failed to process AAD: " + GetOpenSSLError());
        }
    }

    // Encrypt plaintext
    outBlob.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    if (EVP_EncryptUpdate(
              ctx.get(),
              outBlob.ciphertext.data(),
              &outLen,
              plaintext.data(),
              static_cast<int>(plaintext.size())) != 1)
    {
        return Utils::GStatus::Error("Encryption failed: " + GetOpenSSLError());
    }

    int ciphertextLen = outLen;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx.get(), outBlob.ciphertext.data() + outLen, &outLen) != 1)
    {
        return Utils::GStatus::Error("Encryption finalization failed: " + GetOpenSSLError());
    }
    ciphertextLen += outLen;
    outBlob.ciphertext.resize(static_cast<size_t>(ciphertextLen));

    // Get authentication tag
    outBlob.tag.resize(AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(AES_GCM_TAG_SIZE), outBlob.tag.data()) != 1)
    {
        return Utils::GStatus::Error("Failed to get auth tag: " + GetOpenSSLError());
    }

    return Utils::GStatus::Ok();
}

/**
 * @brief Decrypt data using AES-256-GCM
 *
 * @param blob Encrypted blob containing IV, ciphertext, tag
 * @param key 32-byte decryption key
 * @param outPlaintext Output decrypted data
 * @return GStatus indicating success or failure
 */
Utils::GStatus DecryptAES256GCM(
      const EncryptedBlob& blob,
      const std::vector<uint8_t>& key,
      std::vector<uint8_t>& outPlaintext) noexcept
{
    if (key.size() != AES_256_KEY_SIZE)
    {
        return Utils::GStatus::Error("Invalid key size (expected 32 bytes)");
    }

    if (blob.iv.size() != AES_GCM_IV_SIZE)
    {
        return Utils::GStatus::Error("Invalid IV size");
    }

    if (blob.tag.size() != AES_GCM_TAG_SIZE)
    {
        return Utils::GStatus::Error("Invalid tag size");
    }

    if (blob.ciphertext.empty())
    {
        return Utils::GStatus::Error("Empty ciphertext");
    }

    // Create cipher context
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
    {
        return Utils::GStatus::Error("Failed to create cipher context");
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        return Utils::GStatus::Error("EVP_DecryptInit_ex failed: " + GetOpenSSLError());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_GCM_IV_SIZE), nullptr) != 1)
    {
        return Utils::GStatus::Error("Failed to set IV length: " + GetOpenSSLError());
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), blob.iv.data()) != 1)
    {
        return Utils::GStatus::Error("Failed to set key/IV: " + GetOpenSSLError());
    }

    // Process AAD if provided
    if (!blob.aad.empty())
    {
        int aadLen = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aadLen, blob.aad.data(), static_cast<int>(blob.aad.size())) != 1)
        {
            return Utils::GStatus::Error("Failed to process AAD: " + GetOpenSSLError());
        }
    }

    // Decrypt ciphertext
    outPlaintext.resize(blob.ciphertext.size());
    int outLen = 0;

    if (EVP_DecryptUpdate(
              ctx.get(),
              outPlaintext.data(),
              &outLen,
              blob.ciphertext.data(),
              static_cast<int>(blob.ciphertext.size())) != 1)
    {
        outPlaintext.clear();
        return Utils::GStatus::Error("Decryption failed: " + GetOpenSSLError());
    }

    int plaintextLen = outLen;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(
              ctx.get(),
              EVP_CTRL_GCM_SET_TAG,
              static_cast<int>(AES_GCM_TAG_SIZE),
              const_cast<uint8_t*>(blob.tag.data())) != 1)
    {
        outPlaintext.clear();
        return Utils::GStatus::Error("Failed to set expected tag: " + GetOpenSSLError());
    }

    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(ctx.get(), outPlaintext.data() + outLen, &outLen) != 1)
    {
        outPlaintext.clear();
        return Utils::GStatus::Error("Decryption verification failed - data may be tampered");
    }
    plaintextLen += outLen;
    outPlaintext.resize(static_cast<size_t>(plaintextLen));

    return Utils::GStatus::Ok();
}

/**
 * @brief Compute SHA-256 hash of data
 *
 * @param data Input data
 * @param outHash Output 32-byte hash
 * @return GStatus indicating success or failure
 */
Utils::GStatus ComputeSHA256(
      const std::vector<uint8_t>& data,
      std::vector<uint8_t>& outHash) noexcept
{
    outHash.resize(SHA256_DIGEST_LENGTH);

    if (SHA256(data.data(), data.size(), outHash.data()) == nullptr)
    {
        outHash.clear();
        return Utils::GStatus::Error("SHA256 computation failed");
    }

    return Utils::GStatus::Ok();
}

/**
 * @brief Compute SHA-256 hash of a file
 *
 * @param filePath Path to file
 * @param outHash Output 32-byte hash
 * @return GStatus indicating success or failure
 */
Utils::GStatus ComputeFileSHA256(
      const std::filesystem::path& filePath,
      std::vector<uint8_t>& outHash) noexcept
{
    try
    {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            return Utils::GStatus::Error("Failed to open file: " + filePath.string());
        }

        SHA256_CTX ctx;
        if (SHA256_Init(&ctx) != 1)
        {
            return Utils::GStatus::Error("SHA256_Init failed");
        }

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
        {
            if (SHA256_Update(&ctx, buffer, static_cast<size_t>(file.gcount())) != 1)
            {
                return Utils::GStatus::Error("SHA256_Update failed");
            }
        }

        outHash.resize(SHA256_DIGEST_LENGTH);
        if (SHA256_Final(outHash.data(), &ctx) != 1)
        {
            outHash.clear();
            return Utils::GStatus::Error("SHA256_Final failed");
        }

        return Utils::GStatus::Ok();
    }
    catch (const std::exception& e)
    {
        return Utils::GStatus::Error(std::string("File hashing error: ") + e.what());
    }
}

/**
 * @brief Derive a key using HKDF (HMAC-based Key Derivation Function)
 *
 * @param inputKey Input keying material
 * @param salt Salt value (can be empty)
 * @param info Context/application-specific info
 * @param outputLength Desired output key length
 * @param outKey Output derived key
 * @return GStatus indicating success or failure
 */
Utils::GStatus DeriveKeyHKDF(
      const std::vector<uint8_t>& inputKey,
      const std::vector<uint8_t>& salt,
      const std::vector<uint8_t>& info,
      size_t outputLength,
      std::vector<uint8_t>& outKey) noexcept
{
    if (inputKey.empty())
    {
        return Utils::GStatus::Error("Empty input key");
    }

    if (outputLength == 0 || outputLength > 255 * SHA256_DIGEST_LENGTH)
    {
        return Utils::GStatus::Error("Invalid output length");
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx == nullptr)
    {
        return Utils::GStatus::Error("Failed to create HKDF context: " + GetOpenSSLError());
    }

    // RAII cleanup
    struct PCtxDeleter {
        EVP_PKEY_CTX* ctx;
        ~PCtxDeleter()
        {
            if (ctx)
                EVP_PKEY_CTX_free(ctx);
        }
    } cleanup{ pctx };

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        return Utils::GStatus::Error("HKDF init failed: " + GetOpenSSLError());
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
    {
        return Utils::GStatus::Error("Failed to set HKDF digest: " + GetOpenSSLError());
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, inputKey.data(), static_cast<int>(inputKey.size())) <= 0)
    {
        return Utils::GStatus::Error("Failed to set HKDF key: " + GetOpenSSLError());
    }

    if (!salt.empty())
    {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) <= 0)
        {
            return Utils::GStatus::Error("Failed to set HKDF salt: " + GetOpenSSLError());
        }
    }

    if (!info.empty())
    {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) <= 0)
        {
            return Utils::GStatus::Error("Failed to set HKDF info: " + GetOpenSSLError());
        }
    }

    outKey.resize(outputLength);
    size_t outLen = outputLength;
    if (EVP_PKEY_derive(pctx, outKey.data(), &outLen) <= 0)
    {
        outKey.clear();
        return Utils::GStatus::Error("HKDF derivation failed: " + GetOpenSSLError());
    }

    outKey.resize(outLen);
    return Utils::GStatus::Ok();
}

/**
 * @brief Generate cryptographically secure random bytes
 *
 * @param length Number of random bytes to generate
 * @param outBytes Output random bytes
 * @return GStatus indicating success or failure
 */
Utils::GStatus GenerateRandomBytes(size_t length, std::vector<uint8_t>& outBytes) noexcept
{
    if (length == 0)
    {
        return Utils::GStatus::Error("Invalid length");
    }

    outBytes.resize(length);
    if (RAND_bytes(outBytes.data(), static_cast<int>(length)) != 1)
    {
        outBytes.clear();
        return Utils::GStatus::Error("Random generation failed: " + GetOpenSSLError());
    }

    return Utils::GStatus::Ok();
}

/**
 * @brief Securely erase memory
 *
 * @param ptr Pointer to memory
 * @param size Size of memory region
 */
void SecureErase(void* ptr, size_t size) noexcept
{
    SecureZero(ptr, size);
}

} // namespace Internal

} // namespace GView::Security::Crypto

