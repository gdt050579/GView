#pragma once

// Task / resource content delivery (spec §3.3 - §3.4):
//  - "GVE1" blob decryption (HKDF-SHA256 key, AES-256-GCM, AAD = item \0 policyId) straight into locked memory
//  - SHA-256 verification of the plaintext
//  - memory mode: a read-only AppCUI DataObject backed by the locked buffer (no file is ever created)
//  - file mode: atomic write (<name>.part -> rename) into a user folder, verified after write

#include "LearningHttp.hpp"

#include <filesystem>

namespace GView::Security::Learning
{
constexpr size_t CONTENT_KEY_SIZE = 32;
constexpr size_t BLOB_IV_SIZE     = 12;
constexpr size_t BLOB_TAG_SIZE    = 16;
constexpr size_t BLOB_HEADER_SIZE = 4 + BLOB_IV_SIZE;

// key = HKDF-SHA256(ikm = token, salt = policyId, info = "GView-Content-v1", L = 32)
Utils::GStatus DeriveContentKey(const SecureString& token, std::string_view policyId, LockedBuffer& outKey);
// hex(sha256(key))[0:16]
std::string ContentKeyId(BufferView key);
SecureBytes BuildContentAad(std::string_view itemName, std::string_view policyId);
Utils::GStatus DecryptContentBlob(BufferView blob, BufferView key, std::string_view itemName, std::string_view policyId, LockedBuffer& out);
Utils::GStatus VerifySha256Hex(BufferView data, std::string_view expectedHex);

struct DeliveredContent {
    LockedBuffer data;
    std::string fileName;
    std::string sha256; // lowercase hex of data (verified against X-GView-SHA256 when the server sent it)
    DeliveryMode mode{ DeliveryMode::File };
    uint32 itemVersion{ 0 };
    bool wasEncrypted{ false };
};

struct DeliveryContext {
    const RestrictedMode::Policy* policy{ nullptr }; // null => legacy (unrestricted) session
    const SecureString* token{ nullptr };
};

// Most restrictive of policy.storageMode, the catalogue entry and the X-GView-Delivery header (memory wins).
DeliveryMode ResolveDeliveryMode(const RestrictedMode::Policy* policy, const CatalogueItem& item, const DeliveryHeaders& headers) noexcept;

// Validates and decodes a successful download response. The response body is wiped when this returns.
Utils::GStatus ProcessDownloadResponse(HttpResponse& response, const CatalogueItem& item, const DeliveryContext& ctx, DeliveredContent& out);

// UTF-8 <-> std::filesystem::path (C++20: u8string() returns std::u8string)
std::filesystem::path PathFromUtf8(std::string_view utf8);
std::string PathToUtf8(const std::filesystem::path& p);

// File mode helpers
std::filesystem::path DefaultDownloadFolder(std::string_view configuredFolder, std::string_view weekName);
Utils::GStatus WriteFileAtomic(
      const std::filesystem::path& folder, std::string_view fileName, BufferView data, std::string_view expectedSha256Hex, std::filesystem::path& outPath);

// Read-only DataObject over locked memory; the content is wiped when the object is closed/destroyed.
class LockedMemoryDataObject : public AppCUI::OS::DataObject
{
    LockedBuffer buffer;
    uint64 pos{ 0 };

  protected:
    bool ReadBuffer(void* dest, uint32 bufferSize, uint32& bytesRead) override;
    bool WriteBuffer(const void* source, uint32 bufferSize, uint32& bytesWritten) override;

  public:
    explicit LockedMemoryDataObject(LockedBuffer&& data) noexcept;
    ~LockedMemoryDataObject() override;
    uint64 GetSize() override;
    uint64 GetCurrentPos() override;
    bool SetSize(uint64 newSize) override;
    bool SetCurrentPos(uint64 newPosition) override;
    void Close() override;
};
} // namespace GView::Security::Learning
