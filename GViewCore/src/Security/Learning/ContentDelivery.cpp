#include "ContentDelivery.hpp"

#include <cstring>
#include <cstdlib>
#include <fstream>

#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#endif

namespace GView::Security::Learning
{
using RestrictedMode::Policy;
using RestrictedMode::StorageMode;

Utils::GStatus DeriveContentKey(const SecureString& token, std::string_view policyId, LockedBuffer& outKey)
{
    if (token.empty() || policyId.empty())
        return Utils::GStatus::Error("content key needs a token and a policy id");
    if (!outKey.Allocate(CONTENT_KEY_SIZE))
        return Utils::GStatus::Error("failed to allocate the content key");
    auto st = Crypto::Internal::DeriveKeyHKDF(ToView(token), BufferView(policyId), BufferView(CONTENT_INFO_LABEL), outKey.Data(), CONTENT_KEY_SIZE);
    if (!st.ok)
        outKey.Wipe();
    return st;
}

std::string ContentKeyId(BufferView key)
{
    uint8 hash[32];
    if (!Crypto::Internal::ComputeSHA256(key, hash).ok)
        return {};
    return ToHex(BufferView(hash, 8));
}

SecureBytes BuildContentAad(std::string_view itemName, std::string_view policyId)
{
    SecureBytes aad;
    aad.reserve(itemName.size() + 1 + policyId.size());
    aad.insert(aad.end(), itemName.begin(), itemName.end());
    aad.push_back(0);
    aad.insert(aad.end(), policyId.begin(), policyId.end());
    return aad;
}

Utils::GStatus DecryptContentBlob(BufferView blob, BufferView key, std::string_view itemName, std::string_view policyId, LockedBuffer& out)
{
    if (blob.GetLength() < BLOB_HEADER_SIZE + BLOB_TAG_SIZE + 1)
        return Utils::GStatus::Error("encrypted blob is too short");
    if (std::memcmp(blob.GetData(), BLOB_MAGIC.data(), BLOB_MAGIC.size()) != 0)
        return Utils::GStatus::Error("encrypted blob has an unknown format (expected GVE1)");
    const size_t ctLen = blob.GetLength() - BLOB_HEADER_SIZE - BLOB_TAG_SIZE;
    const BufferView iv(blob.GetData() + 4, BLOB_IV_SIZE);
    const BufferView ct(blob.GetData() + BLOB_HEADER_SIZE, ctLen);
    const BufferView tag(blob.GetData() + BLOB_HEADER_SIZE + ctLen, BLOB_TAG_SIZE);
    const SecureBytes aad = BuildContentAad(itemName, policyId);

    LockedBuffer plain;
    if (!plain.Allocate(ctLen))
        return Utils::GStatus::Error("failed to allocate memory for the decrypted content");
    size_t produced = 0;
    auto st         = Crypto::Internal::DecryptAES256GCMInto(iv, ct, tag, key, ToView(aad), plain.Data(), plain.Size(), produced);
    if (!st.ok)
        return st; // plain is wiped by its destructor
    plain.Truncate(produced);
    out = std::move(plain);
    return Utils::GStatus::Ok();
}

Utils::GStatus VerifySha256Hex(BufferView data, std::string_view expectedHex)
{
    if (expectedHex.size() != 64)
        return Utils::GStatus::Error("invalid expected SHA-256");
    uint8 hash[32];
    auto st = Crypto::Internal::ComputeSHA256(data, hash);
    if (!st.ok)
        return st;
    const std::string actual = ToHex(BufferView(hash, sizeof(hash)));
    if (!Crypto::Internal::ConstantTimeEquals(actual.data(), expectedHex.data(), 64))
        return Utils::GStatus::Error("SHA-256 mismatch: the delivered content is corrupted or was modified");
    return Utils::GStatus::Ok();
}

DeliveryMode ResolveDeliveryMode(const Policy* policy, const CatalogueItem& item, const DeliveryHeaders& headers) noexcept
{
    if (policy != nullptr && policy->storageMode == StorageMode::Memory)
        return DeliveryMode::Memory;
    if (item.deliveryMode == DeliveryMode::Memory)
        return DeliveryMode::Memory;
    if (headers.hasMode && headers.mode == DeliveryMode::Memory)
        return DeliveryMode::Memory;
    if (policy == nullptr)
        return DeliveryMode::Memory; // legacy servers: keep the historic behaviour (open as an in-memory buffer)
    return DeliveryMode::File;
}

Utils::GStatus ProcessDownloadResponse(HttpResponse& response, const CatalogueItem& item, const DeliveryContext& ctx, DeliveredContent& out)
{
    const bool v2 = ctx.policy != nullptr;
    DeliveryHeaders headers;
    auto st = ParseDeliveryHeaders(response.headers, v2, headers);
    if (!st.ok)
        return st;
    if (response.body.empty())
        return Utils::GStatus::Error("the delivered content is empty");

    DeliveredContent result;
    result.mode        = ResolveDeliveryMode(ctx.policy, item, headers);
    result.itemVersion = headers.itemVersion;
    result.fileName    = !headers.fileName.empty() ? headers.fileName : (!item.fileName.empty() ? item.fileName : SanitizeFileName(item.name));

    if (headers.encrypted)
    {
        if (!v2 || ctx.token == nullptr)
            return Utils::GStatus::Error("encrypted content requires an active course policy");
        if (!ctx.policy->contentEncryption.empty() && ctx.policy->contentEncryption != "aes-256-gcm-hkdf-v1")
            return Utils::GStatus::Error("unsupported content encryption");
        LockedBuffer key;
        st = DeriveContentKey(*ctx.token, ctx.policy->id, key);
        if (!st.ok)
            return st;
        if (!ctx.policy->contentKeyId.empty())
        {
            // detect a key mismatch before attempting to decrypt (spec §3.4)
            const std::string expected = ToHex(BufferView(ctx.policy->contentKeyId.data(), ctx.policy->contentKeyId.size()));
            if (ContentKeyId(key.View()) != expected)
                return Utils::GStatus::Error("content key id mismatch: the content was encrypted for a different token or policy");
        }
        st = DecryptContentBlob(ToView(response.body), key.View(), item.name, ctx.policy->id, result.data);
        if (!st.ok)
            return st;
        result.wasEncrypted = true;
    }
    else
    {
        if (result.mode == DeliveryMode::Memory && v2 && !ctx.policy->contentEncryption.empty())
            return Utils::GStatus::Error("memory-only content was delivered unencrypted although the policy requires encryption");
        if (!result.data.Allocate(response.body.size()))
            return Utils::GStatus::Error("failed to allocate memory for the delivered content");
        std::memcpy(result.data.Data(), response.body.data(), response.body.size());
    }
    // the ciphertext / plaintext copy in the HTTP buffer is no longer needed
    response.body.clear();
    response.body.shrink_to_fit();

    if (!headers.sha256.empty())
    {
        st = VerifySha256Hex(result.data.View(), headers.sha256);
        if (!st.ok)
            return st;
        result.sha256 = headers.sha256;
    }
    else if (v2)
        return Utils::GStatus::Error("missing X-GView-SHA256 header");
    else
    {
        uint8 hash[32];
        if (Crypto::Internal::ComputeSHA256(result.data.View(), hash).ok)
            result.sha256 = ToHex(BufferView(hash, sizeof(hash)));
    }
    out = std::move(result);
    return Utils::GStatus::Ok();
}

std::filesystem::path PathFromUtf8(std::string_view utf8)
{
    return std::filesystem::path(std::u8string_view(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size()));
}

std::string PathToUtf8(const std::filesystem::path& p)
{
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::filesystem::path DefaultDownloadFolder(std::string_view configuredFolder, std::string_view weekName)
{
    std::filesystem::path base;
    if (!configuredFolder.empty())
    {
        base = PathFromUtf8(configuredFolder);
    }
    else
    {
#ifdef BUILD_FOR_WINDOWS
        wchar_t profile[MAX_PATH] = {};
        const DWORD n             = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
        if (n > 0 && n < MAX_PATH)
            base = std::filesystem::path(profile) / "Documents" / "GView";
#else
        if (const char* home = std::getenv("HOME"); home != nullptr && home[0] == '/')
            base = std::filesystem::path(home) / "Documents" / "GView";
#endif
        if (base.empty())
            base = std::filesystem::current_path() / "GView";
    }
    const std::string week = SanitizeFileName(weekName.empty() ? std::string_view("Course") : weekName);
    return base / PathFromUtf8(week);
}

Utils::GStatus WriteFileAtomic(
      const std::filesystem::path& folder, std::string_view fileName, BufferView data, std::string_view expectedSha256Hex, std::filesystem::path& outPath)
{
    std::filesystem::path partPath;
    try
    {
        const std::string safeName = SanitizeFileName(fileName);
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        if (ec)
            return Utils::GStatus::Error("cannot create the download folder: " + ec.message());
        const auto finalPath = folder / PathFromUtf8(safeName);
        // defence in depth: the sanitised name can never escape the folder
        if (finalPath.parent_path().lexically_normal() != folder.lexically_normal())
            return Utils::GStatus::Error("invalid file name");
        partPath = finalPath;
        partPath += ".part";
        {
            std::ofstream f(partPath, std::ios::binary | std::ios::trunc);
            if (!f.is_open())
                return Utils::GStatus::Error("cannot create " + PathToUtf8(partPath));
            f.write(reinterpret_cast<const char*>(data.GetData()), static_cast<std::streamsize>(data.GetLength()));
            f.flush();
            if (!f.good())
            {
                f.close();
                std::filesystem::remove(partPath, ec);
                return Utils::GStatus::Error("failed to write the downloaded content");
            }
        }
        if (!expectedSha256Hex.empty())
        {
            std::vector<uint8_t> hash;
            auto st = Crypto::Internal::ComputeFileSHA256(partPath, hash);
            if (!st.ok || ToHex(BufferView(hash.data(), hash.size())) != expectedSha256Hex)
            {
                std::filesystem::remove(partPath, ec);
                return Utils::GStatus::Error("the file written to disk does not match the expected SHA-256");
            }
        }
#ifdef BUILD_FOR_WINDOWS
        if (!MoveFileExW(partPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::filesystem::remove(partPath, ec);
            return Utils::GStatus::Error("cannot move the downloaded file into place (is it open in another program?)");
        }
#else
        std::filesystem::rename(partPath, finalPath, ec);
        if (ec)
        {
            std::filesystem::remove(partPath, ec);
            return Utils::GStatus::Error("cannot move the downloaded file into place: " + ec.message());
        }
#endif
        outPath = finalPath;
        return Utils::GStatus::Ok();
    }
    catch (const std::exception& e)
    {
        std::error_code ec;
        if (!partPath.empty())
            std::filesystem::remove(partPath, ec);
        return Utils::GStatus::Error(std::string("file write failed: ") + e.what());
    }
}

// ============================================================================ LockedMemoryDataObject
LockedMemoryDataObject::LockedMemoryDataObject(LockedBuffer&& data) noexcept : buffer(std::move(data))
{
}

LockedMemoryDataObject::~LockedMemoryDataObject()
{
    Close();
}

bool LockedMemoryDataObject::ReadBuffer(void* dest, uint32 bufferSize, uint32& bytesRead)
{
    bytesRead = 0;
    if (dest == nullptr)
        return false;
    if (pos >= buffer.Size() || bufferSize == 0)
        return true;
    const uint64 toRead = std::min<uint64>(buffer.Size() - pos, bufferSize);
    std::memcpy(dest, buffer.Data() + pos, static_cast<size_t>(toRead));
    bytesRead = static_cast<uint32>(toRead);
    pos += toRead;
    return true;
}

bool LockedMemoryDataObject::WriteBuffer(const void*, uint32, uint32& bytesWritten)
{
    bytesWritten = 0;
    return false; // task content is read-only
}

uint64 LockedMemoryDataObject::GetSize()
{
    return buffer.Size();
}

uint64 LockedMemoryDataObject::GetCurrentPos()
{
    return pos;
}

bool LockedMemoryDataObject::SetSize(uint64)
{
    return false;
}

bool LockedMemoryDataObject::SetCurrentPos(uint64 newPosition)
{
    if (newPosition > buffer.Size())
        return false;
    pos = newPosition;
    return true;
}

void LockedMemoryDataObject::Close()
{
    buffer.Wipe();
    pos = 0;
}
} // namespace GView::Security::Learning
