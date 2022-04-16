#include <cassert>
#include <GView.hpp>
#include <openssl/evp.h>

namespace GView::Hashes
{

// size == 0 means we haven't called EVP_DigestFinal_ex yet
// we do this to avoid calling that twice

OpenSSLHash::OpenSSLHash(OpenSSLHashKind kind)
{
#define H(n, f)                                                                                                                            \
    case OpenSSLHashKind::n:                                                                                                               \
        alg = EVP_##f();                                                                                                                   \
        break

    const EVP_MD* alg = nullptr;
    switch (kind)
    {
        H(Md4, md4);
        H(Md5, md5);
        H(Blake2s256, blake2s256);
        H(Blake2b512, blake2b512);
        H(Sha1, sha1);
        H(Sha224, sha224);
        H(Sha256, sha256);
        H(Sha384, sha384);
        H(Sha512, sha512);
        H(Sha512_224, sha512_224);
        H(Sha512_256, sha512_256);
        H(Sha3_224, sha3_224);
        H(Sha3_256, sha3_256);
        H(Sha3_384, sha3_384);
        H(Sha3_512, sha3_512);
        H(Shake128, shake128);
        H(Shake256, shake256);
    }
    auto ctx = EVP_MD_CTX_new();
    assert(EVP_DigestInit_ex(ctx, alg, nullptr));
    handle = ctx;
    size   = 0;
}
OpenSSLHash::~OpenSSLHash()
{
    EVP_MD_CTX_free((EVP_MD_CTX*) handle);
}

bool OpenSSLHash::Update(const void* input, uint32 length)
{
    return EVP_DigestUpdate((EVP_MD_CTX*) handle, input, length);
}

bool OpenSSLHash::Final()
{
    if (size != 0)
    {
        return true;
    }
    return EVP_DigestFinal_ex((EVP_MD_CTX*) handle, hash, &size);
}

std::string_view OpenSSLHash::GetHexValue()
{
    if (!Final())
    {
        return {};
    }

    LocalString<(sizeof(hash) / sizeof(hash[0])) * 2> ls;
    for (auto i = 0U; i < size; i++)
    {
        ls.AddFormat("%.2X", hash[i]);
    }
    memcpy(hexDigest, ls.GetText(), size * 2ULL);

    return { hexDigest, size * 2 };
}

const uint8* OpenSSLHash::Get() const
{
    assert(size != 0);
    return hash;
}

uint32 OpenSSLHash::GetSize() const
{
    assert(size != 0);
    return size;
}

} // namespace GView::Hashes