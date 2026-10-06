#include "RemoteTls.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <ctime>
#include <fstream>
#include <vector>

#ifndef BUILD_FOR_WINDOWS
#    include <fcntl.h>
#    include <sys/stat.h>
#    include <unistd.h>
#endif

namespace GView::Remote::Tls
{
namespace
{
    constexpr const char* CIPHER_SUITES   = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    constexpr const char* KEY_EXCHANGE    = "X25519";
    constexpr int SECURITY_LEVEL          = 3; // >= 128 bit security for every key and signature in the chain
    constexpr int MAX_VERIFY_DEPTH        = 4;
    constexpr uint32 MAX_CA_DAYS          = 3650;
    constexpr uint32 MAX_CERTIFICATE_DAYS = 825;
    constexpr long CLOCK_SKEW_SECONDS     = 300;

    struct BioDeleter {
        void operator()(BIO* p) const
        {
            BIO_free(p);
        }
    };
    struct X509Deleter {
        void operator()(X509* p) const
        {
            X509_free(p);
        }
    };
    struct KeyDeleter {
        void operator()(EVP_PKEY* p) const
        {
            EVP_PKEY_free(p);
        }
    };
    using BioPtr  = std::unique_ptr<BIO, BioDeleter>;
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;
    using KeyPtr  = std::unique_ptr<EVP_PKEY, KeyDeleter>;

    std::string OpenSslErrors()
    {
        std::string result;
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
            char buffer[256];
            ERR_error_string_n(e, buffer, sizeof(buffer));
            if (!result.empty())
                result += "; ";
            result += buffer;
        }
        return result.empty() ? "unknown TLS error" : result;
    }
    // private keys are never encrypted (unattended servers): refuse any passphrase prompt
    int NoPassword(char*, int, int, void*)
    {
        return 0;
    }
    std::string Printable(std::string_view text)
    {
        std::string r;
        r.reserve(text.size());
        for (auto ch : text)
            r.push_back((ch >= 0x20 && ch < 0x7F) ? ch : '?');
        return r;
    }
    std::string PathText(const std::filesystem::path& p)
    {
        const auto u8 = p.u8string();
        return std::string(reinterpret_cast<const char*>(u8.c_str()), u8.size());
    }
    bool ReadSmallFile(const std::filesystem::path& path, std::string& content, std::string& error)
    {
        std::error_code ec;
        const auto size = std::filesystem::file_size(path, ec);
        if (ec) {
            error = "cannot access '" + PathText(path) + "': " + ec.message();
            return false;
        }
        if (size == 0 || size > MAX_CERTIFICATE_FILE_SIZE) {
            error = "'" + PathText(path) + "' is empty or too large";
            return false;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            error = "cannot open '" + PathText(path) + "'";
            return false;
        }
        content.resize(static_cast<size_t>(size));
        if (!f.read(content.data(), static_cast<std::streamsize>(size))) {
            error = "cannot read '" + PathText(path) + "'";
            return false;
        }
        return true;
    }
    BioPtr MemoryBio(const std::string& content)
    {
        return BioPtr(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    }
    // reads every PEM certificate of a file
    bool ReadCertificates(const std::filesystem::path& path, std::vector<X509Ptr>& certificates, std::string& error)
    {
        std::string content;
        if (!ReadSmallFile(path, content, error))
            return false;
        auto bio = MemoryBio(content);
        if (!bio) {
            error = OpenSslErrors();
            return false;
        }
        while (true) {
            X509* x = PEM_read_bio_X509(bio.get(), nullptr, NoPassword, nullptr);
            if (!x)
                break;
            certificates.emplace_back(x);
        }
        ERR_clear_error(); // end of data is reported as an error
        if (certificates.empty()) {
            error = "no PEM certificate found in '" + PathText(path) + "'";
            return false;
        }
        return true;
    }
    bool ReadPrivateKey(const std::filesystem::path& path, KeyPtr& key, std::string& error)
    {
#ifndef BUILD_FOR_WINDOWS
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            error = "the private key '" + PathText(path) + "' is accessible by other users (use: chmod 600)";
            return false;
        }
#endif
        std::string content;
        if (!ReadSmallFile(path, content, error))
            return false;
        auto bio = MemoryBio(content);
        key.reset(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, NoPassword, nullptr) : nullptr);
        // wipe the PEM copy of the key
        OPENSSL_cleanse(content.data(), content.size());
        if (!key) {
            error = "cannot load the private key '" + PathText(path) + "' (PEM, unencrypted): " + OpenSslErrors();
            return false;
        }
        return true;
    }

    int LifetimeIndex()
    {
        static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
        return index;
    }
    int VerifyCallback(int preverifyOk, X509_STORE_CTX* store)
    {
        if (preverifyOk != 1)
            return 0;
        if (X509_STORE_CTX_get_error_depth(store) != 0)
            return 1;
        auto ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
        if (!ssl)
            return 0;
        const auto maxDays = reinterpret_cast<uintptr_t>(SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), LifetimeIndex()));
        if (maxDays == 0)
            return 1;
        X509* cert = X509_STORE_CTX_get_current_cert(store);
        int days = 0, seconds = 0;
        if (!cert || ASN1_TIME_diff(&days, &seconds, X509_get0_notBefore(cert), X509_get0_notAfter(cert)) != 1 || days < 0 || seconds < 0 ||
            static_cast<uintptr_t>(days) > maxDays || (static_cast<uintptr_t>(days) == maxDays && seconds > 0)) {
            // short-lived certificates only: a long-lived (possibly stolen / forgotten) certificate is refused
            X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        }
        return 1;
    }
    int AlpnSelect(SSL*, const unsigned char** out, unsigned char* outLength, const unsigned char* in, unsigned int inLength, void* arg)
    {
        const auto& expected = *static_cast<const std::string*>(arg); // length prefixed
        unsigned int pos     = 0;
        while (pos < inLength) {
            const unsigned int len = in[pos];
            if (len == 0 || len > inLength - pos - 1)
                break;
            if (len + 1 == expected.size() && memcmp(in + pos, expected.data(), expected.size()) == 0) {
                *out       = in + pos + 1;
                *outLength = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }
            pos += len + 1;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL; // a peer that does not speak the GView protocol is refused
    }
} // namespace

bool Settings::Validate(std::string& error) const
{
    if (certificate.empty() || privateKey.empty() || trustedCA.empty()) {
        error = "the remote mode requires a certificate, its private key and a trusted CA bundle "
                "(see 'GView remote-certs' and the [Remote] section of gview.ini)";
        return false;
    }
    if (alpn.empty() || alpn.size() > 255) {
        error = "invalid ALPN value";
        return false;
    }
    for (auto ch : alpn) {
        if (ch <= 0x20 || ch >= 0x7F) {
            error = "invalid ALPN value (printable ASCII without spaces expected)";
            return false;
        }
    }
    if (maxPeerCertificateLifetimeDays > MAX_CA_DAYS) {
        error = "invalid maximum certificate lifetime";
        return false;
    }
    return true;
}

Context::~Context()
{
    if (ctx)
        SSL_CTX_free(ctx);
}

std::shared_ptr<Context> Context::Create(const Settings& settings, Role role, std::string& error)
{
    if (!settings.Validate(error))
        return nullptr;
    ERR_clear_error();
    auto c  = std::shared_ptr<Context>(new Context(role));
    c->alpn = settings.alpn;
    c->alpnWire.push_back(static_cast<char>(settings.alpn.size()));
    c->alpnWire += settings.alpn;

    c->ctx = SSL_CTX_new(role == Role::Server ? TLS_server_method() : TLS_client_method());
    if (!c->ctx) {
        error = "SSL_CTX_new: " + OpenSslErrors();
        return nullptr;
    }
    auto ctx = c->ctx;
    // protocol hardening
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, CIPHER_SUITES) != 1 || SSL_CTX_set1_groups_list(ctx, KEY_EXCHANGE) != 1) {
        error = "cannot configure TLS 1.3: " + OpenSslErrors();
        return nullptr;
    }
    SSL_CTX_set_security_level(ctx, SECURITY_LEVEL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (role == Role::Server) {
        // no resumption tickets and no early data (0-RTT data can be replayed)
        SSL_CTX_set_num_tickets(ctx, 0);
        SSL_CTX_set_max_early_data(ctx, 0);
        SSL_CTX_set_recv_max_early_data(ctx, 0);
    }

    // own identity
    std::vector<X509Ptr> chain;
    if (!ReadCertificates(settings.certificate, chain, error))
        return nullptr;
    if (SSL_CTX_use_certificate(ctx, chain[0].get()) != 1) {
        error = "invalid certificate '" + PathText(settings.certificate) + "': " + OpenSslErrors();
        return nullptr;
    }
    for (size_t i = 1; i < chain.size(); i++) {
        if (SSL_CTX_add1_chain_cert(ctx, chain[i].get()) != 1) {
            error = "invalid intermediate certificate: " + OpenSslErrors();
            return nullptr;
        }
    }
    KeyPtr key;
    if (!ReadPrivateKey(settings.privateKey, key, error))
        return nullptr;
    if (SSL_CTX_use_PrivateKey(ctx, key.get()) != 1 || SSL_CTX_check_private_key(ctx) != 1) {
        error = "the private key does not match the certificate (or is too weak): " + OpenSslErrors();
        return nullptr;
    }

    // trust anchors: ONLY the configured CA bundle (never the system store)
    std::vector<X509Ptr> anchors;
    if (!ReadCertificates(settings.trustedCA, anchors, error))
        return nullptr;
    auto store = SSL_CTX_get_cert_store(ctx);
    for (auto& a : anchors) {
        if (X509_STORE_add_cert(store, a.get()) != 1) {
            error = "invalid CA certificate in '" + PathText(settings.trustedCA) + "': " + OpenSslErrors();
            return nullptr;
        }
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, VerifyCallback);
    SSL_CTX_set_verify_depth(ctx, MAX_VERIFY_DEPTH);
    SSL_CTX_set_ex_data(ctx, LifetimeIndex(), reinterpret_cast<void*>(static_cast<uintptr_t>(settings.maxPeerCertificateLifetimeDays)));

    // ALPN (mandatory)
    if (role == Role::Server) {
        SSL_CTX_set_alpn_select_cb(ctx, AlpnSelect, &c->alpnWire);
    } else if (SSL_CTX_set_alpn_protos(ctx, reinterpret_cast<const unsigned char*>(c->alpnWire.data()), static_cast<unsigned int>(c->alpnWire.size())) != 0) {
        error = "cannot configure ALPN: " + OpenSslErrors();
        return nullptr;
    }
    return c;
}

bool ContextProvider::ReadStamps(std::filesystem::file_time_type (&out)[3]) const
{
    const std::filesystem::path* files[3] = { &settings.certificate, &settings.privateKey, &settings.trustedCA };
    for (size_t i = 0; i < 3; i++) {
        std::error_code ec;
        out[i] = std::filesystem::last_write_time(*files[i], ec);
        if (ec)
            return false;
    }
    return true;
}

bool ContextProvider::Init(const Settings& s, Role r, std::string& error)
{
    std::lock_guard<std::mutex> guard(lock);
    settings = s;
    role     = r;
    current  = Context::Create(settings, role, error);
    if (!current)
        return false;
    ReadStamps(stamps);
    lastCheck = std::chrono::steady_clock::now();
    return true;
}

std::shared_ptr<Context> ContextProvider::Get(std::string& reloadError)
{
    std::lock_guard<std::mutex> guard(lock);
    reloadError.clear();
    const auto now = std::chrono::steady_clock::now();
    if (now - lastCheck < std::chrono::seconds(2))
        return current;
    lastCheck = now;
    std::filesystem::file_time_type fresh[3];
    if (!ReadStamps(fresh))
        return current; // files temporarily missing (rotation in progress) -> keep the current identity
    if (fresh[0] == stamps[0] && fresh[1] == stamps[1] && fresh[2] == stamps[2])
        return current;
    std::string error;
    auto next = Context::Create(settings, role, error);
    if (!next) {
        // e.g. the new certificate was written but the new key not yet -> keep the previous context, retry later
        reloadError = "cannot reload the TLS identity (the previous one stays in use): " + error;
        return current;
    }
    current = std::move(next);
    for (size_t i = 0; i < 3; i++)
        stamps[i] = fresh[i];
    return current;
}

// ------------------------------------------------------------------ stream
Stream::~Stream()
{
    if (ssl)
        SSL_free(ssl);
}

std::unique_ptr<Stream> Stream::Create(std::shared_ptr<Context> context, Net::Socket&& socket, const std::string& expectedPeerName, std::string& error)
{
    if (!context || !socket.IsValid()) {
        error = "invalid TLS context or socket";
        return nullptr;
    }
    ERR_clear_error();
    auto s     = std::unique_ptr<Stream>(new Stream());
    s->context = std::move(context);
    s->socket  = std::move(socket);
    s->ssl     = SSL_new(s->context->Native());
    if (!s->ssl || SSL_set_fd(s->ssl, static_cast<int>(s->socket.Get())) != 1) {
        error = "SSL_new: " + OpenSslErrors();
        return nullptr;
    }
    if (s->context->GetRole() == Role::Client) {
        if (expectedPeerName.empty()) {
            error = "the server name to verify is missing";
            return nullptr;
        }
        auto param = SSL_get0_param(s->ssl);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (Net::IsIpAddress(expectedPeerName)) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, expectedPeerName.c_str()) != 1) {
                error = "invalid server address: " + OpenSslErrors();
                return nullptr;
            }
        } else if (SSL_set_tlsext_host_name(s->ssl, expectedPeerName.c_str()) != 1 || SSL_set1_host(s->ssl, expectedPeerName.c_str()) != 1) {
            error = "invalid server name: " + OpenSslErrors();
            return nullptr;
        }
        SSL_set_connect_state(s->ssl);
    } else {
        SSL_set_accept_state(s->ssl);
    }
    return s;
}

bool Stream::Handshake(std::chrono::steady_clock::time_point deadline, const std::atomic<bool>& stop, Net::Waker& waker, std::string& error)
{
    while (true) {
        if (stop.load()) {
            error = "cancelled";
            return false;
        }
        ERR_clear_error();
        const int rc = SSL_do_handshake(ssl);
        if (rc == 1)
            break;
        const int e          = SSL_get_error(ssl, rc);
        const bool wantRead  = e == SSL_ERROR_WANT_READ;
        const bool wantWrite = e == SSL_ERROR_WANT_WRITE;
        if (!wantRead && !wantWrite) {
            const long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK)
                error = std::string("peer certificate rejected: ") + (verify == X509_V_ERR_APPLICATION_VERIFICATION
                                                                            ? "its lifetime exceeds the allowed maximum (short-lived certificates required)"
                                                                            : X509_verify_cert_error_string(verify));
            else if (ERR_peek_error() != 0)
                error = "TLS handshake failed: " + OpenSslErrors();
            else
                error = "the connection was closed during the TLS handshake";
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            error = "TLS handshake timed out";
            return false;
        }
        const auto left         = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        Net::PollRequest req[2] = {};
        req[0].socket           = socket.Get();
        req[0].wantRead         = wantRead;
        req[0].wantWrite        = wantWrite;
        req[1].socket           = waker.Get();
        req[1].wantRead         = true;
        if (!Net::Poll(req, 2, static_cast<int>(std::min<long long>(left, 250)))) {
            error = "poll: " + Net::LastErrorText();
            return false;
        }
        if (req[1].readable)
            waker.Drain();
    }

    // defence in depth: re-check everything the policy requires
    if (SSL_version(ssl) != TLS1_3_VERSION) {
        error = "TLS 1.3 was not negotiated";
        return false;
    }
    X509Ptr peerCertificate(SSL_get1_peer_certificate(ssl));
    if (!peerCertificate || SSL_get_verify_result(ssl) != X509_V_OK) {
        error = "the peer did not present a valid certificate";
        return false;
    }
    const unsigned char* selected = nullptr;
    unsigned int selectedLength   = 0;
    SSL_get0_alpn_selected(ssl, &selected, &selectedLength);
    if (selected == nullptr || std::string_view(reinterpret_cast<const char*>(selected), selectedLength) != context->GetAlpn()) {
        error = "the peer did not negotiate the '" + context->GetAlpn() + "' protocol (ALPN)";
        return false;
    }

    char subject[512] = {};
    X509_NAME_oneline(X509_get_subject_name(peerCertificate.get()), subject, sizeof(subject));
    peer.subject = Printable(subject);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLength = 0;
    if (X509_digest(peerCertificate.get(), EVP_sha256(), md, &mdLength) == 1) {
        static const char hex[] = "0123456789ABCDEF";
        peer.fingerprint.clear();
        for (unsigned int i = 0; i < mdLength; i++) {
            if (i)
                peer.fingerprint.push_back(':');
            peer.fingerprint.push_back(hex[md[i] >> 4]);
            peer.fingerprint.push_back(hex[md[i] & 0x0F]);
        }
    }
    const char* cipher = SSL_get_cipher_name(ssl);
    peer.cipher        = cipher ? cipher : "";
    return true;
}

Stream::Io Stream::Translate(int rc)
{
    const int e = SSL_get_error(ssl, rc);
    switch (e) {
    case SSL_ERROR_WANT_READ:
        return Io::WantRead;
    case SSL_ERROR_WANT_WRITE:
        return Io::WantWrite;
    case SSL_ERROR_ZERO_RETURN:
        lastError = "connection closed by the peer";
        return Io::Closed;
    case SSL_ERROR_SYSCALL:
        if (ERR_peek_error() == 0) {
            lastError = "connection closed by the peer";
            return Io::Closed;
        }
        break;
    case SSL_ERROR_SSL:
        if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
            ERR_clear_error();
            lastError = "connection closed by the peer";
            return Io::Closed;
        }
        break;
    default:
        break;
    }
    // any TLS failure (including an integrity / authentication failure of a record) ends the session
    lastError = OpenSslErrors();
    return Io::Failed;
}

Stream::Io Stream::Read(uint8* buffer, size_t size, size_t& read)
{
    read = 0;
    ERR_clear_error();
    size_t n = 0;
    if (SSL_read_ex(ssl, buffer, size, &n) == 1) {
        read = n;
        return Io::Ok;
    }
    return Translate(0);
}

Stream::Io Stream::Write(const uint8* data, size_t size, size_t& written)
{
    written = 0;
    ERR_clear_error();
    size_t n = 0;
    if (SSL_write_ex(ssl, data, size, &n) == 1) {
        written = n;
        return Io::Ok;
    }
    return Translate(0);
}

void Stream::Shutdown()
{
    if (!ssl || shutdownSent)
        return;
    shutdownSent = true;
    ERR_clear_error();
    SSL_shutdown(ssl); // non-blocking socket -> sends close_notify if possible, never waits for the answer
    ERR_clear_error();
}

// ------------------------------------------------------------------ certificate generation
namespace
{
    KeyPtr GenerateKey()
    {
        EVP_PKEY* key = nullptr;
        auto ctx      = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx)
            return nullptr;
        if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &key) != 1)
            key = nullptr;
        EVP_PKEY_CTX_free(ctx);
        return KeyPtr(key);
    }
    bool SetRandomSerial(X509* x)
    {
        uint8 bytes[16];
        if (RAND_bytes(bytes, sizeof(bytes)) != 1)
            return false;
        bytes[0]   = static_cast<uint8>((bytes[0] & 0x7F) | 0x40); // positive, non-zero, 128 bits
        BIGNUM* bn = BN_bin2bn(bytes, sizeof(bytes), nullptr);
        if (!bn)
            return false;
        ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(bn, nullptr);
        BN_free(bn);
        if (!serial)
            return false;
        const bool ok = X509_set_serialNumber(x, serial) == 1;
        ASN1_INTEGER_free(serial);
        return ok;
    }
    bool AddExtension(X509* cert, X509* issuer, int nid, const char* value)
    {
        X509V3_CTX v3;
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, issuer, cert, nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, nid, value);
        if (!ext)
            return false;
        const bool ok = X509_add_ext(cert, ext, -1) == 1;
        X509_EXTENSION_free(ext);
        return ok;
    }
    // issuer == nullptr -> self signed CA
    X509Ptr CreateCertificate(EVP_PKEY* key, const std::string& commonName, X509* issuer, EVP_PKEY* issuerKey, uint32 days, const std::string& subjectAltName)
    {
        X509Ptr x(X509_new());
        if (!x || X509_set_version(x.get(), 2) != 1 || !SetRandomSerial(x.get()))
            return nullptr;
        // valid from a few minutes ago (clock skew) for exactly `days` days (so that `days` passes a lifetime cap of `days`)
        if (!X509_gmtime_adj(X509_getm_notBefore(x.get()), -CLOCK_SKEW_SECONDS) ||
            !X509_gmtime_adj(X509_getm_notAfter(x.get()), static_cast<long>(days) * 86400L - CLOCK_SKEW_SECONDS))
            return nullptr;
        if (X509_set_pubkey(x.get(), key) != 1)
            return nullptr;
        auto name = X509_get_subject_name(x.get());
        if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>("GView Remote"), -1, -1, 0) != 1 ||
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0) != 1)
            return nullptr;
        if (X509_set_issuer_name(x.get(), issuer ? X509_get_subject_name(issuer) : name) != 1)
            return nullptr;
        X509* extIssuer = issuer ? issuer : x.get();
        bool ok         = AddExtension(x.get(), extIssuer, NID_subject_key_identifier, "hash");
        if (issuer == nullptr) {
            ok = ok && AddExtension(x.get(), extIssuer, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") &&
                 AddExtension(x.get(), extIssuer, NID_key_usage, "critical,keyCertSign,cRLSign");
        } else {
            ok = ok && AddExtension(x.get(), extIssuer, NID_basic_constraints, "critical,CA:FALSE") &&
                 AddExtension(x.get(), extIssuer, NID_key_usage, "critical,digitalSignature") &&
                 AddExtension(x.get(), extIssuer, NID_ext_key_usage, "serverAuth,clientAuth") &&
                 AddExtension(x.get(), extIssuer, NID_subject_alt_name, subjectAltName.c_str());
        }
        ok = ok && AddExtension(x.get(), extIssuer, NID_authority_key_identifier, "keyid:always");
        if (!ok)
            return nullptr;
        // Ed25519 -> no separate digest
        if (X509_sign(x.get(), issuerKey ? issuerKey : key, nullptr) <= 0)
            return nullptr;
        return x;
    }
    std::string BioToString(BIO* bio)
    {
        char* data      = nullptr;
        const long size = BIO_get_mem_data(bio, &data);
        return (size > 0 && data) ? std::string(data, static_cast<size_t>(size)) : std::string();
    }
    std::string CertificateToPem(X509* x)
    {
        BioPtr bio(BIO_new(BIO_s_mem()));
        if (!bio || PEM_write_bio_X509(bio.get(), x) != 1)
            return {};
        return BioToString(bio.get());
    }
    std::string KeyToPem(EVP_PKEY* key)
    {
        BioPtr bio(BIO_new(BIO_s_mem()));
        if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
            return {};
        return BioToString(bio.get());
    }
    std::string TimeText(const ASN1_TIME* t)
    {
        BioPtr bio(BIO_new(BIO_s_mem()));
        if (!bio || ASN1_TIME_print(bio.get(), t) != 1)
            return "?";
        return BioToString(bio.get());
    }
    // written to a temporary file then renamed -> a server that reloads its identity never reads a partial file
    bool WriteFileAtomically(const std::filesystem::path& path, const std::string& content, bool secret, std::string& error)
    {
        auto temp = path;
        temp += ".tmp";
#ifdef BUILD_FOR_WINDOWS
        (void) secret; // the file inherits the ACL of the folder (keep it in a folder only the analyst can read)
        {
            std::ofstream f(temp, std::ios::binary | std::ios::trunc);
            if (!f || !f.write(content.data(), static_cast<std::streamsize>(content.size()))) {
                error = "cannot write '" + PathText(temp) + "'";
                return false;
            }
        }
#else
        const int fd = open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, secret ? 0600 : 0644);
        if (fd < 0) {
            error = "cannot create '" + PathText(temp) + "': " + Net::LastErrorText();
            return false;
        }
        fchmod(fd, secret ? 0600 : 0644);
        size_t done = 0;
        while (done < content.size()) {
            const auto n = write(fd, content.data() + done, content.size() - done);
            if (n <= 0) {
                close(fd);
                error = "cannot write '" + PathText(temp) + "'";
                return false;
            }
            done += static_cast<size_t>(n);
        }
        fsync(fd);
        close(fd);
#endif
        std::error_code ec;
        std::filesystem::rename(temp, path, ec);
        if (ec) {
            error = "cannot replace '" + PathText(path) + "': " + ec.message();
            return false;
        }
        return true;
    }
    bool IsValidCertificateName(const std::string& name)
    {
        if (name.empty() || name.size() > 253 || name.front() == '.' || name.front() == '-')
            return false;
        if (Net::IsIpAddress(name))
            return true;
        for (auto ch : name) {
            const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
            if (!ok)
                return false;
        }
        return true;
    }
} // namespace

bool GenerateCertificates(const std::filesystem::path& directory, const std::string& name, uint32 days, uint32 caDays, std::string& report, std::string& error)
{
    if (!IsValidCertificateName(name)) {
        error = "invalid name '" + Printable(name) + "' (expected a host name, an IP address or an analyst name: letters, digits, '.', '-', '_')";
        return false;
    }
    if (days == 0 || days > MAX_CERTIFICATE_DAYS) {
        error = "the certificate validity must be between 1 and " + std::to_string(MAX_CERTIFICATE_DAYS) + " days";
        return false;
    }
    if (caDays == 0 || caDays > MAX_CA_DAYS) {
        error = "the CA validity must be between 1 and " + std::to_string(MAX_CA_DAYS) + " days";
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) {
        error = "cannot create '" + PathText(directory) + "': " + ec.message();
        return false;
    }
    ERR_clear_error();

    const auto caCertPath = directory / "gview-ca.crt";
    const auto caKeyPath  = directory / "gview-ca.key";
    const bool hasCaCert  = std::filesystem::exists(caCertPath, ec);
    const bool hasCaKey   = std::filesystem::exists(caKeyPath, ec);
    if (hasCaCert != hasCaKey) {
        error = "only one of 'gview-ca.crt' / 'gview-ca.key' exists in '" + PathText(directory) + "'";
        return false;
    }

    X509Ptr caCert;
    KeyPtr caKey;
    bool caCreated = false;
    if (hasCaCert) {
        std::vector<X509Ptr> certs;
        if (!ReadCertificates(caCertPath, certs, error) || !ReadPrivateKey(caKeyPath, caKey, error))
            return false;
        caCert = std::move(certs[0]);
        if (X509_check_private_key(caCert.get(), caKey.get()) != 1) {
            error = "'gview-ca.key' does not match 'gview-ca.crt'";
            return false;
        }
        time_t until = time(nullptr) + static_cast<time_t>(days) * 86400;
        if (X509_cmp_time(X509_get0_notAfter(caCert.get()), &until) < 0) {
            error = "the existing CA expires before the new certificate (delete gview-ca.* to create a new CA, then re-issue every certificate)";
            return false;
        }
    } else {
        caKey = GenerateKey();
        if (!caKey) {
            error = "cannot generate the CA key: " + OpenSslErrors();
            return false;
        }
        caCert = CreateCertificate(caKey.get(), "GView Remote CA", nullptr, nullptr, caDays, "");
        if (!caCert) {
            error = "cannot create the CA certificate: " + OpenSslErrors();
            return false;
        }
        if (!WriteFileAtomically(caKeyPath, KeyToPem(caKey.get()), true, error) ||
            !WriteFileAtomically(caCertPath, CertificateToPem(caCert.get()), false, error))
            return false;
        caCreated = true;
    }

    auto key = GenerateKey();
    if (!key) {
        error = "cannot generate the key: " + OpenSslErrors();
        return false;
    }
    const std::string san = (Net::IsIpAddress(name) ? "IP:" : "DNS:") + name;
    auto cert             = CreateCertificate(key.get(), name, caCert.get(), caKey.get(), days, san);
    if (!cert) {
        error = "cannot create the certificate: " + OpenSslErrors();
        return false;
    }
    std::string fileName = name;
    for (auto& ch : fileName)
        if (ch == ':')
            ch = '_'; // IPv6 addresses
    const auto keyPath  = directory / (fileName + ".key");
    const auto certPath = directory / (fileName + ".crt");
    // key first: a server reloading in between sees a key/certificate mismatch and keeps its current identity
    if (!WriteFileAtomically(keyPath, KeyToPem(key.get()), true, error) || !WriteFileAtomically(certPath, CertificateToPem(cert.get()), false, error))
        return false;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLength = 0;
    std::string fingerprint;
    if (X509_digest(cert.get(), EVP_sha256(), md, &mdLength) == 1) {
        static const char hex[] = "0123456789ABCDEF";
        for (unsigned int i = 0; i < mdLength; i++) {
            if (i)
                fingerprint.push_back(':');
            fingerprint.push_back(hex[md[i] >> 4]);
            fingerprint.push_back(hex[md[i] & 0x0F]);
        }
    }
    report = "CA certificate : " + PathText(caCertPath) + (caCreated ? " (created)" : " (reused)") + "\n" + "CA private key : " + PathText(caKeyPath) + "\n" +
             "Certificate    : " + PathText(certPath) + "\n" + "Private key    : " + PathText(keyPath) + "\n" + "Subject        : CN=" + name + " (" + san +
             ")\n" + "Valid until    : " + TimeText(X509_get0_notAfter(cert.get())) + "\n" + "SHA-256        : " + fingerprint + "\n";
    return true;
}
} // namespace GView::Remote::Tls
