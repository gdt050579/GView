#pragma once

// TLS layer of the remote TUI (OpenSSL).
//
// Security policy (docs/source/remote_protocol.rst, "Security model"):
//   * TLS 1.3 only, AEAD suites TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256, X25519 key exchange
//   * mutual TLS: both ends present a certificate that chains to an explicitly configured (private) CA bundle;
//     the system trust store is never used
//   * the client verifies the server name (DNS SAN or IP SAN) against the host it connected to (or --server-name)
//   * ALPN is mandatory ("gview/1" by default, configurable); a peer that does not negotiate it is rejected
//   * no session tickets / resumption, no 0-RTT (replay), no compression, no renegotiation
//   * optional cap on the lifetime of the peer certificate (short-lived certificates)
//   * certificates / keys are re-read when the files change (rotation without restarting the server)
// Every failure is fatal for the connection (fail closed).

#include "RemoteNet.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

struct ssl_ctx_st;
struct ssl_st;

namespace GView::Remote::Tls
{
constexpr std::string_view DEFAULT_ALPN                     = "gview/1";
constexpr uint32 DEFAULT_MAX_PEER_CERTIFICATE_LIFETIME_DAYS = 30;
constexpr uint32 MAX_CERTIFICATE_FILE_SIZE                  = 1024 * 1024;
constexpr std::chrono::milliseconds DEFAULT_HANDSHAKE_TIMEOUT{ 10000 };

struct Settings {
    std::filesystem::path certificate; // PEM: certificate of this GView instance (+ optional intermediate certificates)
    std::filesystem::path privateKey;  // PEM: its (unencrypted) private key
    std::filesystem::path trustedCA;   // PEM: CA certificate(s) that must have issued the peer certificate
    std::string alpn{ DEFAULT_ALPN };
    uint32 maxPeerCertificateLifetimeDays{ DEFAULT_MAX_PEER_CERTIFICATE_LIFETIME_DAYS }; // 0 = no limit

    bool Validate(std::string& error) const;
};

enum class Role {
    Server, // TLS server (accepts the TCP connection)
    Client, // TLS client (initiates the TCP connection)
};

// One immutable OpenSSL context
class Context
{
    ssl_ctx_st* ctx{ nullptr };
    std::string alpnWire; // length prefixed ALPN protocol (used by the ALPN callback -> must outlive ctx)
    std::string alpn;
    Role role;

    Context(Role r) : role(r)
    {
    }

  public:
    ~Context();
    Context(const Context&)            = delete;
    Context& operator=(const Context&) = delete;

    static std::shared_ptr<Context> Create(const Settings& settings, Role role, std::string& error);
    ssl_ctx_st* Native() const
    {
        return ctx;
    }
    Role GetRole() const
    {
        return role;
    }
    const std::string& GetAlpn() const
    {
        return alpn;
    }
};

// Thread-safe holder of the current context; the files are re-read when they change (certificate rotation). If a
// reload fails, the previous (valid) context stays in use and the error is reported once.
class ContextProvider
{
    Settings settings;
    Role role{ Role::Server };
    std::shared_ptr<Context> current;
    std::filesystem::file_time_type stamps[3];
    std::chrono::steady_clock::time_point lastCheck;
    std::mutex lock;

    bool ReadStamps(std::filesystem::file_time_type (&out)[3]) const;

  public:
    bool Init(const Settings& s, Role r, std::string& error);
    // returns the context to use for a new connection; reloadError is set when the files changed but are invalid
    std::shared_ptr<Context> Get(std::string& reloadError);
};

struct PeerInfo {
    std::string subject;     // printable one-line subject of the peer certificate
    std::string fingerprint; // SHA-256 of the peer certificate (hex, ':' separated)
    std::string cipher;
};

class Stream
{
  public:
    enum class Io {
        Ok,
        WantRead,
        WantWrite,
        Closed, // orderly close (or end of stream)
        Failed,
    };

    ~Stream();
    Stream(const Stream&)            = delete;
    Stream& operator=(const Stream&) = delete;

    // expectedPeerName: Client role -> DNS name / IP address the server certificate must be issued for
    static std::unique_ptr<Stream> Create(std::shared_ptr<Context> context, Net::Socket&& socket, const std::string& expectedPeerName, std::string& error);

    // Non-blocking handshake. Returns false on failure, timeout or when stop becomes true (waker interrupts the wait).
    bool Handshake(std::chrono::steady_clock::time_point deadline, const std::atomic<bool>& stop, Net::Waker& waker, std::string& error);
    Io Read(uint8* buffer, size_t size, size_t& read);
    Io Write(const uint8* data, size_t size, size_t& written);
    void Shutdown(); // best effort close_notify (never blocks)

    Net::SocketHandle GetSocket() const
    {
        return socket.Get();
    }
    const PeerInfo& GetPeer() const
    {
        return peer;
    }
    const std::string& GetLastError() const
    {
        return lastError;
    }

  private:
    Stream() = default;
    Io Translate(int rc);

    std::shared_ptr<Context> context;
    Net::Socket socket;
    ssl_st* ssl{ nullptr };
    PeerInfo peer;
    std::string lastError;
    bool shutdownSent{ false };
};

// `GView remote-certs`: creates (once) a private CA in `directory` and issues a short-lived certificate for `name`
// (usable both as TLS client and TLS server). Existing CA files are reused, so running the command again rotates
// the certificate of `name`.
bool GenerateCertificates(const std::filesystem::path& directory, const std::string& name, uint32 days, uint32 caDays, std::string& report, std::string& error);
} // namespace GView::Remote::Tls
