#ifndef SCA_AUTH_ENGINE_H
#define SCA_AUTH_ENGINE_H

// =============================================================================
// Auth engine: HMAC-SHA256 challenge-response with anti-replay nonce pool.
//
//   1. new_challenge()  -> generates a 32-byte random nonce, binds it to a BLE
//                          connection handle, and records its issue time.
//   2. verify_response() -> recomputes HMAC(nonce, shared_secret) and compares
//                          in constant time. Enforces: nonce known, not expired
//                          (TTL), not already consumed (replay), and bound to
//                          the same connection handle (MITM).
//
// The nonce pool is a fixed-size ring suitable for storing in RTC slow memory
// across deep-sleep on the ESP32.
// =============================================================================

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace sca {

/// Result of a response verification.
enum class AuthResult : uint8_t {
    OK = 0,           ///< HMAC valid, nonce fresh and bound correctly.
    UNKNOWN_NONCE,    ///< Nonce was never issued (or evicted).
    EXPIRED,          ///< Nonce older than TTL.
    REPLAYED,         ///< Nonce already consumed.
    HANDLE_MISMATCH,  ///< Nonce bound to a different connection (MITM).
    BAD_HMAC,         ///< HMAC did not match.
};

/// A single issued challenge record.
struct NonceRecord {
    uint8_t  nonce[config::NONCE_LEN];
    uint32_t issued_ms;
    uint16_t conn_handle;
    bool     consumed;
    bool     valid;
};

/// Stateful HMAC challenge-response engine.
class AuthEngine {
public:
    AuthEngine();

    /// Generate a fresh nonce for a connection and copy it to @p out_nonce.
    ///
    /// @param conn_handle BLE connection handle to bind the nonce to.
    /// @param now_ms       Current monotonic time in milliseconds.
    /// @param out_nonce    Output buffer of at least config::NONCE_LEN bytes.
    /// @return true on success.
    bool new_challenge(uint16_t conn_handle, uint32_t now_ms, uint8_t* out_nonce);

    /// Verify a client's HMAC response against a previously issued nonce.
    ///
    /// @param conn_handle  Connection the response arrived on.
    /// @param now_ms        Current monotonic time in milliseconds.
    /// @param nonce         The nonce echoed by the client (NONCE_LEN bytes).
    /// @param response      The client's HMAC (HMAC_LEN bytes).
    /// @return An AuthResult describing the outcome.
    AuthResult verify_response(uint16_t conn_handle, uint32_t now_ms,
                               const uint8_t* nonce, const uint8_t* response);

    /// Compute the expected client response for a nonce (used by the simulator
    /// / client side and by tests). Writes HMAC_LEN bytes to @p out.
    static bool compute_response(const uint8_t* nonce, size_t nonce_len,
                                 uint8_t* out);

    /// Number of currently valid (non-evicted) nonce records.
    size_t active_nonces() const;

    /// Replace the RNG with a deterministic source (testing only).
    void set_test_rng(uint32_t seed);

private:
    NonceRecord pool_[config::NONCE_POOL_SIZE];
    size_t      next_slot_;
    uint32_t    rng_state_;
    bool        test_rng_;

    NonceRecord* find(const uint8_t* nonce);
    uint32_t     next_rand();
    void         fill_random(uint8_t* buf, size_t len);
};

} // namespace sca

#endif // SCA_AUTH_ENGINE_H
