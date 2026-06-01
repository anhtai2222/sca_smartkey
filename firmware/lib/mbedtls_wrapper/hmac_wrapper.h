#ifndef SCA_HMAC_WRAPPER_H
#define SCA_HMAC_WRAPPER_H

// =============================================================================
// Thin wrapper over mbedTLS HMAC-SHA256.
//
// On the ESP32 target this delegates to mbedtls_md_hmac(). For host-side unit
// testing (when SCA_HOST_BUILD is defined and mbedTLS is unavailable) it falls
// back to a small, self-contained SHA-256/HMAC implementation so that the same
// auth logic can be verified on a desktop with only a C++17 compiler.
//
// Either way the public API is identical, and the two paths are bit-compatible
// (verified against the Python hmac module in tests/test_python_auth.py).
// =============================================================================

#include <cstddef>
#include <cstdint>

namespace sca {
namespace crypto {

/// SHA-256 digest length in bytes.
constexpr size_t kSha256Len = 32;

/// Compute HMAC-SHA256.
///
/// @param key      Pointer to the secret key bytes.
/// @param key_len  Length of the key in bytes.
/// @param msg      Pointer to the message bytes.
/// @param msg_len  Length of the message in bytes.
/// @param out      Output buffer, must be at least kSha256Len bytes.
/// @return true on success, false on invalid arguments.
bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t* out);

/// Constant-time comparison of two equal-length byte buffers.
///
/// Avoids timing side-channels when verifying a MAC.
///
/// @param a    First buffer.
/// @param b    Second buffer.
/// @param len  Number of bytes to compare.
/// @return true if all bytes are equal.
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace crypto
} // namespace sca

#endif // SCA_HMAC_WRAPPER_H
