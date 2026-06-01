// =============================================================================
// Auth engine implementation.
// =============================================================================

#include "auth_engine.h"

#include <cstring>

#include "hmac_wrapper.h"

// On the ESP32 target use the hardware RNG; on host builds use a seeded PRNG.
#if !defined(SCA_HOST_BUILD)
#  include "esp_random.h"
#endif

namespace sca {

AuthEngine::AuthEngine()
    : next_slot_(0), rng_state_(0x12345678u), test_rng_(false) {
    for (auto& rec : pool_) {
        rec.valid = false;
        rec.consumed = false;
    }
}

void AuthEngine::set_test_rng(uint32_t seed) {
    test_rng_ = true;
    rng_state_ = seed ? seed : 1u;
}

uint32_t AuthEngine::next_rand() {
    // xorshift32 — only used when test_rng_ or on host builds.
    uint32_t x = rng_state_;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state_ = x;
    return x;
}

void AuthEngine::fill_random(uint8_t* buf, size_t len) {
#if !defined(SCA_HOST_BUILD)
    if (!test_rng_) {
        esp_fill_random(buf, len);  // CSPRNG on ESP32
        return;
    }
#endif
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>(next_rand() & 0xFF);
    }
}

bool AuthEngine::new_challenge(uint16_t conn_handle, uint32_t now_ms,
                               uint8_t* out_nonce) {
    if (out_nonce == nullptr) return false;

    NonceRecord& rec = pool_[next_slot_];
    next_slot_ = (next_slot_ + 1) % config::NONCE_POOL_SIZE;

    fill_random(rec.nonce, config::NONCE_LEN);
    rec.issued_ms = now_ms;
    rec.conn_handle = conn_handle;
    rec.consumed = false;
    rec.valid = true;

    std::memcpy(out_nonce, rec.nonce, config::NONCE_LEN);
    return true;
}

NonceRecord* AuthEngine::find(const uint8_t* nonce) {
    for (auto& rec : pool_) {
        if (rec.valid &&
            crypto::constant_time_equal(rec.nonce, nonce, config::NONCE_LEN)) {
            return &rec;
        }
    }
    return nullptr;
}

AuthResult AuthEngine::verify_response(uint16_t conn_handle, uint32_t now_ms,
                                       const uint8_t* nonce,
                                       const uint8_t* response) {
    if (nonce == nullptr || response == nullptr) return AuthResult::UNKNOWN_NONCE;

    NonceRecord* rec = find(nonce);
    if (rec == nullptr) return AuthResult::UNKNOWN_NONCE;

    // Anti-replay: single use. A consumed nonce stays in the pool (findable)
    // until its ring slot is overwritten, so a replay is reported as REPLAYED
    // rather than masquerading as an unknown nonce.
    if (rec->consumed) {
        return AuthResult::REPLAYED;
    }
    // Anti-replay: TTL.
    if (now_ms - rec->issued_ms > config::NONCE_TTL_MS) {
        return AuthResult::EXPIRED;
    }
    // MITM: nonce bound to the connection it was issued on.
    if (rec->conn_handle != conn_handle) {
        return AuthResult::HANDLE_MISMATCH;
    }

    uint8_t expected[config::HMAC_LEN];
    if (!compute_response(nonce, config::NONCE_LEN, expected)) {
        return AuthResult::BAD_HMAC;
    }
    if (!crypto::constant_time_equal(expected, response, config::HMAC_LEN)) {
        return AuthResult::BAD_HMAC;
    }

    // Success: mark consumed (but keep the record so a replay is detectable).
    rec->consumed = true;
    return AuthResult::OK;
}

bool AuthEngine::compute_response(const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* out) {
    return crypto::hmac_sha256(config::SHARED_SECRET, config::SHARED_SECRET_LEN,
                               nonce, nonce_len, out);
}

size_t AuthEngine::active_nonces() const {
    size_t n = 0;
    for (const auto& rec : pool_) {
        if (rec.valid && !rec.consumed) ++n;
    }
    return n;
}

} // namespace sca
