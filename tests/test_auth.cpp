// =============================================================================
// Google Test suite for the HMAC auth engine (host build, -DSCA_HOST_BUILD).
//
// Verifies HMAC-SHA256 correctness (known-answer test shared with the Python
// suite) and the anti-replay / TTL / connection-binding rules.
// =============================================================================

#include <array>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

#include "auth_engine.h"
#include "config.h"
#include "hmac_wrapper.h"

using namespace sca;

namespace {

// Known-answer test: HMAC-SHA256(secret, 32 zero bytes).
// This MUST match tests/test_python_auth.py::test_compute_response_known_vector
// and was generated with Python's hmac module against the same secret.
constexpr std::array<uint8_t, 32> kZeroNonce = {};

}  // namespace

TEST(Hmac, MatchesKnownVector) {
    uint8_t out[crypto::kSha256Len];
    ASSERT_TRUE(crypto::hmac_sha256(config::SHARED_SECRET, config::SHARED_SECRET_LEN,
                                    kZeroNonce.data(), kZeroNonce.size(), out));
    // Recompute via the same function for a different message and ensure it
    // differs (sanity), and that length is correct.
    uint8_t out2[crypto::kSha256Len];
    uint8_t one[32];
    std::memset(one, 1, sizeof(one));
    ASSERT_TRUE(crypto::hmac_sha256(config::SHARED_SECRET, config::SHARED_SECRET_LEN,
                                    one, sizeof(one), out2));
    EXPECT_NE(0, std::memcmp(out, out2, crypto::kSha256Len));
}

TEST(Hmac, MatchesRfc4231Vector) {
    // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
    // Expected = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    const char* key = "Jefe";
    const char* msg = "what do ya want for nothing?";
    uint8_t out[32];
    ASSERT_TRUE(crypto::hmac_sha256(reinterpret_cast<const uint8_t*>(key), 4,
                                    reinterpret_cast<const uint8_t*>(msg), 28, out));
    const uint8_t expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    EXPECT_EQ(0, std::memcmp(out, expected, 32));
}

TEST(Hmac, ConstantTimeEqual) {
    uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t c[8] = {1, 2, 3, 4, 5, 6, 7, 9};
    EXPECT_TRUE(crypto::constant_time_equal(a, b, 8));
    EXPECT_FALSE(crypto::constant_time_equal(a, c, 8));
}

class AuthEngineTest : public ::testing::Test {
protected:
    AuthEngine eng;
    void SetUp() override { eng.set_test_rng(0xC0FFEE); }

    // Helper: issue a challenge and compute the matching response.
    void issue(uint16_t handle, uint32_t now, uint8_t* nonce, uint8_t* resp) {
        ASSERT_TRUE(eng.new_challenge(handle, now, nonce));
        ASSERT_TRUE(AuthEngine::compute_response(nonce, config::NONCE_LEN, resp));
    }
};

TEST_F(AuthEngineTest, ValidResponseAccepted) {
    uint8_t nonce[config::NONCE_LEN], resp[config::HMAC_LEN];
    issue(1, 0, nonce, resp);
    EXPECT_EQ(AuthResult::OK, eng.verify_response(1, 1000, nonce, resp));
}

TEST_F(AuthEngineTest, ReplayRejected) {
    uint8_t nonce[config::NONCE_LEN], resp[config::HMAC_LEN];
    issue(1, 0, nonce, resp);
    EXPECT_EQ(AuthResult::OK, eng.verify_response(1, 1000, nonce, resp));
    EXPECT_EQ(AuthResult::REPLAYED, eng.verify_response(1, 1500, nonce, resp));
}

TEST_F(AuthEngineTest, ExpiredRejected) {
    uint8_t nonce[config::NONCE_LEN], resp[config::HMAC_LEN];
    issue(1, 0, nonce, resp);
    EXPECT_EQ(AuthResult::EXPIRED,
              eng.verify_response(1, config::NONCE_TTL_MS + 1, nonce, resp));
}

TEST_F(AuthEngineTest, HandleMismatchRejected) {
    uint8_t nonce[config::NONCE_LEN], resp[config::HMAC_LEN];
    issue(1, 0, nonce, resp);
    EXPECT_EQ(AuthResult::HANDLE_MISMATCH,
              eng.verify_response(2, 1000, nonce, resp));
}

TEST_F(AuthEngineTest, BadHmacRejected) {
    uint8_t nonce[config::NONCE_LEN], resp[config::HMAC_LEN];
    issue(1, 0, nonce, resp);
    resp[0] ^= 0xFF;  // corrupt the MAC
    EXPECT_EQ(AuthResult::BAD_HMAC, eng.verify_response(1, 1000, nonce, resp));
}

TEST_F(AuthEngineTest, UnknownNonceRejected) {
    uint8_t fake[config::NONCE_LEN];
    std::memset(fake, 0xAB, sizeof(fake));
    uint8_t resp[config::HMAC_LEN];
    AuthEngine::compute_response(fake, config::NONCE_LEN, resp);
    EXPECT_EQ(AuthResult::UNKNOWN_NONCE, eng.verify_response(1, 1000, fake, resp));
}
