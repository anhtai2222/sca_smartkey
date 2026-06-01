#ifndef SCA_CONFIG_H
#define SCA_CONFIG_H

// =============================================================================
// Smart Car Access (SCA) Smart Key — central configuration.
//
// ALL constants, keys, thresholds and pin assignments live here so that no
// magic numbers leak into the rest of the firmware.
//
// SECURITY: the shared secret below is a Proof-of-Concept placeholder.
// =============================================================================

#warning "Replace SCA_SHARED_SECRET with a provisioned key / HSM before production"

#include <cstdint>
#include <cstddef>

namespace sca {
namespace config {

// ----------------------------------------------------------------------------
// Identity / BLE
// ----------------------------------------------------------------------------
constexpr char     DEVICE_NAME[]            = "SCA-SmartKey";

// Custom 128-bit BLE service + characteristic UUIDs (randomly generated).
constexpr char     SERVICE_UUID[]           = "6e9f0001-b5a3-4f6d-9c21-7d3e8a1b2c40";
constexpr char     CHAR_CHALLENGE_UUID[]    = "6e9f0002-b5a3-4f6d-9c21-7d3e8a1b2c40"; // notify
constexpr char     CHAR_RESPONSE_UUID[]     = "6e9f0003-b5a3-4f6d-9c21-7d3e8a1b2c40"; // write
constexpr char     CHAR_STATUS_UUID[]       = "6e9f0004-b5a3-4f6d-9c21-7d3e8a1b2c40"; // notify

constexpr uint16_t BLE_PREFERRED_MTU        = 247;
constexpr uint32_t BLE_INACTIVITY_TIMEOUT_MS = 30000; // disconnect after 30s idle

// ----------------------------------------------------------------------------
// Cryptography (HMAC-SHA256 challenge-response)
// ----------------------------------------------------------------------------
constexpr size_t   NONCE_LEN                = 32;  // 256-bit random challenge
constexpr size_t   HMAC_LEN                 = 32;  // SHA-256 output
constexpr uint32_t NONCE_TTL_MS             = 60000; // anti-replay TTL: 60s
constexpr size_t   NONCE_POOL_SIZE          = 16;    // used-nonce ring buffer

// PoC shared secret (32 bytes). PROVISION SECURELY IN PRODUCTION.
constexpr uint8_t  SHARED_SECRET[32] = {
    0x53, 0x43, 0x41, 0x2d, 0x73, 0x6d, 0x61, 0x72,
    0x74, 0x6b, 0x65, 0x79, 0x2d, 0x73, 0x68, 0x61,
    0x72, 0x65, 0x64, 0x2d, 0x73, 0x65, 0x63, 0x72,
    0x65, 0x74, 0x2d, 0x76, 0x31, 0x2e, 0x30, 0x21,
};
constexpr size_t   SHARED_SECRET_LEN        = sizeof(SHARED_SECRET);

// ----------------------------------------------------------------------------
// UWB proximity (cm)
// ----------------------------------------------------------------------------
constexpr float    UWB_NEAR_CM             = 30.0f;   // < NEAR  -> auto-unlock zone
constexpr float    UWB_MEDIUM_CM           = 150.0f;  // < MEDIUM -> arm zone
// >= UWB_MEDIUM_CM -> FAR (lock)

// Anti-relay: maximum allowed change in distance per ranging interval.
// A relayed signal teleports the apparent distance, violating this bound.
constexpr float    UWB_MAX_DELTA_CM_PER_S  = 500.0f;  // human cannot move faster
constexpr uint32_t UWB_MAX_TOF_NS          = 50;      // plausibility cap on time-of-flight
constexpr uint32_t UWB_RANGING_INTERVAL_MS = 100;

// ----------------------------------------------------------------------------
// NFC (PN532) — UID whitelist
// ----------------------------------------------------------------------------
constexpr size_t   NFC_MAX_UID_LEN         = 7;
constexpr size_t   NFC_WHITELIST_SIZE      = 2;
// Two authorised 4-byte UIDs (NXP MIFARE style).
constexpr uint8_t  NFC_WHITELIST[NFC_WHITELIST_SIZE][NFC_MAX_UID_LEN] = {
    { 0x04, 0xA2, 0x1C, 0x5B, 0x00, 0x00, 0x00 },
    { 0x04, 0xDE, 0xAD, 0xBE, 0x00, 0x00, 0x00 },
};
constexpr size_t   NFC_WHITELIST_UID_LEN[NFC_WHITELIST_SIZE] = { 4, 4 };

// ----------------------------------------------------------------------------
// Access state machine
// ----------------------------------------------------------------------------
constexpr uint32_t STATE_TIMEOUT_MS        = 10000; // per-transition timeout
constexpr uint32_t FAIL_PENALTY_MS         = 5000;  // delay after a failed auth
constexpr uint8_t  MAX_CONSECUTIVE_FAILS   = 3;     // -> lockout
constexpr uint32_t LOCKOUT_MS              = 60000; // 60s lockout

// ----------------------------------------------------------------------------
// GPIO actuator
// ----------------------------------------------------------------------------
constexpr int      PIN_RELAY               = 4;   // door-lock relay
constexpr int      PIN_SERVO               = 5;   // optional PWM servo
constexpr int      PIN_LED_R               = 16;
constexpr int      PIN_LED_G               = 17;
constexpr int      PIN_LED_B               = 18;
constexpr uint32_t UNLOCK_PULSE_MS         = 500; // relay HIGH duration

// Servo PWM (LEDC) parameters.
constexpr int      SERVO_LOCK_ANGLE        = 0;
constexpr int      SERVO_UNLOCK_ANGLE      = 90;

// ----------------------------------------------------------------------------
// FreeRTOS task tuning
// ----------------------------------------------------------------------------
constexpr uint32_t TASK_STACK_BLE          = 4096;
constexpr uint32_t TASK_STACK_UWB          = 3072;
constexpr uint32_t TASK_STACK_NFC          = 3072;
constexpr uint32_t TASK_STACK_CTRL         = 4096;
constexpr uint32_t EVENT_QUEUE_LEN         = 16;

} // namespace config
} // namespace sca

#endif // SCA_CONFIG_H
