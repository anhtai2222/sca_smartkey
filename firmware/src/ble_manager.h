#ifndef SCA_BLE_MANAGER_H
#define SCA_BLE_MANAGER_H

// =============================================================================
// BLE manager — GATT server (NimBLE on ESP32).
//
// Service "SCA-SmartKey" exposes three characteristics:
//   * CHALLENGE (notify) — server pushes a 32-byte nonce.
//   * RESPONSE  (write)  — client writes nonce(32) || hmac(32).
//   * STATUS    (notify) — server pushes the current AccessState byte.
//
// Handles advertising, connection/MTU events and a 30s inactivity timeout.
// The class is only compiled into the firmware target; on host builds it is
// excluded (the Python simulator plays the BLE role instead).
// =============================================================================

#include <cstdint>

namespace sca {

class AuthEngine;
enum class AccessState : uint8_t;

/// Callback invoked when a complete RESPONSE (nonce||hmac) is received.
/// Signature: (conn_handle, nonce_ptr, hmac_ptr).
using ResponseCallback = void (*)(uint16_t, const uint8_t*, const uint8_t*);

/// Callback invoked on connect/disconnect (conn_handle, connected).
using ConnectionCallback = void (*)(uint16_t, bool);

/// BLE GATT server wrapper.
class BleManager {
public:
    BleManager();

    /// Initialise NimBLE, register the GATT service and start advertising.
    void begin();

    /// Push a fresh challenge nonce to the connected client.
    void notify_challenge(const uint8_t* nonce);

    /// Push the current access state to the client.
    void notify_status(AccessState state);

    /// Register the response / connection callbacks.
    void set_response_callback(ResponseCallback cb) { on_response_ = cb; }
    void set_connection_callback(ConnectionCallback cb) { on_connection_ = cb; }

    /// Periodic service: enforces the inactivity timeout.
    void service(uint32_t now_ms);

    /// Mark activity (resets the inactivity timer).
    void note_activity(uint32_t now_ms) { last_activity_ms_ = now_ms; }

    bool     connected() const { return conn_handle_ != kInvalidHandle; }
    uint16_t conn_handle() const { return conn_handle_; }

    static constexpr uint16_t kInvalidHandle = 0xFFFF;

    // Internal hooks invoked by the NimBLE C-style callbacks. Public so the
    // free-function callbacks in the .cpp can reach them; not part of the
    // intended user-facing API.
    void _on_connect(uint16_t handle);
    void _on_disconnect();
    void _on_response(const uint8_t* nonce, const uint8_t* hmac);

private:
    ResponseCallback   on_response_;
    ConnectionCallback on_connection_;
    uint16_t           conn_handle_;
    uint32_t           last_activity_ms_;
};

} // namespace sca

#endif // SCA_BLE_MANAGER_H
