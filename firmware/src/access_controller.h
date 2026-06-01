#ifndef SCA_ACCESS_CONTROLLER_H
#define SCA_ACCESS_CONTROLLER_H

// =============================================================================
// Access state machine.
//
//   IDLE -> BLE_CONNECTED -> NFC_VERIFIED -> UWB_NEAR -> AUTHENTICATED
//        -> UNLOCKED -> LOCKED -> IDLE
//
//   * Every state carries a timeout; expiry drops back to IDLE.
//   * A failed auth applies a FAIL_PENALTY and returns to IDLE.
//   * MAX_CONSECUTIVE_FAILS failures trigger a LOCKOUT and log an event.
//
// The controller is hardware-agnostic and fully unit-testable: events are fed
// in via handle_event() and time via tick(); it emits Action enums that the
// firmware maps to GPIO/LED operations.
// =============================================================================

#include <cstdint>

namespace sca {

/// States of the access flow.
enum class AccessState : uint8_t {
    IDLE = 0,
    BLE_CONNECTED,
    NFC_VERIFIED,
    UWB_NEAR,
    AUTHENTICATED,
    UNLOCKED,
    LOCKED,
    LOCKOUT,
};

/// Events driving the state machine.
enum class AccessEvent : uint8_t {
    BLE_CONNECT,
    BLE_DISCONNECT,
    NFC_OK,
    NFC_FAIL,
    UWB_NEAR,
    UWB_FAR,
    AUTH_OK,
    AUTH_FAIL,
    USER_LOCK,
};

/// Side-effect actions emitted to the actuator layer.
enum class Action : uint8_t {
    NONE,
    LED_AUTHENTICATING,  ///< blue
    LED_LOCKED,          ///< red
    LED_UNLOCKED,        ///< green
    PULSE_UNLOCK,        ///< drive relay/servo to unlock
    DRIVE_LOCK,          ///< drive relay/servo to lock
    LOG_LOCKOUT,         ///< persist a lockout security event
};

/// Hardware-agnostic access state machine.
class AccessController {
public:
    AccessController();

    /// Feed an event into the machine.
    ///
    /// @param ev      The event.
    /// @param now_ms  Current monotonic time in milliseconds.
    /// @return The action the firmware should perform.
    Action handle_event(AccessEvent ev, uint32_t now_ms);

    /// Advance time; handles state and penalty/lockout timeouts.
    ///
    /// @param now_ms  Current monotonic time in milliseconds.
    /// @return The action triggered by any timeout (often NONE).
    Action tick(uint32_t now_ms);

    AccessState state() const { return state_; }
    uint8_t     fail_count() const { return fail_count_; }
    bool        is_locked_out() const { return state_ == AccessState::LOCKOUT; }

    /// Reset to IDLE (e.g. on boot). Does not clear fail history.
    void reset(uint32_t now_ms);

private:
    AccessState state_;
    uint32_t    state_entered_ms_;
    uint32_t    penalty_until_ms_;
    uint32_t    lockout_until_ms_;
    uint8_t     fail_count_;

    void        enter(AccessState s, uint32_t now_ms);
    Action      register_failure(uint32_t now_ms);
};

/// Human-readable name for a state (for logging/tests).
const char* to_string(AccessState s);
/// Human-readable name for an action (for logging/tests).
const char* to_string(Action a);

} // namespace sca

#endif // SCA_ACCESS_CONTROLLER_H
