// =============================================================================
// Access state machine implementation.
// =============================================================================

#include "access_controller.h"

#include "config.h"

namespace sca {

AccessController::AccessController()
    : state_(AccessState::IDLE),
      state_entered_ms_(0),
      penalty_until_ms_(0),
      lockout_until_ms_(0),
      fail_count_(0) {}

void AccessController::reset(uint32_t now_ms) {
    enter(AccessState::IDLE, now_ms);
}

void AccessController::enter(AccessState s, uint32_t now_ms) {
    state_ = s;
    state_entered_ms_ = now_ms;
}

Action AccessController::register_failure(uint32_t now_ms) {
    ++fail_count_;
    if (fail_count_ >= config::MAX_CONSECUTIVE_FAILS) {
        lockout_until_ms_ = now_ms + config::LOCKOUT_MS;
        enter(AccessState::LOCKOUT, now_ms);
        return Action::LOG_LOCKOUT;
    }
    penalty_until_ms_ = now_ms + config::FAIL_PENALTY_MS;
    enter(AccessState::IDLE, now_ms);
    return Action::LED_LOCKED;
}

Action AccessController::handle_event(AccessEvent ev, uint32_t now_ms) {
    // Hard lock requests and disconnects are honoured from any state.
    if (ev == AccessEvent::USER_LOCK || ev == AccessEvent::BLE_DISCONNECT) {
        if (state_ == AccessState::LOCKOUT) return Action::NONE;
        enter(AccessState::LOCKED, now_ms);
        return Action::DRIVE_LOCK;
    }

    // While locked out, ignore everything until the lockout timer expires.
    if (state_ == AccessState::LOCKOUT) {
        return Action::NONE;
    }

    // While serving a fail penalty, reject progress attempts.
    if (now_ms < penalty_until_ms_) {
        return Action::NONE;
    }

    switch (state_) {
        case AccessState::IDLE:
        case AccessState::LOCKED:
            if (ev == AccessEvent::BLE_CONNECT) {
                enter(AccessState::BLE_CONNECTED, now_ms);
                return Action::LED_AUTHENTICATING;
            }
            break;

        case AccessState::BLE_CONNECTED:
            if (ev == AccessEvent::NFC_OK) {
                enter(AccessState::NFC_VERIFIED, now_ms);
                return Action::LED_AUTHENTICATING;
            }
            if (ev == AccessEvent::NFC_FAIL) {
                return register_failure(now_ms);
            }
            break;

        case AccessState::NFC_VERIFIED:
            if (ev == AccessEvent::UWB_NEAR) {
                enter(AccessState::UWB_NEAR, now_ms);
                return Action::LED_AUTHENTICATING;
            }
            if (ev == AccessEvent::UWB_FAR) {
                enter(AccessState::IDLE, now_ms);
                return Action::LED_LOCKED;
            }
            break;

        case AccessState::UWB_NEAR:
            if (ev == AccessEvent::AUTH_OK) {
                enter(AccessState::AUTHENTICATED, now_ms);
                fail_count_ = 0;  // success clears the failure streak
                // Immediately progress to UNLOCKED.
                enter(AccessState::UNLOCKED, now_ms);
                return Action::PULSE_UNLOCK;
            }
            if (ev == AccessEvent::AUTH_FAIL) {
                return register_failure(now_ms);
            }
            if (ev == AccessEvent::UWB_FAR) {
                enter(AccessState::IDLE, now_ms);
                return Action::LED_LOCKED;
            }
            break;

        case AccessState::UNLOCKED:
            if (ev == AccessEvent::UWB_FAR) {
                enter(AccessState::LOCKED, now_ms);
                return Action::DRIVE_LOCK;
            }
            break;

        default:
            break;
    }
    return Action::NONE;
}

Action AccessController::tick(uint32_t now_ms) {
    // Lockout expiry.
    if (state_ == AccessState::LOCKOUT) {
        if (now_ms >= lockout_until_ms_) {
            fail_count_ = 0;
            enter(AccessState::IDLE, now_ms);
            return Action::LED_LOCKED;
        }
        return Action::NONE;
    }

    // Per-state inactivity timeout for the intermediate (authenticating) states.
    const bool transient =
        state_ == AccessState::BLE_CONNECTED ||
        state_ == AccessState::NFC_VERIFIED ||
        state_ == AccessState::UWB_NEAR ||
        state_ == AccessState::AUTHENTICATED;

    if (transient && (now_ms - state_entered_ms_ > config::STATE_TIMEOUT_MS)) {
        enter(AccessState::IDLE, now_ms);
        return Action::LED_LOCKED;
    }
    return Action::NONE;
}

const char* to_string(AccessState s) {
    switch (s) {
        case AccessState::IDLE:          return "IDLE";
        case AccessState::BLE_CONNECTED: return "BLE_CONNECTED";
        case AccessState::NFC_VERIFIED:  return "NFC_VERIFIED";
        case AccessState::UWB_NEAR:      return "UWB_NEAR";
        case AccessState::AUTHENTICATED: return "AUTHENTICATED";
        case AccessState::UNLOCKED:      return "UNLOCKED";
        case AccessState::LOCKED:        return "LOCKED";
        case AccessState::LOCKOUT:       return "LOCKOUT";
    }
    return "?";
}

const char* to_string(Action a) {
    switch (a) {
        case Action::NONE:              return "NONE";
        case Action::LED_AUTHENTICATING:return "LED_AUTHENTICATING";
        case Action::LED_LOCKED:        return "LED_LOCKED";
        case Action::LED_UNLOCKED:      return "LED_UNLOCKED";
        case Action::PULSE_UNLOCK:      return "PULSE_UNLOCK";
        case Action::DRIVE_LOCK:        return "DRIVE_LOCK";
        case Action::LOG_LOCKOUT:       return "LOG_LOCKOUT";
    }
    return "?";
}

} // namespace sca
