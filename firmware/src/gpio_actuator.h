#ifndef SCA_GPIO_ACTUATOR_H
#define SCA_GPIO_ACTUATOR_H

// =============================================================================
// GPIO actuator — door-lock relay, optional PWM servo, and RGB status LED.
//
// The class compiles on both ESP32 (drives real GPIO/LEDC) and host builds
// (records the requested state for inspection by tests). The unlock pulse is
// non-blocking: begin_unlock_pulse() latches a deadline that service() clears,
// so no Arduino-style delay() ever runs inside the control flow.
// =============================================================================

#include <cstdint>

namespace sca {

/// Status LED colours.
enum class LedColor : uint8_t { OFF, RED, GREEN, BLUE };

/// Lock actuator + status LED driver.
class GpioActuator {
public:
    GpioActuator();

    /// Configure GPIO directions / LEDC channels (no-op on host).
    void begin();

    /// Begin a non-blocking unlock pulse (relay HIGH for UNLOCK_PULSE_MS).
    void begin_unlock_pulse(uint32_t now_ms);

    /// Drive the lock to the LOCKED position immediately.
    void lock();

    /// Set the RGB status LED colour.
    void set_led(LedColor color);

    /// Must be called periodically; ends the unlock pulse when due.
    void service(uint32_t now_ms);

    bool     relay_active() const { return relay_active_; }
    LedColor led() const { return led_; }
    int      servo_angle() const { return servo_angle_; }

private:
    bool     relay_active_;
    uint32_t pulse_until_ms_;
    LedColor led_;
    int      servo_angle_;

    void write_relay(bool active);
    void write_servo(int angle);
};

} // namespace sca

#endif // SCA_GPIO_ACTUATOR_H
