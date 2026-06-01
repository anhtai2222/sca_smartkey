// =============================================================================
// GPIO actuator implementation.
// =============================================================================

#include "gpio_actuator.h"

#include "config.h"

#if !defined(SCA_HOST_BUILD)
#  include "Arduino.h"
#endif

namespace sca {

GpioActuator::GpioActuator()
    : relay_active_(false),
      pulse_until_ms_(0),
      led_(LedColor::OFF),
      servo_angle_(config::SERVO_LOCK_ANGLE) {}

void GpioActuator::begin() {
#if !defined(SCA_HOST_BUILD)
    pinMode(config::PIN_RELAY, OUTPUT);
    pinMode(config::PIN_LED_R, OUTPUT);
    pinMode(config::PIN_LED_G, OUTPUT);
    pinMode(config::PIN_LED_B, OUTPUT);
    // LEDC channel for the servo (50 Hz, 16-bit).
    ledcSetup(/*channel=*/0, /*freq=*/50, /*resolution=*/16);
    ledcAttachPin(config::PIN_SERVO, 0);
#endif
    write_relay(false);
    write_servo(config::SERVO_LOCK_ANGLE);
    set_led(LedColor::RED);
}

void GpioActuator::write_relay(bool active) {
    relay_active_ = active;
#if !defined(SCA_HOST_BUILD)
    digitalWrite(config::PIN_RELAY, active ? HIGH : LOW);
#endif
}

void GpioActuator::write_servo(int angle) {
    servo_angle_ = angle;
#if !defined(SCA_HOST_BUILD)
    // Map 0..180deg to a ~1..2ms pulse over a 20ms (50Hz) period, 16-bit duty.
    const float min_duty = 0.025f;  // 0.5ms
    const float max_duty = 0.125f;  // 2.5ms
    const float frac = static_cast<float>(angle) / 180.0f;
    const uint32_t duty =
        static_cast<uint32_t>((min_duty + frac * (max_duty - min_duty)) * 65535.0f);
    ledcWrite(0, duty);
#endif
}

void GpioActuator::begin_unlock_pulse(uint32_t now_ms) {
    write_relay(true);
    write_servo(config::SERVO_UNLOCK_ANGLE);
    pulse_until_ms_ = now_ms + config::UNLOCK_PULSE_MS;
    set_led(LedColor::GREEN);
}

void GpioActuator::lock() {
    write_relay(false);
    write_servo(config::SERVO_LOCK_ANGLE);
    pulse_until_ms_ = 0;
    set_led(LedColor::RED);
}

void GpioActuator::set_led(LedColor color) {
    led_ = color;
#if !defined(SCA_HOST_BUILD)
    digitalWrite(config::PIN_LED_R, color == LedColor::RED ? HIGH : LOW);
    digitalWrite(config::PIN_LED_G, color == LedColor::GREEN ? HIGH : LOW);
    digitalWrite(config::PIN_LED_B, color == LedColor::BLUE ? HIGH : LOW);
#endif
}

void GpioActuator::service(uint32_t now_ms) {
    // End the non-blocking unlock pulse when due. The servo stays in the
    // unlocked position (door open) until an explicit lock() is requested.
    if (relay_active_ && pulse_until_ms_ != 0 && now_ms >= pulse_until_ms_) {
        write_relay(false);
        pulse_until_ms_ = 0;
    }
}

} // namespace sca
