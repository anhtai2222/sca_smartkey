// =============================================================================
// UWB proximity manager implementation.
// =============================================================================

#include "uwb_manager.h"

#include <cmath>

#include "config.h"

namespace sca {

namespace {
// Speed of light in cm/ns (~29.979 cm per nanosecond).
constexpr float kSpeedOfLightCmPerNs = 29.9792458f;
}  // namespace

UwbManager::UwbManager()
    : last_{0.0f, 0, 0},
      zone_(UwbZone::FAR),
      has_fix_(false),
      relay_suspected_(false) {}

UwbZone UwbManager::classify(float distance_cm) {
    if (distance_cm < config::UWB_NEAR_CM) return UwbZone::NEAR;
    if (distance_cm < config::UWB_MEDIUM_CM) return UwbZone::MEDIUM;
    return UwbZone::FAR;
}

float UwbManager::twr_distance_cm(uint32_t t_round_ns, uint32_t t_reply_ns) {
    // Time of flight is half the (round - reply) interval.
    if (t_round_ns <= t_reply_ns) return 0.0f;
    const float tof_ns = static_cast<float>(t_round_ns - t_reply_ns) / 2.0f;
    return tof_ns * kSpeedOfLightCmPerNs;
}

bool UwbManager::push_measurement(const UwbSample& sample) {
    // Plausibility 1: physical time-of-flight bound. A relay adds latency,
    // inflating apparent ToF beyond what the configured range allows.
    if (sample.tof_ns > config::UWB_MAX_TOF_NS) {
        relay_suspected_ = true;  // latched for the session
        zone_ = UwbZone::FAR;     // fail safe: treat as far/locked
        return false;
    }

    // Plausibility 2: distance-rate bound vs. the last *trusted* sample. A
    // relay teleports the apparent distance faster than a person can move.
    if (has_fix_) {
        const float dt_s =
            static_cast<float>(sample.timestamp_ms - last_.timestamp_ms) / 1000.0f;
        if (dt_s > 0.0f) {
            const float rate = std::fabs(sample.distance_cm - last_.distance_cm) / dt_s;
            if (rate > config::UWB_MAX_DELTA_CM_PER_S) {
                relay_suspected_ = true;  // latched
                zone_ = UwbZone::FAR;
                return false;
            }
        }
    }

    // Accepted: advance the trusted baseline. Suspicion, once latched, is not
    // cleared by a later self-consistent sample.
    last_ = sample;
    has_fix_ = true;
    zone_ = relay_suspected_ ? UwbZone::FAR : classify(sample.distance_cm);
    return !relay_suspected_;
}

void UwbManager::reset_session() {
    has_fix_ = false;
    zone_ = UwbZone::FAR;
    relay_suspected_ = false;
}

const char* to_string(UwbZone z) {
    switch (z) {
        case UwbZone::NEAR:   return "NEAR";
        case UwbZone::MEDIUM: return "MEDIUM";
        case UwbZone::FAR:    return "FAR";
    }
    return "?";
}

} // namespace sca
