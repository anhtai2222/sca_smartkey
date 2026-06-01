#ifndef SCA_UWB_MANAGER_H
#define SCA_UWB_MANAGER_H

// =============================================================================
// UWB proximity manager — DW3000 abstraction + simulation layer.
//
// Provides a hardware-independent ranging interface. On real hardware the
// driver hooks call into the Qorvo/Decawave DW3000 API; in the host/simulation
// build distances are injected via push_measurement(). Proximity zones and an
// anti-relay consistency check are computed here.
// =============================================================================

#include <cstdint>

namespace sca {

/// Proximity zones derived from the measured distance.
enum class UwbZone : uint8_t {
    NEAR,    ///< < UWB_NEAR_CM   -> auto-unlock
    MEDIUM,  ///< arm zone
    FAR,     ///< >= UWB_MEDIUM_CM -> lock
};

/// One ranging sample.
struct UwbSample {
    float    distance_cm;
    uint32_t timestamp_ms;
    uint32_t tof_ns;  ///< measured time-of-flight (plausibility check)
};

/// Manages UWB ranging, zone classification and relay detection.
class UwbManager {
public:
    UwbManager();

    /// Classify a distance into a proximity zone.
    static UwbZone classify(float distance_cm);

    /// Feed a new ranging sample (called by the driver task or the simulator).
    ///
    /// @return false if the sample is rejected as a suspected relay attack.
    bool push_measurement(const UwbSample& sample);

    /// Two-Way-Ranging distance from round/reply times (nanoseconds).
    ///
    /// d = c * (T_round - T_reply) / 2, returned in centimetres.
    static float twr_distance_cm(uint32_t t_round_ns, uint32_t t_reply_ns);

    /// Clear ranging state for a new, independent session.
    void reset_session();

    UwbZone  zone() const { return zone_; }
    float    last_distance_cm() const { return last_.distance_cm; }
    bool     relay_suspected() const { return relay_suspected_; }
    bool     has_fix() const { return has_fix_; }

private:
    UwbSample last_;
    UwbZone   zone_;
    bool      has_fix_;
    bool      relay_suspected_;
};

const char* to_string(UwbZone z);

} // namespace sca

#endif // SCA_UWB_MANAGER_H
