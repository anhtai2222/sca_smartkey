#ifndef SCA_NFC_MANAGER_H
#define SCA_NFC_MANAGER_H

// =============================================================================
// NFC manager — PN532 (SPI/I2C) abstraction.
//
// On hardware this wraps the Adafruit/PN532 driver to poll for ISO 14443-A
// tags and read their UID / NDEF record. In the host build, taps are injected
// via on_tag(). UID verification against the config whitelist happens here.
// =============================================================================

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace sca {

/// Result of an NFC tap.
struct NfcTap {
    uint8_t uid[config::NFC_MAX_UID_LEN];
    size_t  uid_len;
    bool    authorised;
};

/// Handles PN532 polling and UID whitelist checks.
class NfcManager {
public:
    NfcManager();

    /// Check a UID against the configured whitelist.
    ///
    /// @param uid      Pointer to UID bytes.
    /// @param uid_len  Length of the UID.
    /// @return true if the UID is authorised.
    static bool is_authorised(const uint8_t* uid, size_t uid_len);

    /// Process a presented tag (driver task or simulator calls this).
    ///
    /// @param uid      UID bytes read from the tag.
    /// @param uid_len  Length of the UID.
    /// @return Populated NfcTap with the authorisation verdict.
    NfcTap on_tag(const uint8_t* uid, size_t uid_len);

    const NfcTap& last_tap() const { return last_; }

private:
    NfcTap last_;
};

} // namespace sca

#endif // SCA_NFC_MANAGER_H
