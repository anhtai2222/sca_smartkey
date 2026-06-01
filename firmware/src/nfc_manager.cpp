// =============================================================================
// NFC manager implementation.
// =============================================================================

#include "nfc_manager.h"

#include <cstring>

namespace sca {

NfcManager::NfcManager() {
    std::memset(&last_, 0, sizeof(last_));
}

bool NfcManager::is_authorised(const uint8_t* uid, size_t uid_len) {
    if (uid == nullptr || uid_len == 0 || uid_len > config::NFC_MAX_UID_LEN) {
        return false;
    }
    for (size_t i = 0; i < config::NFC_WHITELIST_SIZE; ++i) {
        if (config::NFC_WHITELIST_UID_LEN[i] != uid_len) continue;
        if (std::memcmp(config::NFC_WHITELIST[i], uid, uid_len) == 0) {
            return true;
        }
    }
    return false;
}

NfcTap NfcManager::on_tag(const uint8_t* uid, size_t uid_len) {
    NfcTap tap;
    std::memset(&tap, 0, sizeof(tap));
    if (uid != nullptr && uid_len <= config::NFC_MAX_UID_LEN) {
        std::memcpy(tap.uid, uid, uid_len);
        tap.uid_len = uid_len;
    }
    tap.authorised = is_authorised(uid, uid_len);
    last_ = tap;
    return tap;
}

} // namespace sca
