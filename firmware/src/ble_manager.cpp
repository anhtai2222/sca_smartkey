// =============================================================================
// BLE manager implementation (NimBLE on ESP32).
//
// This file only contains active code on the ESP32 target. On host builds it
// compiles to an empty translation unit because the Python simulator provides
// the BLE peer; the firmware-side BLE stack cannot run off-target.
// =============================================================================

#include "ble_manager.h"

#if !defined(SCA_HOST_BUILD)

#include <cstring>

#include <NimBLEDevice.h>

#include "access_controller.h"
#include "config.h"

namespace sca {

namespace {

BleManager*               g_self = nullptr;
NimBLECharacteristic*     g_challenge = nullptr;
NimBLECharacteristic*     g_response = nullptr;
NimBLECharacteristic*     g_status = nullptr;

// Connection / MTU server callbacks.
class ServerCallbacks : public NimBLEServerCallbacks {
public:
    void onConnect(NimBLEServer* server, ble_gap_conn_desc* desc) override {
        if (g_self) g_self->_on_connect(desc->conn_handle);
    }
    void onDisconnect(NimBLEServer* server) override {
        if (g_self) g_self->_on_disconnect();
        NimBLEDevice::startAdvertising();  // re-advertise after disconnect
    }
    void onMTUChange(uint16_t mtu, ble_gap_conn_desc* /*desc*/) override {
        // MTU negotiated; larger MTU lets the 64-byte response fit one packet.
        (void)mtu;
    }
};

// RESPONSE characteristic write callback: expects nonce(32) || hmac(32).
class ResponseCallbacks : public NimBLECharacteristicCallbacks {
public:
    void onWrite(NimBLECharacteristic* chr) override {
        if (!g_self) return;
        const std::string& v = chr->getValue();
        if (v.size() != config::NONCE_LEN + config::HMAC_LEN) return;
        const auto* data = reinterpret_cast<const uint8_t*>(v.data());
        g_self->_on_response(data, data + config::NONCE_LEN);
    }
};

ServerCallbacks   g_server_cbs;
ResponseCallbacks g_response_cbs;

}  // namespace

BleManager::BleManager()
    : on_response_(nullptr),
      on_connection_(nullptr),
      conn_handle_(kInvalidHandle),
      last_activity_ms_(0) {}

void BleManager::begin() {
    g_self = this;

    NimBLEDevice::init(config::DEVICE_NAME);
    NimBLEDevice::setMTU(config::BLE_PREFERRED_MTU);
    NimBLEDevice::setSecurityAuth(/*bonding=*/true, /*mitm=*/true, /*sc=*/true);

    NimBLEServer* server = NimBLEDevice::createServer();
    server->setCallbacks(&g_server_cbs);

    NimBLEService* service = server->createService(config::SERVICE_UUID);

    g_challenge = service->createCharacteristic(
        config::CHAR_CHALLENGE_UUID, NIMBLE_PROPERTY::NOTIFY);
    g_response = service->createCharacteristic(
        config::CHAR_RESPONSE_UUID,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC);
    g_response->setCallbacks(&g_response_cbs);
    g_status = service->createCharacteristic(
        config::CHAR_STATUS_UUID, NIMBLE_PROPERTY::NOTIFY);

    service->start();

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(config::SERVICE_UUID);
    adv->setName(config::DEVICE_NAME);
    adv->setScanResponse(true);
    NimBLEDevice::startAdvertising();
}

void BleManager::notify_challenge(const uint8_t* nonce) {
    if (g_challenge && connected()) {
        g_challenge->setValue(nonce, config::NONCE_LEN);
        g_challenge->notify();
    }
}

void BleManager::notify_status(AccessState state) {
    if (g_status && connected()) {
        uint8_t s = static_cast<uint8_t>(state);
        g_status->setValue(&s, 1);
        g_status->notify();
    }
}

void BleManager::service(uint32_t now_ms) {
    if (connected() &&
        (now_ms - last_activity_ms_ > config::BLE_INACTIVITY_TIMEOUT_MS)) {
        NimBLEDevice::getServer()->disconnect(conn_handle_);
    }
}

// Internal hooks called from the NimBLE callbacks above.
void BleManager::_on_connect(uint16_t handle) {
    conn_handle_ = handle;
    last_activity_ms_ = millis();
    if (on_connection_) on_connection_(handle, true);
}
void BleManager::_on_disconnect() {
    uint16_t h = conn_handle_;
    conn_handle_ = kInvalidHandle;
    if (on_connection_) on_connection_(h, false);
}
void BleManager::_on_response(const uint8_t* nonce, const uint8_t* hmac) {
    last_activity_ms_ = millis();
    if (on_response_) on_response_(conn_handle_, nonce, hmac);
}

} // namespace sca

#endif // !SCA_HOST_BUILD
