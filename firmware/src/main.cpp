// =============================================================================
// SCA Smart Key — ESP32-S3 firmware entry point.
//
// Architecture: four FreeRTOS tasks communicate with a central controller task
// through a single event queue (IPC). No busy-waiting / Arduino delay() appears
// in the control flow; timing is driven by monotonic millis() and task ticks.
//
//   [BLE task]  -- connect / response  -->\
//   [NFC task]  -- tag tap             ---> (event queue) --> [Controller task]
//   [UWB task]  -- ranging zone        --->/                      |
//                                                                  v
//                                          AuthEngine + AccessController + GPIO
//
// This file is excluded from host builds; the logic-bearing modules it wires
// together are unit-tested separately under tests/.
// =============================================================================

#if !defined(SCA_HOST_BUILD)

#include <cstring>

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include "access_controller.h"
#include "auth_engine.h"
#include "ble_manager.h"
#include "config.h"
#include "gpio_actuator.h"
#include "nfc_manager.h"
#include "uwb_manager.h"

namespace {

using namespace sca;

// ---- Shared objects -------------------------------------------------------
AuthEngine       g_auth;
AccessController g_ctrl;
GpioActuator     g_gpio;
BleManager       g_ble;
UwbManager       g_uwb;
NfcManager       g_nfc;

QueueHandle_t    g_events;

void apply(Action a);  // forward declaration (defined after the tasks)

// ---- IPC event payload ----------------------------------------------------
struct Evt {
    AccessEvent type;
    uint16_t    conn_handle;
    uint8_t     nonce[config::NONCE_LEN];
    uint8_t     hmac[config::HMAC_LEN];
    bool        has_crypto;
};

void post(AccessEvent type) {
    Evt e{};
    e.type = type;
    xQueueSend(g_events, &e, 0);
}

// ---- BLE callbacks --------------------------------------------------------
void on_ble_connection(uint16_t handle, bool connected) {
    Evt e{};
    e.type = connected ? AccessEvent::BLE_CONNECT : AccessEvent::BLE_DISCONNECT;
    e.conn_handle = handle;
    xQueueSend(g_events, &e, 0);

    if (connected) {
        // Push a fresh challenge immediately on connect.
        uint8_t nonce[config::NONCE_LEN];
        if (g_auth.new_challenge(handle, millis(), nonce)) {
            g_ble.notify_challenge(nonce);
        }
    }
}

void on_ble_response(uint16_t handle, const uint8_t* nonce, const uint8_t* hmac) {
    Evt e{};
    e.has_crypto = true;
    e.conn_handle = handle;
    std::memcpy(e.nonce, nonce, config::NONCE_LEN);
    std::memcpy(e.hmac, hmac, config::HMAC_LEN);
    const AuthResult r = g_auth.verify_response(handle, millis(), nonce, hmac);
    e.type = (r == AuthResult::OK) ? AccessEvent::AUTH_OK : AccessEvent::AUTH_FAIL;
    xQueueSend(g_events, &e, 0);
}

// ---- Tasks ----------------------------------------------------------------
void ble_task(void*) {
    g_ble.set_connection_callback(on_ble_connection);
    g_ble.set_response_callback(on_ble_response);
    g_ble.begin();
    for (;;) {
        g_ble.service(millis());
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void uwb_task(void*) {
    // On real hardware: poll the DW3000 driver. Here we emit a slowly
    // approaching distance so the demo progresses on the bench.
    float d = 200.0f;
    UwbZone prev = UwbZone::FAR;
    for (;;) {
        UwbSample s{d, millis(), /*tof_ns=*/1};
        g_uwb.push_measurement(s);
        const UwbZone z = g_uwb.zone();
        if (z != prev) {
            if (z == UwbZone::NEAR) post(AccessEvent::UWB_NEAR);
            else if (z == UwbZone::FAR) post(AccessEvent::UWB_FAR);
            prev = z;
        }
        if (d > 10.0f) d -= 5.0f;
        vTaskDelay(pdMS_TO_TICKS(config::UWB_RANGING_INTERVAL_MS));
    }
}

void nfc_task(void*) {
    // On real hardware: poll the PN532. Here we wait for the BLE link, then
    // present the first whitelisted UID once per connection.
    bool tapped = false;
    for (;;) {
        if (g_ble.connected() && !tapped) {
            const NfcTap t = g_nfc.on_tag(config::NFC_WHITELIST[0],
                                          config::NFC_WHITELIST_UID_LEN[0]);
            post(t.authorised ? AccessEvent::NFC_OK : AccessEvent::NFC_FAIL);
            tapped = true;
        }
        if (!g_ble.connected()) tapped = false;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

void controller_task(void*) {
    g_gpio.begin();
    g_ctrl.reset(millis());
    Evt e;
    for (;;) {
        // Drain events (block up to one tick) then service timers.
        if (xQueueReceive(g_events, &e, pdMS_TO_TICKS(20)) == pdTRUE) {
            g_ble.note_activity(millis());
            const Action a = g_ctrl.handle_event(e.type, millis());
            apply(a);
            g_ble.notify_status(g_ctrl.state());
        }
        const Action ta = g_ctrl.tick(millis());
        apply(ta);
        g_gpio.service(millis());
    }
}

void apply(Action a) {
    switch (a) {
        case Action::LED_AUTHENTICATING: g_gpio.set_led(LedColor::BLUE); break;
        case Action::LED_LOCKED:         g_gpio.set_led(LedColor::RED);  break;
        case Action::LED_UNLOCKED:       g_gpio.set_led(LedColor::GREEN);break;
        case Action::PULSE_UNLOCK:       g_gpio.begin_unlock_pulse(millis()); break;
        case Action::DRIVE_LOCK:         g_gpio.lock(); break;
        case Action::LOG_LOCKOUT:
            Serial.println("[SECURITY] lockout: 3 consecutive auth failures");
            g_gpio.set_led(LedColor::RED);
            break;
        case Action::NONE: break;
    }
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(200);  // allow USB-CDC to enumerate (one-time, outside control flow)
    Serial.println("SCA Smart Key booting...");

    g_events = xQueueCreate(sca::config::EVENT_QUEUE_LEN, sizeof(Evt));

    xTaskCreatePinnedToCore(controller_task, "ctrl",
                            sca::config::TASK_STACK_CTRL, nullptr, 5, nullptr, 1);
    xTaskCreatePinnedToCore(ble_task, "ble",
                            sca::config::TASK_STACK_BLE, nullptr, 4, nullptr, 0);
    xTaskCreatePinnedToCore(uwb_task, "uwb",
                            sca::config::TASK_STACK_UWB, nullptr, 3, nullptr, 1);
    xTaskCreatePinnedToCore(nfc_task, "nfc",
                            sca::config::TASK_STACK_NFC, nullptr, 3, nullptr, 1);
}

void loop() {
    // All work runs in FreeRTOS tasks; nothing to do here.
    vTaskDelay(pdMS_TO_TICKS(1000));
}

#endif  // !SCA_HOST_BUILD
