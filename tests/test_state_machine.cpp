// =============================================================================
// Google Test suite for the access state machine and UWB proximity logic
// (host build, -DSCA_HOST_BUILD).
// =============================================================================

#include <gtest/gtest.h>

#include "access_controller.h"
#include "config.h"
#include "uwb_manager.h"

using namespace sca;

// --------------------------------------------------------------------------- //
// Access state machine
// --------------------------------------------------------------------------- //
class StateMachineTest : public ::testing::Test {
protected:
    AccessController ctrl;
    void SetUp() override { ctrl.reset(0); }

    // Drive the full happy path to UNLOCKED.
    Action driveToUnlock(uint32_t t) {
        EXPECT_EQ(Action::LED_AUTHENTICATING, ctrl.handle_event(AccessEvent::BLE_CONNECT, t));
        EXPECT_EQ(Action::LED_AUTHENTICATING, ctrl.handle_event(AccessEvent::NFC_OK, t));
        EXPECT_EQ(Action::LED_AUTHENTICATING, ctrl.handle_event(AccessEvent::UWB_NEAR, t));
        return ctrl.handle_event(AccessEvent::AUTH_OK, t);
    }
};

TEST_F(StateMachineTest, HappyPathUnlocks) {
    EXPECT_EQ(Action::PULSE_UNLOCK, driveToUnlock(100));
    EXPECT_EQ(AccessState::UNLOCKED, ctrl.state());
}

TEST_F(StateMachineTest, StartsIdle) {
    EXPECT_EQ(AccessState::IDLE, ctrl.state());
}

TEST_F(StateMachineTest, NfcFailReturnsToIdleWithPenalty) {
    ctrl.handle_event(AccessEvent::BLE_CONNECT, 0);
    Action a = ctrl.handle_event(AccessEvent::NFC_FAIL, 0);
    EXPECT_EQ(Action::LED_LOCKED, a);
    EXPECT_EQ(AccessState::IDLE, ctrl.state());
    EXPECT_EQ(1, ctrl.fail_count());
    // During the penalty window progress is blocked.
    EXPECT_EQ(Action::NONE, ctrl.handle_event(AccessEvent::BLE_CONNECT, 100));
}

TEST_F(StateMachineTest, ThreeFailuresTriggerLockout) {
    for (int i = 0; i < 2; ++i) {
        ctrl.handle_event(AccessEvent::BLE_CONNECT, /*t=*/i * (config::FAIL_PENALTY_MS + 1));
        ctrl.handle_event(AccessEvent::NFC_FAIL, i * (config::FAIL_PENALTY_MS + 1));
    }
    // Third failure.
    uint32_t t = 2 * (config::FAIL_PENALTY_MS + 1);
    ctrl.handle_event(AccessEvent::BLE_CONNECT, t);
    Action a = ctrl.handle_event(AccessEvent::NFC_FAIL, t);
    EXPECT_EQ(Action::LOG_LOCKOUT, a);
    EXPECT_TRUE(ctrl.is_locked_out());
    EXPECT_EQ(AccessState::LOCKOUT, ctrl.state());
}

TEST_F(StateMachineTest, LockoutIgnoresEventsUntilExpiry) {
    // Force lockout.
    for (int i = 0; i < 3; ++i) {
        uint32_t t = i * (config::FAIL_PENALTY_MS + 1);
        ctrl.handle_event(AccessEvent::BLE_CONNECT, t);
        ctrl.handle_event(AccessEvent::NFC_FAIL, t);
    }
    ASSERT_TRUE(ctrl.is_locked_out());
    uint32_t locked_at = 2 * (config::FAIL_PENALTY_MS + 1);
    // Events ignored during lockout.
    EXPECT_EQ(Action::NONE, ctrl.handle_event(AccessEvent::BLE_CONNECT, locked_at + 10));
    EXPECT_TRUE(ctrl.is_locked_out());
    // Lockout clears after LOCKOUT_MS.
    ctrl.tick(locked_at + config::LOCKOUT_MS + 1);
    EXPECT_FALSE(ctrl.is_locked_out());
    EXPECT_EQ(0, ctrl.fail_count());
}

TEST_F(StateMachineTest, SuccessClearsFailureStreak) {
    ctrl.handle_event(AccessEvent::BLE_CONNECT, 0);
    ctrl.handle_event(AccessEvent::NFC_FAIL, 0);
    EXPECT_EQ(1, ctrl.fail_count());
    // After penalty, complete a successful flow.
    uint32_t t = config::FAIL_PENALTY_MS + 1;
    driveToUnlock(t);
    EXPECT_EQ(0, ctrl.fail_count());
}

TEST_F(StateMachineTest, TransientStateTimesOut) {
    ctrl.handle_event(AccessEvent::BLE_CONNECT, 0);
    EXPECT_EQ(AccessState::BLE_CONNECTED, ctrl.state());
    Action a = ctrl.tick(config::STATE_TIMEOUT_MS + 1);
    EXPECT_EQ(Action::LED_LOCKED, a);
    EXPECT_EQ(AccessState::IDLE, ctrl.state());
}

TEST_F(StateMachineTest, DisconnectLocksFromAnyState) {
    driveToUnlock(100);
    ASSERT_EQ(AccessState::UNLOCKED, ctrl.state());
    Action a = ctrl.handle_event(AccessEvent::BLE_DISCONNECT, 200);
    EXPECT_EQ(Action::DRIVE_LOCK, a);
    EXPECT_EQ(AccessState::LOCKED, ctrl.state());
}

TEST_F(StateMachineTest, UwbFarLocksWhenUnlocked) {
    driveToUnlock(100);
    Action a = ctrl.handle_event(AccessEvent::UWB_FAR, 200);
    EXPECT_EQ(Action::DRIVE_LOCK, a);
    EXPECT_EQ(AccessState::LOCKED, ctrl.state());
}

// --------------------------------------------------------------------------- //
// UWB proximity
// --------------------------------------------------------------------------- //
TEST(UwbTest, ZoneClassification) {
    EXPECT_EQ(UwbZone::NEAR, UwbManager::classify(10.0f));
    EXPECT_EQ(UwbZone::MEDIUM, UwbManager::classify(100.0f));
    EXPECT_EQ(UwbZone::FAR, UwbManager::classify(300.0f));
}

TEST(UwbTest, TwrDistanceFormula) {
    // (3 - 1)/2 = 1 ns half-ToF -> ~29.98 cm.
    EXPECT_NEAR(29.9792458f, UwbManager::twr_distance_cm(3, 1), 1e-3);
}

TEST(UwbTest, SmoothApproachAccepted) {
    UwbManager uwb;
    EXPECT_TRUE(uwb.push_measurement({200.0f, 0, 5}));
    EXPECT_TRUE(uwb.push_measurement({120.0f, 300, 4}));
    EXPECT_TRUE(uwb.push_measurement({20.0f, 600, 1}));
    EXPECT_EQ(UwbZone::NEAR, uwb.zone());
    EXPECT_FALSE(uwb.relay_suspected());
}

TEST(UwbTest, InflatedTofRejected) {
    UwbManager uwb;
    EXPECT_FALSE(uwb.push_measurement({10.0f, 0, /*tof_ns=*/80}));
    EXPECT_TRUE(uwb.relay_suspected());
    EXPECT_EQ(UwbZone::FAR, uwb.zone());
}

TEST(UwbTest, DistanceTeleportRejectedAndLatches) {
    UwbManager uwb;
    EXPECT_TRUE(uwb.push_measurement({900.0f, 0, 10}));
    EXPECT_FALSE(uwb.push_measurement({10.0f, 100, 1}));  // teleport
    EXPECT_TRUE(uwb.relay_suspected());
    // Latched: a later consistent NEAR sample still does not clear suspicion.
    EXPECT_FALSE(uwb.push_measurement({10.0f, 200, 1}));
    EXPECT_EQ(UwbZone::FAR, uwb.zone());
}
