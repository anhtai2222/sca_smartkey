"""End-to-end SCA Smart Key demo (no hardware required).

Runs the complete happy-path flow with timestamped steps:

    discover BLE -> connect -> NFC tap -> UWB ranging (approach) ->
    HMAC challenge-response -> UNLOCK

Run:
    python full_demo.py
"""

from __future__ import annotations

import logging
import time

from ble_sim import VirtualBleLink
from nfc_sim import NfcReader
from phone_sim import PhoneSim
from uwb_sim import UwbSample
from vehicle_sim import VehicleServer

logger = logging.getLogger("sca.demo")


def _banner(title: str) -> None:
    print(f"\n{'=' * 64}\n  {title}\n{'=' * 64}")


def _step(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def run_demo() -> bool:
    """Run the full happy-path demo.

    Returns:
        True if the vehicle unlocked, False otherwise.
    """
    _banner("SCA SMART KEY — END-TO-END DEMO")

    link = VirtualBleLink()
    vehicle = VehicleServer()
    vehicle.bind(link)
    phone = PhoneSim()

    _step("1. Phone discovers and connects over BLE")
    phone.connect(link)
    assert phone.last_challenge is not None, "vehicle should challenge on connect"
    _step(f"   -> challenge nonce received: {phone.last_challenge.hex()[:24]}...")

    _step("2. NFC tap (presenting whitelisted UID)")
    uid = NfcReader.authorised_uid()
    ok_nfc = vehicle.verify_nfc(uid)
    _step(f"   -> NFC authorised: {ok_nfc}")

    _step("3. UWB ranging — phone approaching the vehicle")
    t0 = time.monotonic()
    for i, dist in enumerate((200.0, 140.0, 90.0, 45.0, 22.0)):
        # Realistic ToF for the given distance (well under the relay cap).
        tof = dist / 29.98 * 2.0
        accepted = vehicle.range_uwb(
            UwbSample(distance_cm=dist, timestamp_s=t0 + i * 0.3, tof_ns=tof)
        )
        _step(f"   -> d={dist:6.1f}cm zone={vehicle.uwb.zone.value:<6} accepted={accepted}")

    _step("4. HMAC-SHA256 challenge-response")
    phone.respond_to_challenge()

    decision = vehicle.last_decision
    assert decision is not None
    _step(f"5. Vehicle decision: {'UNLOCK' if decision.granted else 'DENY'} "
          f"({decision.reason})")

    _banner("RESULT: " + ("🔓 UNLOCKED" if decision.granted else "🔒 LOCKED"))
    phone.disconnect()
    return decision.granted


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
        datefmt="%H:%M:%S",
    )
    granted = run_demo()
    return 0 if granted else 1


if __name__ == "__main__":
    raise SystemExit(main())
