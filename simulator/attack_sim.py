"""Attack simulations: relay (distance spoofing) and replay (reused nonce).

Both attacks succeed against naive keyless entry but are *blocked* by this
design. Each scenario prints what the attacker does and the defence that stops
it.

Run:
    python attack_sim.py
"""

from __future__ import annotations

import logging
import time

from ble_sim import VirtualBleLink
from nfc_sim import NfcReader
from phone_sim import PhoneSim
from sca_common import AuthResult
from uwb_sim import UwbSample
from vehicle_sim import VehicleServer

logger = logging.getLogger("sca.attack")


def _banner(title: str) -> None:
    print(f"\n{'=' * 64}\n  {title}\n{'=' * 64}")


def relay_attack() -> bool:
    """Relay attack: attacker forwards BLE/UWB to make a far phone look near.

    The real phone is far away; the attacker relays signals to the car. The
    relay adds latency (inflated time-of-flight) and the apparent distance
    teleports between samples. UWB plausibility checks reject both.

    Returns:
        True if the attack was blocked (i.e. the test passed).
    """
    _banner("RELAY ATTACK (distance spoofing)")
    link = VirtualBleLink()
    vehicle = VehicleServer()
    vehicle.bind(link)
    phone = PhoneSim()
    phone.connect(link)

    vehicle.verify_nfc(NfcReader.authorised_uid())

    # Legit baseline sample: phone genuinely far away.
    t0 = time.monotonic()
    vehicle.range_uwb(UwbSample(distance_cm=900.0, timestamp_s=t0, tof_ns=60.1))
    print("[attacker] phone is 9m away; relaying to fake proximity...")

    # Attack vector A: inflated ToF (relay latency) on a 'near' claim.
    a = vehicle.range_uwb(UwbSample(distance_cm=10.0, timestamp_s=t0 + 0.1, tof_ns=80.0))
    print(f"[defence ] ToF-spoof sample accepted={a} "
          f"relay_suspected={vehicle.uwb.relay_suspected}")

    # Attack vector B: teleport distance 900cm -> 10cm in 100ms.
    b = vehicle.range_uwb(UwbSample(distance_cm=10.0, timestamp_s=t0 + 0.2, tof_ns=1.0))
    print(f"[defence ] distance-teleport accepted={b} "
          f"relay_suspected={vehicle.uwb.relay_suspected}")

    # Even with a valid HMAC, the relay never reaches a trusted NEAR zone.
    phone.respond_to_challenge()
    decision = vehicle.last_decision
    blocked = decision is not None and not decision.granted
    print(f"[result  ] unlock {'DENIED' if blocked else 'GRANTED'} "
          f"({decision.reason if decision else 'n/a'})")
    phone.disconnect()
    return blocked


def replay_attack() -> bool:
    """Replay attack: attacker captures a valid response and re-sends it.

    The first exchange succeeds. The attacker replays the exact same
    nonce||hmac on a new connection. The nonce is single-use and bound to the
    original connection handle, so the server rejects it.

    Returns:
        True if the replay was blocked (i.e. the test passed).
    """
    _banner("REPLAY ATTACK (reused nonce)")
    link = VirtualBleLink()
    vehicle = VehicleServer()
    vehicle.bind(link)

    # ---- Legitimate session: capture a valid response ----
    phone = PhoneSim()
    phone.connect(link)
    vehicle.verify_nfc(NfcReader.authorised_uid())
    t0 = time.monotonic()
    vehicle.range_uwb(UwbSample(distance_cm=20.0, timestamp_s=t0, tof_ns=1.3))
    captured = phone.respond_to_challenge()  # attacker sniffs this 64-byte blob
    first = vehicle.last_decision
    print(f"[capture ] legit unlock granted={first.granted if first else None}; "
          f"attacker captured {len(captured)} bytes")
    phone.disconnect()  # owner leaves; vehicle re-locks on disconnect

    # ---- Attacker opens a NEW connection and replays the captured bytes ----
    # The attacker satisfies NFC + a genuine NEAR ranging on their own session
    # (e.g. standing at the door); only the HMAC is replayed.
    vehicle.uwb.reset_session()
    vehicle.verify_nfc(NfcReader.authorised_uid())
    vehicle.range_uwb(UwbSample(distance_cm=20.0, timestamp_s=t0 + 5.0, tof_ns=1.3))
    new_handle = link.connect(lambda *_: None)  # new connection -> new nonce
    print(f"[attacker] replaying captured response on new handle {new_handle}...")
    link.client_write(captured)

    decision = vehicle.last_decision
    blocked = decision is not None and not decision.granted
    expected = decision and decision.auth_result in (
        AuthResult.REPLAYED,
        AuthResult.UNKNOWN_NONCE,
        AuthResult.HANDLE_MISMATCH,
    )
    print(f"[result  ] replay {'REJECTED' if blocked else 'ACCEPTED'} "
          f"(auth={decision.auth_result.value if decision and decision.auth_result else 'n/a'})")
    link.disconnect()
    return bool(blocked and expected)


def main() -> int:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
        datefmt="%H:%M:%S",
    )
    relay_ok = relay_attack()
    replay_ok = replay_attack()

    _banner("ATTACK SUMMARY")
    print(f"  Relay attack  blocked: {relay_ok}")
    print(f"  Replay attack blocked: {replay_ok}")
    all_blocked = relay_ok and replay_ok
    print(f"\n  {'✅ ALL ATTACKS BLOCKED' if all_blocked else '❌ A DEFENCE FAILED'}")
    return 0 if all_blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
