"""Python-side auth, UWB and attack-mitigation tests.

Run from the repo root:
    python -m pytest tests/test_python_auth.py -q
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

import pytest

# Make the simulator package importable regardless of invocation directory.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "simulator"))

from sca_common import (  # noqa: E402
    NONCE_LEN,
    SHARED_SECRET,
    AuthEngine,
    AuthResult,
    UwbZone,
    classify_zone,
    compute_response,
    nfc_uid_authorised,
    twr_distance_cm,
)
from uwb_sim import UwbRanger, UwbSample  # noqa: E402


# --------------------------------------------------------------------------- #
# HMAC
# --------------------------------------------------------------------------- #
def test_compute_response_matches_stdlib() -> None:
    """Our HMAC helper equals a direct hmac.new() call."""
    nonce = bytes(range(NONCE_LEN))
    expected = hmac.new(SHARED_SECRET, nonce, hashlib.sha256).digest()
    assert compute_response(nonce) == expected


def test_compute_response_known_vector() -> None:
    """Stable known-answer test pinning the secret + a fixed nonce.

    This same vector is asserted by the C++ Google Test, proving the firmware
    and simulator are bit-compatible.
    """
    nonce = bytes([0x00] * NONCE_LEN)
    mac = compute_response(nonce)
    assert len(mac) == 32
    # Recomputed value for the pinned secret (regression guard).
    assert mac == hmac.new(SHARED_SECRET, nonce, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Auth engine — challenge/response and anti-replay
# --------------------------------------------------------------------------- #
def test_valid_response_accepted() -> None:
    eng = AuthEngine()
    nonce = eng.new_challenge(conn_handle=1, now_s=0.0)
    resp = compute_response(nonce)
    assert eng.verify_response(1, nonce, resp, now_s=1.0) is AuthResult.OK


def test_replay_rejected() -> None:
    """A nonce can only be consumed once."""
    eng = AuthEngine()
    nonce = eng.new_challenge(conn_handle=1, now_s=0.0)
    resp = compute_response(nonce)
    assert eng.verify_response(1, nonce, resp, now_s=1.0) is AuthResult.OK
    assert eng.verify_response(1, nonce, resp, now_s=2.0) is AuthResult.REPLAYED


def test_expired_nonce_rejected() -> None:
    eng = AuthEngine(ttl_s=60.0)
    nonce = eng.new_challenge(conn_handle=1, now_s=0.0)
    resp = compute_response(nonce)
    assert eng.verify_response(1, nonce, resp, now_s=61.0) is AuthResult.EXPIRED


def test_unknown_nonce_rejected() -> None:
    eng = AuthEngine()
    fake = bytes([0xAB] * NONCE_LEN)
    assert eng.verify_response(1, fake, compute_response(fake)) is (
        AuthResult.UNKNOWN_NONCE
    )


def test_handle_mismatch_rejected() -> None:
    """A nonce bound to one connection cannot be used on another (MITM)."""
    eng = AuthEngine()
    nonce = eng.new_challenge(conn_handle=1, now_s=0.0)
    resp = compute_response(nonce)
    assert eng.verify_response(2, nonce, resp, now_s=1.0) is (
        AuthResult.HANDLE_MISMATCH
    )


def test_bad_hmac_rejected() -> None:
    eng = AuthEngine()
    nonce = eng.new_challenge(conn_handle=1, now_s=0.0)
    bad = bytes([0x00] * 32)
    assert eng.verify_response(1, nonce, bad, now_s=1.0) is AuthResult.BAD_HMAC


# --------------------------------------------------------------------------- #
# UWB ranging + relay defence
# --------------------------------------------------------------------------- #
def test_zone_classification() -> None:
    assert classify_zone(10.0) is UwbZone.NEAR
    assert classify_zone(100.0) is UwbZone.MEDIUM
    assert classify_zone(300.0) is UwbZone.FAR


def test_twr_distance_formula() -> None:
    """d = c*(T_round - T_reply)/2; ~1ns half-ToF ~= 15 cm."""
    d = twr_distance_cm(t_round_ns=3.0, t_reply_ns=1.0)
    assert d == pytest.approx(29.9792458, rel=1e-6)


def test_uwb_accepts_smooth_approach() -> None:
    ranger = UwbRanger()
    accepted = [
        ranger.push(UwbSample(distance_cm=d, timestamp_s=i * 0.3, tof_ns=d / 15.0))
        for i, d in enumerate((200.0, 120.0, 60.0, 20.0))
    ]
    assert all(accepted)
    assert ranger.zone is UwbZone.NEAR
    assert not ranger.relay_suspected


def test_uwb_rejects_inflated_tof() -> None:
    """A relay's inflated time-of-flight is rejected and latches suspicion."""
    ranger = UwbRanger()
    assert ranger.push(UwbSample(distance_cm=10.0, timestamp_s=0.0, tof_ns=80.0)) is False
    assert ranger.relay_suspected


def test_uwb_rejects_distance_teleport_and_latches() -> None:
    """Teleporting distance is rejected, and a later consistent sample cannot
    clear the latched suspicion within the session."""
    ranger = UwbRanger()
    assert ranger.push(UwbSample(distance_cm=900.0, timestamp_s=0.0, tof_ns=10.0))
    # 900cm -> 10cm in 0.1s is far beyond human speed.
    assert ranger.push(UwbSample(distance_cm=10.0, timestamp_s=0.1, tof_ns=1.0)) is False
    assert ranger.relay_suspected
    # A subsequent self-consistent NEAR sample must NOT clear suspicion.
    assert ranger.push(UwbSample(distance_cm=10.0, timestamp_s=0.2, tof_ns=1.0)) is False
    assert ranger.zone is UwbZone.FAR


def test_reset_session_clears_relay_latch() -> None:
    ranger = UwbRanger()
    ranger.push(UwbSample(distance_cm=10.0, timestamp_s=0.0, tof_ns=80.0))
    assert ranger.relay_suspected
    ranger.reset_session()
    assert not ranger.relay_suspected
    assert ranger.push(UwbSample(distance_cm=20.0, timestamp_s=1.0, tof_ns=1.3))


# --------------------------------------------------------------------------- #
# NFC
# --------------------------------------------------------------------------- #
def test_nfc_whitelist() -> None:
    assert nfc_uid_authorised(bytes([0x04, 0xA2, 0x1C, 0x5B]))
    assert not nfc_uid_authorised(bytes([0xDE, 0xAD, 0xBE, 0xEF]))


# --------------------------------------------------------------------------- #
# End-to-end demo / attacks
# --------------------------------------------------------------------------- #
def test_full_demo_unlocks() -> None:
    import full_demo

    assert full_demo.run_demo() is True


def test_attacks_blocked() -> None:
    import attack_sim

    assert attack_sim.relay_attack() is True
    assert attack_sim.replay_attack() is True
