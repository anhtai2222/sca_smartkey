"""Shared types, crypto, and the server-side auth engine for the simulator.

This module mirrors the firmware's auth logic (``firmware/src/auth_engine.*``)
in pure Python so the desktop simulation is bit-compatible with the C++ side:
both compute ``HMAC-SHA256(nonce, shared_secret)`` and both enforce the same
nonce TTL / single-use / connection-binding anti-replay rules.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger("sca.common")

# --------------------------------------------------------------------------- #
# Constants — kept in sync with firmware/src/config.h
# --------------------------------------------------------------------------- #
DEVICE_NAME = "SCA-SmartKey"
SERVICE_UUID = "6e9f0001-b5a3-4f6d-9c21-7d3e8a1b2c40"
CHAR_CHALLENGE_UUID = "6e9f0002-b5a3-4f6d-9c21-7d3e8a1b2c40"
CHAR_RESPONSE_UUID = "6e9f0003-b5a3-4f6d-9c21-7d3e8a1b2c40"
CHAR_STATUS_UUID = "6e9f0004-b5a3-4f6d-9c21-7d3e8a1b2c40"

NONCE_LEN = 32
HMAC_LEN = 32
NONCE_TTL_S = 60.0

# Must byte-match config.h SHARED_SECRET.
SHARED_SECRET = bytes(
    [
        0x53, 0x43, 0x41, 0x2D, 0x73, 0x6D, 0x61, 0x72,
        0x74, 0x6B, 0x65, 0x79, 0x2D, 0x73, 0x68, 0x61,
        0x72, 0x65, 0x64, 0x2D, 0x73, 0x65, 0x63, 0x72,
        0x65, 0x74, 0x2D, 0x76, 0x31, 0x2E, 0x30, 0x21,
    ]
)

# UWB proximity zones (cm).
UWB_NEAR_CM = 30.0
UWB_MEDIUM_CM = 150.0
UWB_MAX_DELTA_CM_PER_S = 500.0
UWB_MAX_TOF_NS = 50

# NFC whitelist (4-byte UIDs).
NFC_WHITELIST = [
    bytes([0x04, 0xA2, 0x1C, 0x5B]),
    bytes([0x04, 0xDE, 0xAD, 0xBE]),
]

SPEED_OF_LIGHT_CM_PER_NS = 29.9792458


# --------------------------------------------------------------------------- #
# Crypto
# --------------------------------------------------------------------------- #
def compute_response(nonce: bytes, secret: bytes = SHARED_SECRET) -> bytes:
    """Compute the client HMAC response for a challenge nonce.

    Args:
        nonce: The 32-byte challenge nonce.
        secret: Shared secret key.

    Returns:
        32-byte HMAC-SHA256 digest.
    """
    return hmac.new(secret, nonce, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AuthResult(Enum):
    """Outcome of a server-side response verification."""

    OK = "OK"
    UNKNOWN_NONCE = "UNKNOWN_NONCE"
    EXPIRED = "EXPIRED"
    REPLAYED = "REPLAYED"
    HANDLE_MISMATCH = "HANDLE_MISMATCH"
    BAD_HMAC = "BAD_HMAC"


class UwbZone(Enum):
    """UWB proximity zone."""

    NEAR = "NEAR"
    MEDIUM = "MEDIUM"
    FAR = "FAR"


def classify_zone(distance_cm: float) -> UwbZone:
    """Map a distance to a proximity zone (mirrors UwbManager::classify)."""
    if distance_cm < UWB_NEAR_CM:
        return UwbZone.NEAR
    if distance_cm < UWB_MEDIUM_CM:
        return UwbZone.MEDIUM
    return UwbZone.FAR


def twr_distance_cm(t_round_ns: float, t_reply_ns: float) -> float:
    """Two-Way-Ranging distance in cm: d = c*(T_round - T_reply)/2."""
    if t_round_ns <= t_reply_ns:
        return 0.0
    tof_ns = (t_round_ns - t_reply_ns) / 2.0
    return tof_ns * SPEED_OF_LIGHT_CM_PER_NS


# --------------------------------------------------------------------------- #
# Server-side auth engine
# --------------------------------------------------------------------------- #
@dataclass
class _NonceRecord:
    """A single issued challenge record."""

    nonce: bytes
    issued_s: float
    conn_handle: int
    consumed: bool = False


@dataclass
class AuthEngine:
    """HMAC challenge-response engine with anti-replay nonce pool.

    Mirrors the firmware ``sca::AuthEngine``: nonces are single-use, expire
    after ``ttl_s`` and are bound to the connection handle they were issued on.
    """

    secret: bytes = SHARED_SECRET
    ttl_s: float = NONCE_TTL_S
    _pool: Dict[bytes, _NonceRecord] = field(default_factory=dict)

    def new_challenge(self, conn_handle: int, now_s: Optional[float] = None) -> bytes:
        """Generate and register a fresh nonce bound to a connection.

        Args:
            conn_handle: BLE connection handle to bind the nonce to.
            now_s: Optional injected time (defaults to ``time.monotonic()``).

        Returns:
            The new 32-byte nonce.
        """
        now_s = time.monotonic() if now_s is None else now_s
        nonce = secrets.token_bytes(NONCE_LEN)
        self._pool[nonce] = _NonceRecord(nonce, now_s, conn_handle)
        logger.debug("issued nonce %s for handle %d", nonce.hex()[:12], conn_handle)
        return nonce

    def verify_response(
        self,
        conn_handle: int,
        nonce: bytes,
        response: bytes,
        now_s: Optional[float] = None,
    ) -> AuthResult:
        """Verify a client's HMAC response (mirrors the firmware checks).

        Args:
            conn_handle: Connection the response arrived on.
            nonce: The nonce echoed by the client.
            response: The client's HMAC.
            now_s: Optional injected time.

        Returns:
            An :class:`AuthResult`.
        """
        now_s = time.monotonic() if now_s is None else now_s
        rec = self._pool.get(nonce)
        if rec is None:
            return AuthResult.UNKNOWN_NONCE
        # Single-use takes precedence over TTL so a replay is reported as
        # REPLAYED. The consumed record is kept (not popped) for detectability;
        # mirrors firmware sca::AuthEngine::verify_response.
        if rec.consumed:
            return AuthResult.REPLAYED
        if now_s - rec.issued_s > self.ttl_s:
            return AuthResult.EXPIRED
        if rec.conn_handle != conn_handle:
            return AuthResult.HANDLE_MISMATCH
        expected = compute_response(nonce, self.secret)
        if not hmac.compare_digest(expected, response):
            return AuthResult.BAD_HMAC
        rec.consumed = True
        return AuthResult.OK


def nfc_uid_authorised(uid: bytes) -> bool:
    """Return True if an NFC UID is in the whitelist."""
    return uid in NFC_WHITELIST
