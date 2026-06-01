"""Vehicle-side server: the SCA-SmartKey GATT server + access decision logic.

Owns the :class:`AuthEngine`, the :class:`UwbRanger`, and the NFC check, and
exposes the same characteristic contract the firmware does. It records each
unlock/deny decision so demos and tests can assert on the outcome.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from ble_sim import CHAR_CHALLENGE_UUID, CHAR_STATUS_UUID, VirtualBleLink
from nfc_sim import NfcReader
from sca_common import NONCE_LEN, AuthEngine, AuthResult, UwbZone
from uwb_sim import UwbRanger, UwbSample

logger = logging.getLogger("sca.vehicle")


@dataclass
class Decision:
    """A recorded access decision."""

    granted: bool
    reason: str
    auth_result: Optional[AuthResult] = None


@dataclass
class VehicleServer:
    """Simulated vehicle-side smart-key server."""

    auth: AuthEngine = field(default_factory=AuthEngine)
    uwb: UwbRanger = field(default_factory=UwbRanger)
    nfc: NfcReader = field(default_factory=NfcReader)
    nfc_verified: bool = False
    decisions: List[Decision] = field(default_factory=list)
    locked: bool = True
    _link: Optional[VirtualBleLink] = field(default=None, repr=False)

    # ------------------------------------------------------------------ #
    def bind(self, link: VirtualBleLink) -> None:
        """Attach to a BLE link and wire up connect/write handlers."""
        self._link = link
        link.on_connect(self._on_connect)
        link.on_disconnect(self._on_disconnect)
        link.set_write_handler(self._on_response_write)

    def _on_connect(self, conn_handle: int) -> None:
        """On connect, immediately push a fresh challenge nonce."""
        nonce = self.auth.new_challenge(conn_handle)
        assert self._link is not None
        self._link.server_notify(CHAR_CHALLENGE_UUID, nonce)

    def _on_disconnect(self, conn_handle: int) -> None:
        """Lock on disconnect."""
        self.nfc_verified = False
        self.locked = True

    # ------------------------------------------------------------------ #
    def verify_nfc(self, uid: bytes) -> bool:
        """Run the NFC whitelist check (must pass before unlocking)."""
        tap = self.nfc.tap(uid)
        self.nfc_verified = tap.authorised
        return tap.authorised

    def range_uwb(self, sample: UwbSample) -> bool:
        """Feed a UWB sample; returns False if rejected as a relay."""
        return self.uwb.push(sample)

    def _on_response_write(self, conn_handle: int, value: bytes) -> None:
        """Handle a RESPONSE write: verify HMAC + all gating preconditions."""
        if len(value) != NONCE_LEN * 2:
            self._record(False, "malformed response", None)
            return
        nonce, mac = value[:NONCE_LEN], value[NONCE_LEN:]
        result = self.auth.verify_response(conn_handle, nonce, mac)

        if result is not AuthResult.OK:
            self._record(False, f"auth {result.value}", result)
            return
        if not self.nfc_verified:
            self._record(False, "NFC not verified", result)
            return
        if self.uwb.relay_suspected:
            self._record(False, "UWB relay suspected", result)
            return
        if self.uwb.zone is not UwbZone.NEAR:
            self._record(False, f"UWB zone {self.uwb.zone.value}", result)
            return

        self.locked = False
        self._record(True, "all checks passed", result)

    def _record(
        self, granted: bool, reason: str, result: Optional[AuthResult]
    ) -> None:
        """Record a decision and push a STATUS notification."""
        self.decisions.append(Decision(granted, reason, result))
        if granted:
            logger.info("ACCESS GRANTED: %s", reason)
        else:
            logger.warning("ACCESS DENIED: %s", reason)
        if self._link is not None:
            self._link.server_notify(CHAR_STATUS_UUID, bytes([0 if granted else 1]))

    @property
    def last_decision(self) -> Optional[Decision]:
        """Most recent recorded decision."""
        return self.decisions[-1] if self.decisions else None
