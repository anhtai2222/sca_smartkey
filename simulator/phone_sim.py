"""Phone-side simulator: the BLE + UWB + NFC client (the "digital key").

The phone discovers the SCA-SmartKey peer, connects, taps NFC, performs UWB
ranging and answers the HMAC challenge. It is intentionally a *thin* client: it
holds the shared secret and responds to challenges, exactly like the firmware
expects. The vehicle-side server logic lives in :mod:`vehicle_sim`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from ble_sim import (
    CHAR_CHALLENGE_UUID,
    CHAR_RESPONSE_UUID,
    CHAR_STATUS_UUID,
    VirtualBleLink,
)
from sca_common import NONCE_LEN, SHARED_SECRET, compute_response

logger = logging.getLogger("sca.phone")


@dataclass
class PhoneSim:
    """Simulated smart-phone digital key.

    Attributes:
        secret: The shared secret provisioned to the phone.
        last_challenge: Most recent challenge nonce received.
        last_status: Most recent STATUS byte received from the vehicle.
    """

    secret: bytes = SHARED_SECRET
    last_challenge: Optional[bytes] = None
    last_status: Optional[int] = None
    _link: Optional[VirtualBleLink] = field(default=None, repr=False)

    def connect(self, link: VirtualBleLink) -> int:
        """Discover + connect to the vehicle and negotiate MTU.

        Args:
            link: The virtual BLE link to the vehicle.

        Returns:
            The connection handle.
        """
        self._link = link
        name = link.advertise()
        logger.info("phone discovered '%s', connecting...", name)
        handle = link.connect(self._on_notify)
        link.negotiate_mtu(247)
        return handle

    def _on_notify(self, char_uuid: str, value: bytes) -> None:
        """Handle CHALLENGE / STATUS notifications from the vehicle."""
        if char_uuid == CHAR_CHALLENGE_UUID:
            self.last_challenge = value
            logger.info("phone received challenge %s...", value.hex()[:16])
        elif char_uuid == CHAR_STATUS_UUID:
            self.last_status = value[0] if value else None
            logger.info("phone received status byte %s", self.last_status)

    def respond_to_challenge(self, nonce: Optional[bytes] = None) -> bytes:
        """Compute and send HMAC(nonce, secret) on the RESPONSE characteristic.

        Args:
            nonce: Override the stored challenge (used by replay attack demo).

        Returns:
            The 64-byte payload written (nonce || hmac).
        """
        if self._link is None:
            raise RuntimeError("phone is not connected")
        use_nonce = nonce if nonce is not None else self.last_challenge
        if use_nonce is None or len(use_nonce) != NONCE_LEN:
            raise RuntimeError("no valid challenge to respond to")
        mac = compute_response(use_nonce, self.secret)
        payload = use_nonce + mac
        logger.info("phone sending response (hmac %s...)", mac.hex()[:16])
        self._link.client_write(payload)
        return payload

    def disconnect(self) -> None:
        """Disconnect from the vehicle."""
        if self._link is not None:
            self._link.disconnect()
