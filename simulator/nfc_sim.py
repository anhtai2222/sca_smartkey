"""NFC tap simulation (PN532 stand-in).

Models presenting an ISO 14443-A tag/phone to the reader and verifying its UID
against the whitelist from :mod:`sca_common`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sca_common import NFC_WHITELIST, nfc_uid_authorised

logger = logging.getLogger("sca.nfc")


@dataclass
class NfcTap:
    """Result of presenting a tag."""

    uid: bytes
    authorised: bool


class NfcReader:
    """Simulated PN532 NFC reader."""

    def tap(self, uid: bytes) -> NfcTap:
        """Present a tag UID to the reader.

        Args:
            uid: The tag/phone UID bytes.

        Returns:
            An :class:`NfcTap` carrying the authorisation verdict.
        """
        ok = nfc_uid_authorised(uid)
        logger.info("NFC tap uid=%s authorised=%s", uid.hex().upper(), ok)
        return NfcTap(uid=uid, authorised=ok)

    @staticmethod
    def authorised_uid() -> bytes:
        """Return a known-good whitelisted UID for demos."""
        return NFC_WHITELIST[0]

    @staticmethod
    def rogue_uid() -> bytes:
        """Return an unauthorised UID for negative tests."""
        return bytes([0xDE, 0xAD, 0xBE, 0xEF])
