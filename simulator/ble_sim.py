"""Virtual BLE GATT transport for the simulation.

Rather than requiring a real BLE adapter (or `bleak` + an advertising peer),
this provides an in-process virtual GATT link that models the same
CHALLENGE (notify) / RESPONSE (write) / STATUS (notify) characteristics and the
connect/disconnect + MTU events. The server side owns the :class:`AuthEngine`;
the client side is driven by :mod:`phone_sim`.

If you *do* have hardware and want to drive a real ESP32, install ``bleak`` and
swap :class:`VirtualBleLink` for a thin bleak client against the same UUIDs —
the message contract is identical.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from sca_common import (
    CHAR_CHALLENGE_UUID,
    CHAR_RESPONSE_UUID,
    CHAR_STATUS_UUID,
    DEVICE_NAME,
    SERVICE_UUID,
)

logger = logging.getLogger("sca.ble")

# Notification callback: (characteristic_uuid, value_bytes) -> None
NotifyCb = Callable[[str, bytes], None]
# Write handler installed by the server: (conn_handle, value_bytes) -> None
WriteCb = Callable[[int, bytes], None]


@dataclass
class VirtualBleLink:
    """An in-process BLE GATT link between a server and one client.

    Attributes:
        device_name: Advertised device name.
        mtu: Negotiated MTU (negotiate_mtu may change it).
        conn_handle: Active connection handle, or None when disconnected.
    """

    device_name: str = DEVICE_NAME
    mtu: int = 23
    conn_handle: Optional[int] = None
    _next_handle: int = 1
    _client_notify: Optional[NotifyCb] = None
    _server_write: Optional[WriteCb] = None
    _on_connect: List[Callable[[int], None]] = field(default_factory=list)
    _on_disconnect: List[Callable[[int], None]] = field(default_factory=list)

    # ----- advertising / connection ------------------------------------- #
    def advertise(self) -> str:
        """Return the advertised name (a real peer would broadcast this)."""
        logger.info("advertising service %s as '%s'", SERVICE_UUID, self.device_name)
        return self.device_name

    def connect(self, client_notify: NotifyCb) -> int:
        """Client connects; returns the assigned connection handle.

        Args:
            client_notify: Callback the server uses to push notifications.
        """
        self.conn_handle = self._next_handle
        self._next_handle += 1
        self._client_notify = client_notify
        for cb in self._on_connect:
            cb(self.conn_handle)
        logger.info("client connected, handle=%d", self.conn_handle)
        return self.conn_handle

    def negotiate_mtu(self, mtu: int) -> int:
        """Negotiate MTU; the smaller of requested and server preferred wins."""
        self.mtu = min(mtu, 247)
        logger.info("MTU negotiated: %d", self.mtu)
        return self.mtu

    def disconnect(self) -> None:
        """Tear down the connection and fire disconnect callbacks."""
        if self.conn_handle is None:
            return
        handle = self.conn_handle
        self.conn_handle = None
        self._client_notify = None
        for cb in self._on_disconnect:
            cb(handle)
        logger.info("disconnected handle=%d", handle)

    # ----- server registration ------------------------------------------ #
    def on_connect(self, cb: Callable[[int], None]) -> None:
        """Register a server connect handler."""
        self._on_connect.append(cb)

    def on_disconnect(self, cb: Callable[[int], None]) -> None:
        """Register a server disconnect handler."""
        self._on_disconnect.append(cb)

    def set_write_handler(self, cb: WriteCb) -> None:
        """Install the server's RESPONSE-write handler."""
        self._server_write = cb

    # ----- characteristic traffic --------------------------------------- #
    def server_notify(self, char_uuid: str, value: bytes) -> None:
        """Server -> client notification (CHALLENGE or STATUS)."""
        if self._client_notify is not None:
            self._client_notify(char_uuid, value)

    def client_write(self, value: bytes) -> None:
        """Client -> server write on the RESPONSE characteristic."""
        if self.conn_handle is None or self._server_write is None:
            raise RuntimeError("write attempted without an active connection")
        self._server_write(self.conn_handle, value)


# Re-export UUIDs so callers can import everything from one module.
__all__ = [
    "VirtualBleLink",
    "CHAR_CHALLENGE_UUID",
    "CHAR_RESPONSE_UUID",
    "CHAR_STATUS_UUID",
    "SERVICE_UUID",
]
