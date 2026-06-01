"""UWB ranging simulation with an anti-relay consistency check.

Mirrors the firmware ``sca::UwbManager``: it classifies distances into
NEAR/MEDIUM/FAR zones and rejects samples that look like a relay attack — either
an implausible time-of-flight or a distance that changes faster than a human
could move between samples.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sca_common import (
    UWB_MAX_DELTA_CM_PER_S,
    UWB_MAX_TOF_NS,
    UwbZone,
    classify_zone,
)

logger = logging.getLogger("sca.uwb")


@dataclass
class UwbSample:
    """A single ranging sample."""

    distance_cm: float
    timestamp_s: float
    tof_ns: float = 1.0


class UwbRanger:
    """Stateful UWB ranger with relay detection."""

    def __init__(self) -> None:
        self._last: Optional[UwbSample] = None
        self.zone: UwbZone = UwbZone.FAR
        self.relay_suspected: bool = False

    def push(self, sample: UwbSample) -> bool:
        """Feed a ranging sample.

        A relay is detected if either (a) the time-of-flight is implausibly
        large, or (b) the distance changes faster than a human could move since
        the last *trusted* sample. Once relay is suspected it **latches** for
        the rest of the session: a subsequent self-consistent spoof must not be
        able to clear suspicion. The trusted baseline (``_last``) is only
        advanced on accepted samples, so an attacker cannot "anchor" the rate
        check to a value they just injected.

        Args:
            sample: The new measurement.

        Returns:
            False if the sample is rejected as a suspected relay attack.
        """
        # Plausibility 1: physical time-of-flight bound.
        if sample.tof_ns > UWB_MAX_TOF_NS:
            self.relay_suspected = True  # latched
            self.zone = UwbZone.FAR
            logger.warning(
                "relay suspected: ToF %.1fns exceeds %dns bound",
                sample.tof_ns,
                UWB_MAX_TOF_NS,
            )
            return False

        # Plausibility 2: distance-rate bound vs. last *trusted* sample.
        if self._last is not None:
            dt = sample.timestamp_s - self._last.timestamp_s
            if dt > 0:
                rate = abs(sample.distance_cm - self._last.distance_cm) / dt
                if rate > UWB_MAX_DELTA_CM_PER_S:
                    self.relay_suspected = True  # latched
                    self.zone = UwbZone.FAR
                    logger.warning(
                        "relay suspected: distance rate %.0f cm/s exceeds %.0f cm/s",
                        rate,
                        UWB_MAX_DELTA_CM_PER_S,
                    )
                    return False

        # Accepted: advance the trusted baseline. If a relay was previously
        # latched this session, the zone stays FAR (suspicion is not cleared).
        self._last = sample
        if self.relay_suspected:
            self.zone = UwbZone.FAR
        else:
            self.zone = classify_zone(sample.distance_cm)
        return not self.relay_suspected

    def reset_session(self) -> None:
        """Clear ranging state for a new, independent session."""
        self._last = None
        self.zone = UwbZone.FAR
        self.relay_suspected = False
