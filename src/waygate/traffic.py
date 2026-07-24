"""Monotonic peer-counter sampling for traffic API consumers."""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic

from .domain import PeerRuntime


@dataclass(frozen=True, slots=True)
class TrafficReading:
    transfer_rx_bytes: int
    transfer_tx_bytes: int
    sampled_at_monotonic: float
    rx_bytes_per_second: float | None
    tx_bytes_per_second: float | None


class PeerTrafficSampler:
    def __init__(self) -> None:
        self._previous: dict[str, TrafficReading] = {}

    def sample(self, peer: PeerRuntime, *, sampled_at: float | None = None) -> TrafficReading:
        now = monotonic() if sampled_at is None else sampled_at
        previous = self._previous.get(peer.public_key)
        rx_rate = tx_rate = None
        if previous is not None and now > previous.sampled_at_monotonic and peer.transfer_rx_bytes >= previous.transfer_rx_bytes and peer.transfer_tx_bytes >= previous.transfer_tx_bytes:
            elapsed = now - previous.sampled_at_monotonic
            rx_rate = (peer.transfer_rx_bytes - previous.transfer_rx_bytes) / elapsed
            tx_rate = (peer.transfer_tx_bytes - previous.transfer_tx_bytes) / elapsed
        current = TrafficReading(peer.transfer_rx_bytes, peer.transfer_tx_bytes, now, rx_rate, tx_rate)
        self._previous[peer.public_key] = current
        return current
