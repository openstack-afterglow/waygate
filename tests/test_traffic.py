from afterglow_wg_agent.domain import PeerRuntime
from afterglow_wg_agent.traffic import PeerTrafficSampler


def peer(rx, tx):
    return PeerRuntime("public", None, None, rx, tx, ())


def test_rates_are_delta_based_and_reset_safe():
    sampler = PeerTrafficSampler()
    assert sampler.sample(peer(100, 50), sampled_at=10).rx_bytes_per_second is None
    reading = sampler.sample(peer(160, 80), sampled_at=12)
    assert (reading.rx_bytes_per_second, reading.tx_bytes_per_second) == (30.0, 15.0)
    reset = sampler.sample(peer(1, 1), sampled_at=13)
    assert reset.rx_bytes_per_second is None
