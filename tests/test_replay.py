"""Recorded-transcript replay — classify real captured server responses offline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import rawprobe
from cryptoprobe.primitives import NamedGroup

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_replay_hrr_classifies_hybrid():
    data = (FIXTURES / "hrr-x25519mlkem768.bin").read_bytes()
    o = rawprobe.parse_received(data, rawprobe.DEFAULT_OFFER)
    assert o.is_hrr is True
    assert o.selected_group_name == "X25519MLKEM768"
    assert NamedGroup.from_code(o.selected_group).is_hybrid_pqc


def test_replay_serverhello_classifies_classical():
    data = (FIXTURES / "serverhello-x25519.bin").read_bytes()
    o = rawprobe.parse_received(data, rawprobe.CLASSICAL_GROUPS)
    assert o.is_server_hello is True
    assert o.is_hrr is False
    assert o.selected_group_name == "x25519"
    assert NamedGroup.from_code(o.selected_group).is_classical


def test_replay_truncated_transcript_fabricates_nothing():
    data = (FIXTURES / "hrr-x25519mlkem768.bin").read_bytes()[:18]
    o = rawprobe.parse_received(data)
    # not enough bytes for a terminal record -> no group surfaced, not guessed
    assert o.selected_group is None
    assert o.is_server_hello is False
