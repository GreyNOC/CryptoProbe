"""IKEv2 capability detection — request build + response parse. No network."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import ikev2


def test_request_is_well_formed_ike_sa_init():
    pkt = ikev2.build_ike_sa_init()
    # header: SPI_i(8) SPI_r(8) nextpayload(1) version(1) exch(1) flags(1) msgid(4) len(4)
    assert pkt[:8] == ikev2._SPI_I
    assert pkt[16] == ikev2._PL_SA          # first payload is SA
    assert pkt[18] == ikev2._EXCH_IKE_SA_INIT
    assert pkt[19] == 0x08                   # initiator flag
    declared_len = struct.unpack_from(">I", pkt, 24)[0]
    assert declared_len == len(pkt)          # length field matches actual


def _synthetic_response(intermediate=True, addke=True):
    """Craft a minimal IKE_SA_INIT response: SA (with ADDKE1 transform) + a
    NOTIFY(INTERMEDIATE_EXCHANGE_SUPPORTED)."""
    # transforms: DH MODP2048 (type4 id14) [last unless addke]
    def transform(last, ttype, tid):
        body = struct.pack(">BBH", ttype, 0, tid)
        return struct.pack(">BBH", 0 if last else 3, 0, 4 + len(body)) + body

    transforms = transform(not addke, 4, 14)
    n = 1
    if addke:
        transforms += transform(True, 33, 35)  # ADDKE1 carrying group 35 (e.g. ML-KEM)
        n = 2
    prop_body = struct.pack(">BBBB", 0, 1, 0, n) + transforms
    proposal = struct.pack(">BBH", 0, 0, 4 + len(prop_body)) + prop_body
    next_after_sa = ikev2._PL_NOTIFY if intermediate else ikev2._PL_NONE
    sa = struct.pack(">BBH", next_after_sa, 0, 4 + len(proposal)) + proposal
    payloads = sa
    if intermediate:
        nbody = struct.pack(">BBH", 0, 0, ikev2._INTERMEDIATE_EXCHANGE_SUPPORTED)
        payloads += struct.pack(">BBH", ikev2._PL_NONE, 0, 4 + len(nbody)) + nbody
    header = (ikev2._SPI_I + b"\x99" * 8
              + struct.pack(">BBBBII", ikev2._PL_SA, 0x20,
                            ikev2._EXCH_IKE_SA_INIT, 0x20, 0, 28 + len(payloads)))
    return header + payloads


def test_parse_detects_rfc9242_and_rfc9370_signals():
    obs = ikev2.IKEObservation(host="h", port=500, responded=True)
    ikev2._parse(_synthetic_response(intermediate=True, addke=True), obs)
    assert obs.error is None
    assert obs.intermediate_exchange_supported is True
    assert obs.additional_key_exchange  # ADDKE1 observed
    assert any(t.startswith("ADDKE1") for t in obs.selected_transforms)
    assert obs.status == "NOT_YET_VALIDATED"


def test_parse_absent_signals_reported_absent_not_negative():
    obs = ikev2.IKEObservation(host="h", port=500, responded=True)
    ikev2._parse(_synthetic_response(intermediate=False, addke=False), obs)
    assert obs.intermediate_exchange_supported is False
    assert obs.additional_key_exchange == []
    assert obs.status == "NOT_YET_VALIDATED"  # always honest


def test_to_dict_always_carries_status_and_roadmap():
    obs = ikev2.IKEObservation(host="h", port=500)
    d = obs.to_dict()
    assert d["status"] == "NOT_YET_VALIDATED"
    assert "roadmap" in d and "RFC 9370" in d["roadmap"]
