"""Phase 3 parser test — turn a saved tshark-JSON fixture into CaptureFrames.

Verifies field-tolerant payload extraction (usbhid.data / usb.capdata / usb.data_fragment,
flat or nested), direction from endpoint address, endpoint number, transfer-type mapping,
VID:PID, and that payload-less packets are skipped. No USBPcap/tshark install needed.
"""
import os

from lumascope.capture.usbpcap_backend import parse_tshark_packets

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "usbpcap_sample.json")


def _frames():
    with open(FIXTURE, encoding="utf-8") as fh:
        return parse_tshark_packets(fh.read())


def test_skips_payloadless_packets():
    frames = _frames()
    # 5 packets in, but packet #5 (a control status read) carries no payload -> 4 frames.
    assert len(frames) == 4


def test_hid_output_report_flat_field():
    f = _frames()[0]
    assert f.data == bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
    assert f.direction == "out"
    assert f.transfer == "interrupt"
    assert f.endpoint == 3
    assert f.vid == 0x1532
    assert f.pid == 0x0226
    assert f.source == "usbpcap"


def test_capdata_nested_field():
    f = _frames()[1]
    assert f.data == bytes([0xAA, 0xBB, 0xCC])
    assert f.direction == "out"
    assert f.transfer == "bulk"
    assert f.endpoint == 2


def test_data_fragment_field_control():
    f = _frames()[2]
    assert f.data == bytes([0xDE, 0xAD, 0xBE, 0xEF])
    assert f.transfer == "control"
    assert f.direction == "out"


def test_inbound_nested_usbhid():
    f = _frames()[3]
    assert f.data == bytes([0xFF, 0xEE])
    assert f.direction == "in"          # endpoint_address.direction == "1"
    assert f.endpoint == 4              # 0x84 & 0x7f


def test_accepts_decoded_list_and_string():
    import json

    with open(FIXTURE, encoding="utf-8") as fh:
        text = fh.read()
    assert len(parse_tshark_packets(text)) == 4          # str input
    assert len(parse_tshark_packets(json.loads(text))) == 4   # already-decoded list
