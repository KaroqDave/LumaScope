"""Device-discovery ranking. Enumeration itself needs Windows; the ranking does not."""

import sys

import pytest

from lumascope import devices
from lumascope.devices import DeviceInfo


def d(vid=None, pid=None, product="", manufacturer="", path="p") -> DeviceInfo:
    return DeviceInfo(path=path, vid=vid, pid=pid, product=product, manufacturer=manufacturer)


def test_a_named_lighting_device_outranks_a_bare_vendor_match():
    """The real failure this guards: an ASUS AURA controller ranking below a Logitech
    virtual driver merely because both vendors appear in the VID table."""
    aura = d(0x0B05, 0x19AF, "AURA LED Controller")
    other = d(0x046D, 0x4099, "HID VHF Driver")
    assert aura.score > other.score
    assert sorted([other, aura], key=lambda x: -x.score)[0] is aura


def test_led_matches_as_a_word_not_a_substring():
    assert d(product="AURA LED Controller").score > d(product="Bundled Receiver").score
    assert not devices._LIGHT_WORDS.search("Bundled Receiver")


def test_unknown_vendor_with_a_lighting_name_still_ranks():
    assert d(0x9999, 0x0001, "Generic RGB Strip").interesting()


def test_plain_device_is_not_flagged():
    assert not d(0x9999, 0x0001, "USB Audio").interesting()


def test_dedupe_keeps_the_most_descriptive_interface():
    dupes = [
        d(0x046D, 0xC339, "", path="a"),
        d(0x046D, 0xC339, "PRO Gaming Keyboard", path="b"),
    ]
    (kept,) = devices.dedupe(dupes)
    assert kept.product == "PRO Gaming Keyboard"


def test_ids_render_as_padded_hex():
    assert d(0x0B05, 0x19AF).ids == "0b05:19af"
    assert d().ids == "????:????"


def test_vendor_name_lookup():
    assert d(0x0B05, 0x19AF).vendor_name == "ASUS"
    assert d(0x9999, 0x1).vendor_name == ""


def test_report_never_raises_and_stays_ascii():
    text = devices.report()
    text.encode("ascii")
    assert "LumaScope devices" in text


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows guidance path")
def test_report_off_windows_explains_the_alternative():
    assert "Windows-only" in devices.report()


@pytest.mark.skipif(sys.platform != "win32", reason="needs the Windows HID stack")
def test_enumeration_returns_devices_on_windows():
    """Guards the 64-bit handle bug: without explicit ctypes argtypes this raised
    'int too long to convert' and silently reported no devices at all."""
    found = devices.list_devices()
    assert found, "expected at least one HID device on a Windows machine"
    assert all(dev.path for dev in found)
