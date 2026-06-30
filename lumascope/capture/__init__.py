"""Capture backends + on-disk capture formats.

Backends (Frida, USBPcap, SMBus) land in Phases 2/3/6. :mod:`.serialize` defines the
JSON formats now so the decode/emit pipeline can be exercised end-to-end from a saved
corpus, and so backends have a stable shape to write into.
"""
