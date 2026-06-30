"""Stimulus layer: drive a device/app through a controlled state matrix.

:mod:`lumascope.stimulus.matrix` is backend-agnostic and is used both to drive real
hardware (Phase 4) and to fabricate synthetic captures (:mod:`lumascope.synthetic`).
The driver implementations (OpenRGB / REST / pywinauto / image-match) land in Phase 4.
"""
