"""Emit a recovered :class:`ProtocolSpec` to portable artifacts.

* :mod:`.spec_json` — canonical, round-trippable JSON (the source of truth to archive).
* :mod:`.openrgb_cpp` — an OpenRGB-style ``RGBController`` C++ skeleton ready to drop
  into the LumaCore device tree.
"""

from .openrgb_cpp import render_cpp
from .spec_json import spec_from_dict, spec_to_dict, spec_to_json

__all__ = ["spec_to_dict", "spec_from_dict", "spec_to_json", "render_cpp"]
