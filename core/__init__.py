# SPDX-License-Identifier: MIT
# AetherCore - Pure Python Core Package
import os
import sys

_core_dir = os.path.dirname(os.path.abspath(__file__))
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)