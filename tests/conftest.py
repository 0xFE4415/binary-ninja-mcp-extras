"""Test configuration: always run against the fake binaryninja package."""

import os

from helpers import install_fake_binaryninja
from hypothesis import settings

settings.register_profile("mutmut", max_examples=10)
if os.environ.get("HYPOTHESIS_PROFILE") == "mutmut":
    settings.load_profile("mutmut")

install_fake_binaryninja()

import binja_plugin  # noqa: E402,F401  (imported after the fake is installed so tools register)
