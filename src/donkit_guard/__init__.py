"""Donkit Guard: policy checks for LLM traffic and AI-agent actions.

The package is the shared core used both embedded in a runtime and by the
standalone gateway service. Everything here is runtime-agnostic: the host
supplies identity, tools and storage through the adapter interfaces.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("donkit-guard")
except PackageNotFoundError:  # editable checkout without an installed distribution
    __version__ = "0.0.0"

__all__ = ["__version__"]
