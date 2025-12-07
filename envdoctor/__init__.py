"""ENVDOCTOR — .env validator, secret-presence and config-drift checker."""
from envdoctor.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
