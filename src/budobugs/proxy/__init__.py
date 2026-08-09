"""Unified proxy backend adapters."""

from budobugs.proxy.base import ProxyBackend, ProxyCapabilities, ProxyUnavailable
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.proxy.factory import ProxyBackendFactory, ProxySelection
from budobugs.proxy.har import HarProxyBackend
from budobugs.proxy.playwright_trace import PlaywrightTraceBackend

__all__ = [
    "DirectProxyBackend",
    "HarProxyBackend",
    "PlaywrightTraceBackend",
    "ProxyBackend",
    "ProxyBackendFactory",
    "ProxyCapabilities",
    "ProxySelection",
    "ProxyUnavailable",
]
