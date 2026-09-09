"""
ReconAx analysis modules.

Modules are intentionally exported here so applications can import
individual analyzers from one predictable namespace.
"""

from .base import Module
from .http import HTTPModule
from .headers import HeadersModule
from .cookies import CookiesModule
from .html import HTMLModule
from .robots import RobotsModule
from .dns import DNSModule

# The following modules are part of the v0.2.0 architecture and will
# be implemented in the next batch.
#
# from .tls import TLSModule
# from .tech import TechModule
# from .sitemap import SitemapModule
# from .cors import CORSModule
# from .csp import CSPModule
# from .sri import SRIModule
# from .security_txt import SecurityTxtModule
# from .metadata import MetadataModule
# from .resources import ResourcesModule
# from .endpoints import EndpointsModule
# from .attack_surface import AttackSurfaceModule
# from .score import ScoreModule


__all__ = [
    "Module",
    "HTTPModule",
    "HeadersModule",
    "CookiesModule",
    "HTMLModule",
    "RobotsModule",
    "DNSModule",
]