"""NIP-98 authentication gate for HTTP MCP."""

__version__ = "1.0.0"

from .nip98 import AuthError, build_auth_event, verify_authorization_header
from .config import AuthConfig, load_config

__all__ = [
    "AuthConfig",
    "AuthError",
    "build_auth_event",
    "load_config",
    "verify_authorization_header",
    "__version__",
]
