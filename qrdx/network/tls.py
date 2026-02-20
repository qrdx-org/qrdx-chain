"""
QRDX TLS Support

Provides SSL/TLS context creation for securing all external interfaces:
- RPC HTTP and WebSocket endpoints
- P2P connections (future)
- Admin interfaces

Supports:
- TLS 1.2 and 1.3
- Server and mutual TLS (mTLS)
- Certificate validation
- HSTS header generation
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TLS context builder
# ---------------------------------------------------------------------------

class TLSContextBuilder:
    """
    Builder for SSL contexts suitable for QRDX node interfaces.

    Usage:
        builder = TLSContextBuilder(
            cert_file="/path/to/cert.pem",
            key_file="/path/to/key.pem",
        )
        ctx = builder.build_server_context()
        # Pass ctx to Uvicorn: ssl_keyfile, ssl_certfile, ssl_context
    """

    def __init__(
        self,
        cert_file: str = "",
        key_file: str = "",
        ca_file: str = "",
        min_version: str = "1.2",
        client_auth: bool = False,
    ):
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.min_version = min_version
        self.client_auth = client_auth

    # -- Validation ---------------------------------------------------------

    def validate(self) -> None:
        """
        Validate that required files exist and are readable.

        Raises:
            ValueError: on missing/invalid files
        """
        if not self.cert_file:
            raise ValueError("cert_file is required for TLS")
        if not self.key_file:
            raise ValueError("key_file is required for TLS")

        cert_path = Path(self.cert_file)
        if not cert_path.exists():
            raise ValueError(f"Certificate file not found: {self.cert_file}")
        if not cert_path.is_file():
            raise ValueError(f"Certificate path is not a file: {self.cert_file}")

        key_path = Path(self.key_file)
        if not key_path.exists():
            raise ValueError(f"Key file not found: {self.key_file}")
        if not key_path.is_file():
            raise ValueError(f"Key path is not a file: {self.key_file}")

        if self.ca_file:
            ca_path = Path(self.ca_file)
            if not ca_path.exists():
                raise ValueError(f"CA file not found: {self.ca_file}")

        if self.min_version not in ("1.2", "1.3"):
            raise ValueError(
                f"Invalid TLS min_version '{self.min_version}'. Must be '1.2' or '1.3'"
            )

    # -- Context builders ---------------------------------------------------

    def build_server_context(self) -> ssl.SSLContext:
        """
        Build an SSL context for a TLS server (RPC, WebSocket).

        Returns:
            Configured ssl.SSLContext
        """
        self.validate()

        # Determine minimum protocol version
        if self.min_version == "1.3":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable known-weak protocols
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1

        # Load certificate chain
        ctx.load_cert_chain(
            certfile=self.cert_file,
            keyfile=self.key_file,
        )

        # CA / client auth
        if self.ca_file:
            ctx.load_verify_locations(cafile=self.ca_file)

        if self.client_auth:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE

        logger.info(
            "TLS server context created: min=%s, client_auth=%s",
            self.min_version,
            self.client_auth,
        )
        return ctx

    def build_client_context(self) -> ssl.SSLContext:
        """
        Build an SSL context for outgoing TLS connections (P2P, bridge).

        Returns:
            Configured ssl.SSLContext
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if self.min_version == "1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable weak protocols
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1

        # Load CA for verifying server certs
        if self.ca_file:
            ctx.load_verify_locations(cafile=self.ca_file)
        else:
            ctx.load_default_certs()

        # If we have a client cert, load it (for mTLS)
        if self.cert_file and self.key_file:
            cert_path = Path(self.cert_file)
            key_path = Path(self.key_file)
            if cert_path.exists() and key_path.exists():
                ctx.load_cert_chain(
                    certfile=self.cert_file,
                    keyfile=self.key_file,
                )

        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        logger.info("TLS client context created: min=%s", self.min_version)
        return ctx

    # -- Uvicorn integration ------------------------------------------------

    def get_uvicorn_ssl_params(self) -> Dict[str, Any]:
        """
        Return keyword arguments for ``uvicorn.run()`` to enable TLS.

        Returns:
            Dict with ssl_keyfile, ssl_certfile, and optionally ssl_ca_certs
        """
        self.validate()
        params: Dict[str, Any] = {
            "ssl_keyfile": self.key_file,
            "ssl_certfile": self.cert_file,
        }
        if self.ca_file:
            params["ssl_ca_certs"] = self.ca_file
        return params


# ---------------------------------------------------------------------------
# HSTS header helper
# ---------------------------------------------------------------------------

def hsts_header(max_age: int = 31536000, include_subdomains: bool = True) -> str:
    """
    Generate an HTTP Strict-Transport-Security header value.

    Args:
        max_age: Duration in seconds (default 1 year)
        include_subdomains: Include subdomains directive

    Returns:
        HSTS header value string
    """
    value = f"max-age={max_age}"
    if include_subdomains:
        value += "; includeSubDomains"
    return value


# ---------------------------------------------------------------------------
# Self-signed certificate generation (for dev/test only)
# ---------------------------------------------------------------------------

def generate_self_signed_cert(
    common_name: str = "localhost",
    days_valid: int = 365,
    key_size: int = 2048,
) -> Tuple[str, str]:
    """
    Generate a self-signed certificate and key for development/testing.

    WARNING: Do NOT use self-signed certificates in production.

    Returns:
        Tuple of (cert_path, key_path) as temp file paths
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
    except ImportError:
        raise ImportError(
            "cryptography package required for self-signed cert generation. "
            "Install: pip install cryptography"
        )

    # Generate RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QRDX Dev"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write to temp files
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem", prefix="qrdx_cert_")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="qrdx_key_")

    with os.fdopen(cert_fd, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with os.fdopen(key_fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    logger.warning(
        "Generated self-signed certificate for '%s' (dev only!): %s",
        common_name,
        cert_path,
    )
    return cert_path, key_path
