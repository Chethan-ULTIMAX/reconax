"""
TLS and certificate analysis module.

This module performs a single TLS connection to the target hostname
and collects publicly observable certificate and connection metadata.

It does not perform certificate attacks, cipher enumeration, or
active vulnerability scanning.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..context import AnalysisContext
from ..models import TLSAnalysis
from .base import Module


class TLSModule(Module[TLSAnalysis]):
    """Analyze the target's TLS connection and certificate."""

    name = "tls"

    def _get_target(self) -> tuple[str, int]:
        parsed = urlparse(self.context.normalized_url)

        hostname = parsed.hostname

        if not hostname:
            raise ValueError(
                "Unable to determine hostname for TLS analysis."
            )

        if parsed.port:
            port = parsed.port
        else:
            port = 443

        return hostname, port

    @staticmethod
    def _name_attributes(
        certificate: dict,
        key: str,
    ) -> dict[str, str]:
        result: dict[str, str] = {}

        for item in certificate.get(key, []):
            if not item:
                continue

            name, value = item[0]

            if name and value:
                result[str(name)] = str(value)

        return result

    @staticmethod
    def _subject_alt_names(
        certificate: dict,
    ) -> list[str]:
        names: list[str] = []

        for name_type, value in certificate.get(
            "subjectAltName",
            [],
        ):
            if name_type == "DNS":
                names.append(str(value))

        return names

    @staticmethod
    def _parse_certificate_date(
        value: str | None,
    ) -> datetime | None:
        if not value:
            return None

        try:
            return datetime.strptime(
                value,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None

    def analyze(self) -> TLSAnalysis:
        hostname, port = self._get_target()

        if self.context.normalized_url.startswith("http://"):
            return TLSAnalysis(
                hostname=hostname,
                port=port,
                verdict="INFO",
                flags=[
                    "Target URL uses HTTP rather than HTTPS."
                ],
                explanations=[
                    "TLS analysis applies to HTTPS connections."
                ],
            )

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                (hostname, port),
                timeout=self.context.timeout,
            ) as raw_socket:
                with context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                ) as tls_socket:
                    # The default SSLContext has hostname verification enabled.
                    # A successful handshake therefore means the certificate
                    # hostname was already verified by the TLS stack. Python
                    # 3.14 removed ssl.match_hostname, so do not call it here.
                    certificate = tls_socket.getpeercert()

                    cipher_info = tls_socket.cipher()
                    tls_version = tls_socket.version()

                    cipher_name = (
                        cipher_info[0]
                        if cipher_info
                        else None
                    )

                    subject = self._name_attributes(
                        certificate,
                        "subject",
                    )

                    issuer = self._name_attributes(
                        certificate,
                        "issuer",
                    )

                    sans = self._subject_alt_names(certificate)

                    valid_from = certificate.get("notBefore")
                    valid_until = certificate.get("notAfter")

                    valid_from_dt = self._parse_certificate_date(valid_from)
                    valid_until_dt = self._parse_certificate_date(valid_until)

                    days_remaining: int | None = None

                    if valid_until_dt:
                        days_remaining = (
                            valid_until_dt
                            - datetime.now(timezone.utc)
                        ).days

                    # context.wrap_socket() performs certificate chain and
                    # hostname verification because check_hostname is enabled
                    # on the default context. Reaching this point means the
                    # target hostname matched the verified certificate.
                    hostname_match = True

                    flags: list[str] = []
                    explanations: list[str] = []

                    if days_remaining is not None:
                        if days_remaining < 0:
                            flags.append(
                                "TLS certificate appears to be expired."
                            )
                        elif days_remaining <= 30:
                            flags.append(
                                "TLS certificate expires within 30 days."
                            )

                    if tls_version in {"TLSv1", "TLSv1.1"}:
                        flags.append(
                            f"Legacy TLS version observed: {tls_version}."
                        )

                    if flags:
                        verdict = "WARN"
                    else:
                        verdict = "PASS"

                    return TLSAnalysis(
                        hostname=hostname,
                        port=port,
                        tls_version=tls_version,
                        cipher=cipher_name,
                        subject=subject,
                        issuer=issuer,
                        serial_number=(
                            str(certificate.get("serialNumber"))
                            if certificate.get("serialNumber")
                            else None
                        ),
                        valid_from=valid_from,
                        valid_until=valid_until,
                        days_remaining=days_remaining,
                        hostname_match=hostname_match,
                        subject_alt_names=sans,
                        verdict=verdict,
                        flags=flags,
                        explanations=explanations,
                    )

        except (
            socket.timeout,
            TimeoutError,
        ) as exc:
            return TLSAnalysis(
                hostname=hostname,
                port=port,
                verdict="WARN",
                flags=["TLS connection timed out."],
                error=str(exc),
            )

        except (
            ssl.SSLError,
            OSError,
        ) as exc:
            return TLSAnalysis(
                hostname=hostname,
                port=port,
                verdict="WARN",
                flags=[
                    "Unable to establish a verified TLS connection."
                ],
                explanations=[
                    "The failure may be caused by the target's "
                    "TLS configuration, certificate, network, or "
                    "another connection condition."
                ],
                error=str(exc),
            )
