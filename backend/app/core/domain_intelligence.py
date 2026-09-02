"""Domain intelligence hints (Phase 2C).

Pure Python logic that derives informational signals from existing intelligence
sources. Generates INFORMATIONAL signals only — never changes the Phase 1
score, never creates a competing classifier, and never performs network
operations.

Sources:
- Phase 1 features
- Phase 2A collection evidence
- Phase 2B DNS intelligence
- Phase 2C SSL intelligence
"""

from __future__ import annotations

from typing import Any


def derive_domain_intelligence(
    *,
    features: dict[str, Any] | None = None,
    collection: dict[str, Any] | None = None,
    dns: dict[str, Any] | None = None,
    ssl_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive domain intelligence signals from all available sources.

    Returns a structured dict with:

    - ``signals`` — list of detected informational signals
    - ``risk_hints`` — list of risk hint strings
    - ``reasoning`` — human-readable reasoning for each signal

    Never modifies the Phase 1 score or classification.
    """
    features = features or {}
    collection = collection or {}
    dns = dns or {}
    ssl_data = ssl_data or {}

    signals: list[dict[str, str]] = []
    risk_hints: list[str] = []
    reasoning: list[str] = []

    # --- SSL-based signals ---
    if ssl_data:
        status = ssl_data.get("status", "")
        if status == "collected":
            if ssl_data.get("is_expired"):
                signals.append({
                    "type": "expired_certificate",
                    "severity": "high",
                    "source": "ssl",
                })
                risk_hints.append("SSL certificate is expired")
                reasoning.append(
                    "The SSL certificate has expired, indicating the site may "
                    "be abandoned or misconfigured."
                )

            if ssl_data.get("is_self_signed"):
                signals.append({
                    "type": "self_signed_certificate",
                    "severity": "medium",
                    "source": "ssl",
                })
                risk_hints.append("SSL certificate is self-signed")
                reasoning.append(
                    "The certificate is self-signed rather than issued by a "
                    "recognized Certificate Authority."
                )

            if ssl_data.get("hostname_match") is False:
                signals.append({
                    "type": "hostname_mismatch",
                    "severity": "high",
                    "source": "ssl",
                })
                risk_hints.append("Hostname mismatch with SSL certificate")
                reasoning.append(
                    "The hostname does not match the certificate's Subject "
                    "Alternative Names or Common Name, suggesting possible "
                    "misconfiguration or impersonation."
                )

            age_days = ssl_data.get("cert_age_days")
            if age_days is not None and age_days < 30:
                signals.append({
                    "type": "very_new_certificate",
                    "severity": "medium",
                    "source": "ssl",
                })
                risk_hints.append(f"SSL certificate is only {age_days} days old")
                reasoning.append(
                    f"The certificate was issued {age_days} day(s) ago, which "
                    "is unusually new and common for short-lived phishing sites."
                )

        elif status == "timeout":
            signals.append({
                "type": "ssl_timeout",
                "severity": "low",
                "source": "ssl",
            })
            reasoning.append(
                "SSL connection timed out, which may indicate network issues "
                "or a non-responsive server."
            )

        elif status == "error":
            signals.append({
                "type": "ssl_error",
                "severity": "low",
                "source": "ssl",
            })
            reasoning.append(
                f"SSL connection failed: {ssl_data.get('reason', 'unknown')}"
            )

    # --- DNS-based signals ---
    if dns:
        if dns.get("all_private"):
            signals.append({
                "type": "all_private_dns",
                "severity": "medium",
                "source": "dns",
            })
            risk_hints.append("All DNS addresses are private/local")
            reasoning.append(
                "Every resolved address is private or local, which is "
                "unusual for a publicly accessible website."
            )
        elif dns.get("has_private"):
            signals.append({
                "type": "mixed_private_public_dns",
                "severity": "low",
                "source": "dns",
            })
            reasoning.append(
                "Some resolved addresses are private, which may indicate "
                "DNS configuration issues."
            )

        if dns.get("status") == "error":
            signals.append({
                "type": "dns_resolution_error",
                "severity": "medium",
                "source": "dns",
            })
            risk_hints.append("DNS resolution failed")
            reasoning.append(
                "The hostname could not be resolved, which is suspicious "
                "for a website."
            )

    # --- Collection-based signals ---
    if collection:
        status = collection.get("status", "")
        if status == "blocked":
            signals.append({
                "type": "collection_blocked",
                "severity": "low",
                "source": "collection",
            })
            reasoning.append(
                f"Collection was blocked: {collection.get('reason', 'unknown')}"
            )
        elif status == "collected":
            html = collection.get("html") or {}
            if html.get("password_input_count", 0) > 0:
                signals.append({
                    "type": "password_form_detected",
                    "severity": "medium",
                    "source": "collection",
                })
                risk_hints.append("Password input form detected")
                reasoning.append(
                    "The page contains a password input field, which is "
                    "common on login pages but also on phishing sites."
                )

            if html.get("form_count", 0) > 0 and html.get("script_count", 0) > 2:
                signals.append({
                    "type": "forms_with_heavy_scripts",
                    "severity": "low",
                    "source": "collection",
                })
                reasoning.append(
                    "The page contains forms alongside multiple script tags, "
                    "which may indicate dynamic form behavior."
                )

            if collection.get("http_status", 200) >= 400:
                signals.append({
                    "type": "error_http_status",
                    "severity": "low",
                    "source": "collection",
                })
                reasoning.append(
                    f"The server returned HTTP status {collection.get('http_status')}."
                )

    # --- Feature-based signals ---
    if features:
        if features.get("is_ip_hostname"):
            signals.append({
                "type": "ip_based_hostname",
                "severity": "medium",
                "source": "features",
            })
            risk_hints.append("Hostname is a raw IP address")
            reasoning.append(
                "The URL uses a raw IP address as the hostname rather than "
                "a domain name."
            )

        if features.get("is_suspicious_tld"):
            signals.append({
                "type": "suspicious_tld",
                "severity": "medium",
                "source": "features",
            })
            risk_hints.append(
                f"Suspicious top-level domain: .{features.get('tld', '?')}"
            )
            reasoning.append(
                f"The TLD .{features.get('tld', '?')} is frequently abused "
                "by phishing campaigns."
            )

        keywords = features.get("suspicious_keywords", ())
        if keywords:
            signals.append({
                "type": "suspicious_keywords",
                "severity": "medium",
                "source": "features",
            })
            risk_hints.append(
                f"Suspicious keywords found: {', '.join(keywords)}"
            )
            reasoning.append(
                f"The URL contains phishing-associated keywords: "
                f"{', '.join(keywords)}."
            )

    return {
        "signals": signals,
        "risk_hints": risk_hints,
        "reasoning": reasoning,
    }
