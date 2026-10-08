"""Priority 6: Infrastructure Relationship & Campaign Detection.

Provides deterministic correlation between multiple analyzed domains to identify
infrastructure clusters and potential campaigns.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def normalize_domain(domain: str) -> str:
    """Normalize a domain name."""
    if not domain:
        return ""
    return domain.strip().lower().rstrip(".")


def normalize_ip(ip: str) -> str:
    """Normalize an IPv4 or IPv6 address."""
    if not ip:
        return ""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ""


def normalize_registrar(registrar: str) -> str:
    """Normalize a registrar string."""
    if not registrar:
        return ""
    return registrar.strip().lower()


def extract_infrastructure(inspection: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized infrastructure entities from an inspection payload."""
    features = inspection.get("features") or {}
    dns = inspection.get("dns") or {}
    ssl = inspection.get("ssl") or {}
    whois = inspection.get("whois") or {}

    infra = {
        "domain": normalize_domain(features.get("hostname", "")),
        "ips": set(),
        "nameservers": set(),
        "registrar": normalize_registrar(whois.get("registrar", "")),
        "certificate": "",
        "certificate_sans": set(),
    }

    if dns.get("status") == "resolved":
        for ip in dns.get("addresses", []):
            norm = normalize_ip(ip)
            if norm:
                infra["ips"].add(norm)

    if whois.get("status") == "success":
        for ns in whois.get("nameservers", []):
            norm = normalize_domain(ns)
            if norm:
                infra["nameservers"].add(norm)

    if ssl.get("status") == "collected":
        issuer = ssl.get("issuer", "")
        serial = ssl.get("serial_number", "")
        if issuer and serial:
            infra["certificate"] = f"{issuer}|{serial}"

        for san in ssl.get("subject_alt_names", []):
            norm = normalize_domain(san)
            if norm:
                infra["certificate_sans"].add(norm)

    return infra


def find_relationships(infra_a: dict[str, Any], infra_b: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare two infrastructure objects and return their relationships."""
    rels = []
    if not infra_a["domain"] or not infra_b["domain"]:
        return rels
    if infra_a["domain"] == infra_b["domain"]:
        return rels  # Do not correlate a domain with itself

    # Strong: Certificate
    if infra_a["certificate"] and infra_a["certificate"] == infra_b["certificate"]:
        rels.append({
            "type": "SHARED_CERTIFICATE",
            "strength": "strong",
            "evidence": "Both domains share the same TLS certificate."
        })

    # Strong: Certificate SAN
    shared_sans = infra_a["certificate_sans"].intersection(infra_b["certificate_sans"])
    if shared_sans:
        # Avoid treating wildcard as identical to everything unless it's literally the same string
        san = sorted(shared_sans)[0]
        rels.append({
            "type": "SHARED_CERTIFICATE_SAN",
            "strength": "strong",
            "evidence": f"Both domains share a certificate SAN relationship ({san})."
        })

    # Medium: IP
    shared_ips = infra_a["ips"].intersection(infra_b["ips"])
    if shared_ips:
        ip = sorted(shared_ips)[0]
        rels.append({
            "type": "SHARED_IP",
            "strength": "medium",
            "evidence": f"Both analyzed domains resolve to the same IP address ({ip})."
        })

    # Medium: Nameserver
    shared_ns = infra_a["nameservers"].intersection(infra_b["nameservers"])
    if shared_ns:
        ns = sorted(shared_ns)[0]
        rels.append({
            "type": "SHARED_NAMESERVER",
            "strength": "medium",
            "evidence": f"Both domains use the same nameserver ({ns})."
        })

    # Weak: Registrar
    if infra_a["registrar"] and infra_a["registrar"] == infra_b["registrar"]:
        rels.append({
            "type": "SHARED_REGISTRAR",
            "strength": "weak",
            "evidence": "Both domains share the same registrar."
        })

    return rels


def analyze_campaign(target_domain: str, inspections: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze campaign correlation across a dataset of inspections."""
    target_domain = normalize_domain(target_domain)
    
    # Extract infrastructure
    infra_list = [extract_infrastructure(i) for i in inspections]
    domain_to_infra = {i["domain"]: i for i in infra_list if i["domain"]}

    if target_domain not in domain_to_infra:
        return {
            "status": "no_correlation",
            "confidence": 0,
            "related_domains": [],
            "relationships": []
        }

    # BFS to find the connected component (cluster)
    visited = {target_domain}
    queue = [target_domain]
    
    unique_rels = {}

    while queue:
        curr = queue.pop(0)
        curr_infra = domain_to_infra[curr]
        
        for other_domain, other_infra in domain_to_infra.items():
            if curr == other_domain:
                continue
                
            rels = find_relationships(curr_infra, other_infra)
            if not rels:
                continue
                
            pair = tuple(sorted([curr, other_domain]))
            if pair not in unique_rels:
                unique_rels[pair] = []
                for r in rels:
                    unique_rels[pair].append({
                        "source_entity": pair[0],
                        "target_entity": pair[1],
                        "type": r["type"],
                        "strength": r["strength"],
                        "evidence": r["evidence"]
                    })
                
                # Only traverse medium or strong relationships to prevent massive clusters from weak links like registrar.
                if any(r["strength"] in ("medium", "strong") for r in rels):
                    if other_domain not in visited:
                        visited.add(other_domain)
                        queue.append(other_domain)

    flat_rels = []
    for pair, rels in unique_rels.items():
        # Only include relationships that connect to our cluster
        if pair[0] in visited or pair[1] in visited:
            flat_rels.extend(rels)

    # Bound outputs to project limits
    flat_rels = flat_rels[:100]
    
    visited.discard(target_domain)
    related_domains = sorted(list(visited))[:50]

    # Calculate bounded campaign confidence
    score = 0
    types_seen = set()
    for r in flat_rels:
        t = r["type"]
        if t in types_seen:
            continue
        types_seen.add(t)
        if r["strength"] == "strong":
            score += 60
        elif r["strength"] == "medium":
            score += 30
        elif r["strength"] == "weak":
            score += 5

    confidence = min(100, score)
    
    status = "no_correlation"
    if flat_rels:
        if confidence < 30:
            status = "weak_correlation"
        elif confidence < 60:
            status = "potential_campaign"
        else:
            status = "strong_campaign_correlation"

    return {
        "status": status,
        "confidence": confidence,
        "related_domains": related_domains,
        "relationships": flat_rels
    }
