"""Inspection endpoints.

- POST /api/v1/inspect            Phase 1 scoring (+ optional Phase 2A collection, Phase 2C intelligence)
- GET  /api/v1/inspections        list recent inspections
- GET  /api/v1/inspections/{id}   retrieve a persisted inspection
"""

import dataclasses
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collection.collector import collect as collect_url
from app.collection.screenshot import capture_screenshot
from app.core.dns_intelligence import inspect_hostname
from app.core.domain_intelligence import derive_domain_intelligence
from app.core.fusion import fuse_intelligence
from app.core.llm import analyze_webpage
from app.core.ocr import extract_text
from app.core.ssl_intelligence import collect_ssl, not_applicable
from app.core.whois_intelligence import query_whois
from app.db.session import get_db
from app.engine.features import extract_features
from app.engine.parser import MalformedURLError
from app.engine.scorer import score_features
from app.models import Inspection
from app.schemas.inspection import InspectRequest, InspectionResponse

router = APIRouter()

DEFAULT_LIST_LIMIT = 20
MAX_LIST_LIMIT = 100


def _to_response(inspection: Inspection) -> InspectionResponse:
    """Build the API response from a persisted inspection record."""
    return InspectionResponse(
        id=inspection.id,
        url=inspection.url,
        status=inspection.status,
        score=inspection.score if inspection.score is not None else 0,
        classification=inspection.classification or "",
        features=json.loads(inspection.features_json or "{}"),
        reasons=json.loads(inspection.reasons_json or "[]"),
        collection=(
            json.loads(inspection.collection_json)
            if inspection.collection_json is not None
            else None
        ),
        dns=(
            json.loads(inspection.dns_data) if inspection.dns_data is not None else None
        ),
        ssl=(
            json.loads(inspection.ssl_data) if inspection.ssl_data is not None else None
        ),
        whois=(
            json.loads(inspection.whois_data)
            if inspection.whois_data is not None
            else None
        ),
        intelligence=(
            json.loads(inspection.intelligence_json)
            if inspection.intelligence_json is not None
            else None
        ),
        screenshot=(
            json.loads(inspection.screenshot_data)
            if inspection.screenshot_data is not None
            else None
        ),
        ocr=(
            json.loads(inspection.ocr_data)
            if inspection.ocr_data is not None
            else None
        ),
        llm=(
            json.loads(inspection.llm_data)
            if inspection.llm_data is not None
            else None
        ),
        created_at=inspection.created_at,
        updated_at=inspection.updated_at,
    )


def _run_intelligence_pipeline(
    *,
    url: str,
    hostname: str,
    scheme: str,
    features_dict: dict,
    collection: dict | None,
    dns: dict | None,
    score: int,
    classification: str,
) -> tuple[dict | None, dict | None, dict | None, dict | None, dict | None, dict | None]:
    """Run the Phase 2C intelligence pipeline.

    Returns (ssl_data, whois_data, intelligence_summary).
    SSL intelligence only runs for HTTPS URLs after SSRF validation passes.
    """
    # Phase 2C: SSL intelligence
    if scheme == "https":
        ssl_data = collect_ssl(hostname)
    else:
        ssl_data = not_applicable(hostname)

    # Phase 2C: WHOIS stub
    whois_data = query_whois(hostname)

    # Phase 2D: Secure Screenshot Acquisition
    if dns and dns.get("status") in ("error", "timeout"):
        screenshot_data = {
            "status": "not_run",
            "reason": "dns_resolution_failed",
            "url": url,
        }
    else:
        screenshot_data = capture_screenshot(url)

    # Phase 2D: Secure OCR Extraction
    ocr_data = None
    if screenshot_data and screenshot_data.get("status") == "collected":
        image_id = screenshot_data.get("image_id")
        if image_id:
            ocr_data = extract_text(image_id)
        else:
            ocr_data = {"status": "failed", "reason": "invalid_image"}
    else:
        ocr_data = {
            "status": "not_run",
            "reason": "screenshot_unavailable",
        }

    # Phase 2D: Secure LLM-Based Webpage Understanding
    llm_data = analyze_webpage(url=url, html_stats=collection, ocr_data=ocr_data)

    # Phase 2C: Domain intelligence hints
    domain_intel = derive_domain_intelligence(
        features=features_dict,
        collection=collection,
        dns=dns,
        ssl_data=ssl_data,
    )

    # Phase 2C: Fusion engine
    intelligence = fuse_intelligence(
        score=score,
        classification=classification,
        features=features_dict,
        collection=collection,
        dns=dns,
        ssl_data=ssl_data,
        whois_data=whois_data,
        screenshot_data=screenshot_data,
        ocr_data=ocr_data,
        domain_intelligence=domain_intel,
        llm_data=llm_data,
        # LLM data is advisory, doesn't change Phase 1 score, just returned and stored.
    )

    return ssl_data, whois_data, screenshot_data, ocr_data, llm_data, intelligence


@router.post("/inspect", response_model=InspectionResponse)
def inspect_url(payload: InspectRequest, db: Session = Depends(get_db)) -> InspectionResponse:
    """Inspect a URL with the deterministic Phase 1 engine and persist it.

    When ``collect`` is true, safe HTTP/HTML collection runs for eligible URLs
    (SSRF-checked before any connection); otherwise collection is absent.

    When ``intelligence`` is true, Phase 2C intelligence enrichment runs
    (SSL, domain hints, WHOIS stub, fusion); otherwise Phase 2C is skipped.
    """
    try:
        features = extract_features(payload.url)
    except MalformedURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    outcome = score_features(features)

    collection = collect_url(payload.url) if payload.collect else None
    # DNS intelligence is informational; it never affects Phase 1 scoring or
    # Phase 2A SSRF decisions.
    dns = inspect_hostname(features.hostname)

    # Phase 2C: Intelligence pipeline (only when requested)
    ssl_data = None
    whois_data = None
    screenshot_data = None
    ocr_data = None
    llm_data = None
    intelligence = None
    if payload.intelligence:
        ssl_data, whois_data, screenshot_data, ocr_data, llm_data, intelligence = _run_intelligence_pipeline(
            url=features.url,
            hostname=features.hostname,
            scheme=features.scheme,
            features_dict=dataclasses.asdict(features),
            collection=collection,
            dns=dns,
            score=outcome.score,
            classification=outcome.classification,
        )

        # Priority 6: Campaign Detection
        from app.core.campaign import analyze_campaign
        recent_rows = db.scalars(
            select(Inspection).order_by(Inspection.id.desc()).limit(100)
        ).all()
        historical = []
        for r in recent_rows:
            historical.append({
                "features": json.loads(r.features_json or "{}"),
                "dns": json.loads(r.dns_data) if r.dns_data else {},
                "ssl": json.loads(r.ssl_data) if r.ssl_data else {},
                "whois": json.loads(r.whois_data) if r.whois_data else {},
            })
        
        historical.append({
            "features": dataclasses.asdict(features),
            "dns": dns or {},
            "ssl": ssl_data or {},
            "whois": whois_data or {},
        })
        
        campaign_data = analyze_campaign(features.hostname, historical)
        
        # Priority 7: Explainability Layer
        if intelligence:
            from app.core.explainability import build_explanation
            intelligence = build_explanation(intelligence, campaign_data)

    inspection = Inspection(
        url=features.url,
        status="completed",
        score=outcome.score,
        classification=outcome.classification,
        features_json=json.dumps(dataclasses.asdict(features)),
        reasons_json=json.dumps(list(outcome.reasons)),
        collection_json=(
            json.dumps(collection) if collection is not None else None
        ),
        dns_data=json.dumps(dns) if dns is not None else None,
        ssl_data=json.dumps(ssl_data) if ssl_data is not None else None,
        whois_data=json.dumps(whois_data) if whois_data is not None else None,
        screenshot_data=json.dumps(screenshot_data) if screenshot_data is not None else None,
        ocr_data=json.dumps(ocr_data) if ocr_data is not None else None,
        llm_data=json.dumps(llm_data) if llm_data is not None else None,
        intelligence_json=json.dumps(intelligence) if intelligence is not None else None,
    )
    db.add(inspection)
    db.commit()
    db.refresh(inspection)

    return _to_response(inspection)


@router.get("/inspections", response_model=list[InspectionResponse])
def list_inspections(
    limit: int = DEFAULT_LIST_LIMIT, db: Session = Depends(get_db)
) -> list[InspectionResponse]:
    """List recent inspections, newest first, including collection evidence."""
    limit = max(1, min(limit, MAX_LIST_LIMIT))
    rows = db.scalars(
        select(Inspection).order_by(Inspection.id.desc()).limit(limit)
    ).all()
    return [_to_response(inspection) for inspection in rows]


@router.get("/inspections/{inspection_id}", response_model=InspectionResponse)
def get_inspection(
    inspection_id: int, db: Session = Depends(get_db)
) -> InspectionResponse:
    """Retrieve a persisted inspection by id, including collection evidence."""
    inspection = db.get(Inspection, inspection_id)
    if inspection is None:
        raise HTTPException(status_code=404, detail="Inspection not found")
    return _to_response(inspection)
