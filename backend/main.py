from contextlib import asynccontextmanager
import json
import uuid

from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from .config import allowed_target, get_settings
from .crawler.capture import capture
from .crawler.app_inspector import inspect_apk

from .db import (
    close_connections,
    db_health,
    find_threat_indicator,
    get_db_session,
    get_detection_by_id,
    get_detections,
    init_db,
    neo4j_health,
    save_detection,
    save_threat_intel,
)

from .detection.scorer import score
from .evaluation import evaluate_labels
from .graph.builder import (
    add_observation,
    graph_snapshot,
    init_schema,
)
from .graph.cluster import cluster_graph
from .intelligence import analyze_domain
from .models import (
    CaptureRequest,
    DetectionRequest,
    DetectionResponse,
    DiscoverRequest,
    GraphObservation,
)
from .takedown.report import create_report
from .threat_intel import (
    ingest_records,
    load_csv_feed,
    load_json_feed,
)


# ============================================================
# Directories
# ============================================================

for directory in (
    Path("data/captures"),
    Path("data/evidence"),
    Path("data/reports"),
    Path("data/discovered"),
):
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# Application lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await init_schema()

    yield

    await close_connections()


# ============================================================
# FastAPI application
# ============================================================

app = FastAPI(
    title="UPI Shield API",
    version="1.0.0",
    description=(
        "Defensive detection and investigation platform "
        "for suspected payment-brand abuse."
    ),
    lifespan=lifespan,
)


app.mount(
    "/artifacts",
    StaticFiles(directory="data/captures"),
    name="artifacts",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Authentication
# ============================================================

def require_api_key(
    x_api_key: str | None = Header(default=None),
) -> None:

    configured_key = get_settings().admin_api_key

    if configured_key and x_api_key != configured_key:
        raise HTTPException(
            status_code=401,
            detail="Valid X-API-Key header required",
        )


# ============================================================
# Response helpers
# ============================================================

def response_from_record(record) -> DetectionResponse:

    return DetectionResponse(
        id=record.id,
        url=record.url,
        brand=record.brand,
        score=record.score,
        verdict=record.verdict,
        behavioral=record.signals or {},
        evidence=record.evidence or {},
        screenshot=record.screenshot,
        dom=record.dom,
        created_at=record.created_at,
    )


# ============================================================
# Health / root
# ============================================================

@app.get("/", include_in_schema=False)
async def root() -> dict:

    return {
        "name": "UPI Shield API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "online",
    }


@app.get("/health")
async def health() -> dict:

    return {
        "status": "ok",
        "services": {
            "postgres": await db_health(),
            "neo4j": await neo4j_health(),
        },
    }


# ============================================================
# Detection APIs
# ============================================================

@app.get(
    "/detections",
    response_model=list[DetectionResponse],
)
async def list_detections(
    verdict: str | None = None,
) -> list[DetectionResponse]:

    async for session in get_db_session():

        records = await get_detections(
            session,
            verdict=verdict,
        )

    return [
        response_from_record(record)
        for record in records
    ]


@app.post(
    "/detections",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_detection(
    request: DetectionRequest,
) -> DetectionResponse:

    screenshot_path = Path(request.screenshot)
    dom_path = Path(request.dom)

    if not screenshot_path.is_absolute():
        screenshot_path = Path.cwd() / screenshot_path

    if not dom_path.is_absolute():
        dom_path = Path.cwd() / dom_path

    if (
        not screenshot_path.is_file()
        or not dom_path.is_file()
    ):
        raise HTTPException(
            status_code=400,
            detail="Screenshot and DOM files must exist",
        )

    settings = get_settings()

    intel = await analyze_domain(
        str(request.url)
    )

    # --------------------------------------------------------
    # Threat-intelligence lookup
    # --------------------------------------------------------

    ti_match = await find_threat_indicator(
        str(request.url)
    )

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    detection = score(
        str(request.url),
        str(screenshot_path),
        str(dom_path),
        request.brand_keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    async for session in get_db_session():

        record = await save_detection(
            session,
            detection,
            str(screenshot_path),
            str(dom_path),
        )

    return response_from_record(record)


# ============================================================
# Authorized capture pipeline
# ============================================================

async def run_capture(
    url: str,
    keywords: list[str],
) -> DetectionResponse:

    if not allowed_target(url):

        raise HTTPException(
            status_code=403,
            detail=(
                "Target is outside CRAWL_ALLOWLIST; "
                "only explicitly authorized targets may be crawled"
            ),
        )

    capture_result = await capture(url)

    if not capture_result["ok"]:

        raise HTTPException(
            status_code=502,
            detail=capture_result.get(
                "error",
                "capture failed",
            ),
        )

    settings = get_settings()

    intel = await analyze_domain(url)

    # --------------------------------------------------------
    # Threat-intelligence lookup
    # --------------------------------------------------------

    ti_match = await find_threat_indicator(url)

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    # --------------------------------------------------------
    # Detection scoring
    # --------------------------------------------------------

    detection = score(
        url,
        capture_result["screenshot"],
        capture_result["dom"],
        keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    detection["capture"] = {
        key: capture_result.get(key)
        for key in (
            "status",
            "final_url",
            "title",
            "network",
            "redirects",
        )
    }

    # --------------------------------------------------------
    # Save detection
    # --------------------------------------------------------

    async for session in get_db_session():

        record = await save_detection(
            session,
            detection,
            capture_result["screenshot"],
            capture_result["dom"],
        )

    # --------------------------------------------------------
    # Infrastructure graph
    # --------------------------------------------------------

    domain = intel.get("hostname")

    addresses = intel.get(
        "dns",
        {},
    ).get(
        "addresses",
        [],
    )

    cert_sha = intel.get(
        "tls",
        {},
    ).get("sha256")

    if domain:

        await add_observation(
            domain=domain,
            ip=addresses[0] if addresses else None,
            cert_sha=cert_sha,
            brand=detection.get("brand"),
        )

    return response_from_record(record)


@app.post(
    "/captures",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def capture_and_detect(
    request: CaptureRequest,
) -> DetectionResponse:

    return await run_capture(
        str(request.url),
        request.brand_keywords,
    )


# ============================================================
# Screenshot analysis
# ============================================================

@app.post(
    "/analyze-upload",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def analyze_uploaded_screenshot(
    url: str = Form(...),
    brand_keywords: str = Form(""),
    screenshot: UploadFile = File(...),
) -> DetectionResponse:

    if not url.startswith(
        ("http://", "https://")
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "URL must start with "
                "http:// or https://"
            ),
        )

    if screenshot.content_type not in {
        "image/png",
        "image/jpeg",
        "image/webp",
    }:

        raise HTTPException(
            status_code=400,
            detail="Upload a PNG, JPEG, or WebP screenshot",
        )

    content = await screenshot.read()

    if len(content) > (
        get_settings().max_upload_mb
        * 1024
        * 1024
    ):

        raise HTTPException(
            status_code=413,
            detail="Screenshot exceeds upload size limit",
        )

    suffix = Path(
        screenshot.filename or ""
    ).suffix.lower()

    if suffix not in {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
    }:
        suffix = ".png"

    output_dir = Path("data/captures")
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    screenshot_path = (
        output_dir
        / f"upload-{uuid.uuid4().hex}{suffix}"
    )

    screenshot_path.write_bytes(content)

    dom_path = (
        output_dir
        / f"{screenshot_path.stem}.html"
    )

    dom_path.write_text(
        (
            "<html>"
            "<head>"
            "<title>Uploaded analyst screenshot</title>"
            "</head>"
            f'<body data-source-url="{url}">'
            "</body>"
            "</html>"
        ),
        encoding="utf-8",
    )

    keywords = [
        item.strip()
        for item in brand_keywords.split(",")
        if item.strip()
    ]

    intel = await analyze_domain(url)

    # TI lookup for analyst-uploaded evidence
    ti_match = await find_threat_indicator(url)

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    settings = get_settings()

    detection = score(
        url,
        str(screenshot_path),
        str(dom_path),
        keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    async for session in get_db_session():

        record = await save_detection(
            session,
            detection,
            str(screenshot_path),
            str(dom_path),
        )

    return response_from_record(record)


# ============================================================
# Discovery
# ============================================================

@app.post(
    "/discover",
    dependencies=[Depends(require_api_key)],
)
async def discover(
    request: DiscoverRequest,
) -> dict:

    disallowed = [
        str(url)
        for url in request.urls
        if not allowed_target(str(url))
    ]

    if disallowed:

        raise HTTPException(
            status_code=403,
            detail={
                "message": (
                    "Targets must be inside "
                    "CRAWL_ALLOWLIST"
                ),
                "targets": disallowed,
            },
        )

    queue_path = Path(
        "data/discovered/queue.txt"
    )

    queue_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with queue_path.open(
        "a",
        encoding="utf-8",
    ) as stream:

        for url in request.urls:
            stream.write(
                f"{url}\n"
            )

    return {
        "source": request.source,
        "queued": [
            str(url)
            for url in request.urls
        ],
        "count": len(request.urls),
    }


# ============================================================
# APK inspection
# ============================================================

@app.post(
    "/apps/inspect",
    dependencies=[Depends(require_api_key)],
)
async def inspect_app(
    path: str,
) -> dict:

    try:

        return inspect_apk(path)

    except (
        ValueError,
        FileNotFoundError,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.post(
    "/apps/inspect-upload",
    dependencies=[Depends(require_api_key)],
)
async def inspect_app_upload(
    apk: UploadFile = File(...),
) -> dict:

    if not (
        apk.filename or ""
    ).lower().endswith(".apk"):

        raise HTTPException(
            status_code=400,
            detail="Upload an .apk file",
        )

    content = await apk.read()

    if len(content) > (
        get_settings().max_upload_mb
        * 5
        * 1024
        * 1024
    ):

        raise HTTPException(
            status_code=413,
            detail="APK exceeds upload size limit",
        )

    path = (
        Path("data/evidence")
        / f"apk-{uuid.uuid4().hex}.apk"
    )

    path.write_bytes(content)

    try:

        return inspect_apk(path)

    except (
        ValueError,
        FileNotFoundError,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


# ============================================================
# Infrastructure graph
# ============================================================

@app.get("/graph")
async def get_graph() -> dict:

    return await graph_snapshot()


@app.get("/graph/clusters")
async def get_graph_clusters() -> dict:
    """
    Run campaign clustering on the current
    infrastructure graph.

    This is an analytical view only.
    A cluster does not by itself prove that
    all infrastructure belongs to the same
    actor/campaign.
    """

    graph = await graph_snapshot()

    nodes = graph.get(
        "nodes",
        [],
    )

    links = graph.get(
        "links",
        [],
    )

    clusters = cluster_graph(
        nodes=nodes,
        links=links,
    )

    return {
        "clusters": clusters,
        "total_clusters": len(clusters),
        "total_nodes": len(nodes),
        "total_links": len(links),
    }


@app.post(
    "/graph/observations",
    dependencies=[Depends(require_api_key)],
)
async def create_graph_observation(
    observation: GraphObservation,
) -> dict[str, str]:

    await init_schema()

    await add_observation(
        **observation.model_dump()
    )

    return {
        "status": "stored",
        "domain": observation.domain,
    }


# ============================================================
# Evaluation
# ============================================================

@app.get("/evaluation")
async def evaluation() -> dict:

    return evaluate_labels()


# ============================================================
# Detection detail
# ============================================================

@app.get(
    "/detections/{detection_id}",
    response_model=DetectionResponse,
)
async def get_detection(
    detection_id: int,
) -> DetectionResponse:

    async for session in get_db_session():

        record = await get_detection_by_id(
            session,
            detection_id,
        )

    if not record:

        raise HTTPException(
            status_code=404,
            detail="Detection not found",
        )

    return response_from_record(record)


@app.get(
    "/detections/{detection_id}/report"
)
async def detection_report(
    detection_id: int,
) -> Response:

    detection = await get_detection(
        detection_id
    )

    evidence = detection.evidence

    details = [
        f"URL: {detection.url}",
        f"Verdict: {detection.verdict}",
        f"Risk score: {detection.score:.2f}",
        f"Brand: {detection.brand or 'Unidentified'}",
        "",
        "Reasons:",
    ]

    details.extend(
        f"- {reason}"
        for reason in evidence.get(
            "reasons",
            [],
        )
    )

    details += [
        "",
        "Evidence components:",
        str(
            evidence.get(
                "components",
                {},
            )
        ),
        "",
        "Behavioral signals:",
        str(
            detection.behavioral
        ),
    ]

    return Response(
        content=create_report(
            "UPI Shield - Takedown Evidence",
            "\n".join(details),
        ),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f"attachment; "
                f"filename=detection-{detection_id}.pdf"
            )
        },
    )


# ============================================================
# Threat Intelligence
# ============================================================

@app.post(
    "/threat-intel/ingest",
    dependencies=[Depends(require_api_key)],
)
async def ingest_threat_intelligence(
    payload: dict,
) -> dict:

    records = payload.get(
        "indicators"
    )

    if not isinstance(
        records,
        list,
    ):

        raise HTTPException(
            status_code=400,
            detail="'indicators' must be an array",
        )

    if not records:

        raise HTTPException(
            status_code=400,
            detail="'indicators' cannot be empty",
        )

    result = ingest_records(
        records
    )

    saved_count = await save_threat_intel(
        result["accepted"]
    )

    result["saved_count"] = (
        saved_count
    )

    return result