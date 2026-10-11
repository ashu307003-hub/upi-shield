# UPI Shield build status

## Working in the supplied repository

- Docker PostgreSQL 16 / Neo4j 5 / Redis 7 configuration
- FastAPI service with Swagger
- Next.js analyst dashboard
- PostgreSQL persistence
- Neo4j graph observations and fallback graph projection
- Playwright authorized capture pipeline
- Screenshot upload analysis
- pHash visual similarity against local brand references
- Optional Tesseract OCR extraction
- Behavioral DOM analysis for forms, sensitive fields, redirects, iframes and external resources
- URL lexical intelligence
- DNS resolution
- TLS certificate metadata and SHA-256 fingerprint
- RDAP domain registration enrichment for public domains
- Explainable weighted risk scoring
- Detection detail/evidence viewer
- PDF evidence/takedown report
- Static APK metadata inspection, including upload endpoint
- Labelled evaluation with precision, recall, F1 and false-positive rate
- Campaign/infrastructure graph

## Validation performed here

- Python backend source passed `python -m compileall`.
- The existing local environment shown by the user already reached FastAPI startup, `/health` 200 and `/docs` 200.
- The UI shown by the user successfully loaded at `localhost:3000`.

## Important limitation

A production-quality deep-learning classifier/embedding model cannot honestly be claimed from the current five-row labelled dataset. The delivered system therefore exposes deterministic pHash/OCR/behavioral/domain features and an explainable score. A trained embedding/classifier should be added after a substantially larger labelled corpus is collected and split by campaign/time to avoid leakage.

## Next engineering phase

- Add analyst authentication/RBAC and audit logging.
- Add Celery workers and isolated browser execution.
- Add approved CT/TI/RDAP/provider connectors.
- Add object storage and evidence hashes.
- Build campaign clustering jobs from Neo4j.
- Train/calibrate the ML model on a real labelled corpus.
- Add CI, API tests, frontend tests and container scanning.
