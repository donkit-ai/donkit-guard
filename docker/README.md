# Docker images

## `Dockerfile.pii` — `guard-pii`

The NER PII detector service: Presidio with the spaCy `ru_core_news_lg` and `en_core_web_lg`
models, presidio-ru-recognizers, and the tuned recognizers in `services/pii/recognizers.py`.

Build from the repository root:

    docker build -f docker/Dockerfile.pii -t guard-pii:dev .

Run:

    docker run --rm -p 8080:8080 guard-pii:dev

Contract: `POST /v1/analyze` with `{"segments": [{"id": "...", "text": "...", "lang": "ru"}], "deadline_ms": 2000}`
returns `{"detector": "pii-ner", "version": "1", "spans": [...], "failed": false, "error": null}`.
A segment the analyzer cannot process answers `failed: true` with the error class and message
and the spans found so far, so the core reads it as a detector failure instead of as "clean".
`GET /healthz` returns `{"status": "ok"}` once the models are loaded (about 2 s cold start,
about 1.7 GB RSS with the two large models).

`PII_HOST` and `PII_PORT` (default `0.0.0.0:8080`) select the listening address, and the
`HEALTHCHECK` builds its probe URL from `PII_PORT`, so an image started on another port still
reports its real state. The service runs as the unprivileged user `guard` (uid 10001) and
writes nothing at runtime. Analysis runs on a bounded thread pool: a request that misses its
deadline is answered at once, and its worker is not offered to the next request until the
abandoned analysis has really finished.

The image performs no network calls at runtime: models come from release wheels at
build time and the tldextract cache is warmed during the build. Run with
`--network none` to verify; `.github/workflows/pii-image.yml` builds the image and probes it
that way on every change to the service.

## `Dockerfile.standalone` — `guard-standalone`

The standalone service: the HTTP API on 8080 and the gRPC server agentgateway calls on 9090
(ext_proc for the LLM route, ExtMcp for the MCP route). Dependencies are installed from
`poetry.lock`; nothing is downloaded at runtime.

Build from the repository root:

    docker build -f docker/Dockerfile.standalone -t guard-standalone:dev .

It needs a policy file at `/etc/guard/policy.yaml` (or `GUARD_POLICY_FILE`), `GUARD_API_KEYS`,
`GUARD_ADMIN_TOKEN`, and either `GUARD_PII_URL` or `GUARD_PII_DISABLED=true`; the SQLite database
lives on the `/data` volume unless `GUARD_DB_URL` points elsewhere. The service runs as the
unprivileged user `guard` (uid 10001). `docker-compose.yml` in the repository root runs it with
guard-pii and agentgateway; see [docs/standalone.md](../docs/standalone.md).
