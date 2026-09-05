####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

# Local ES 8 port of malice-plugins/pkgs. Passed as an additional build
# context: docker build --build-context pkgs=../malice-plugins
COPY --from=pkgs . /build/malice-plugins/
COPY . /build/pdf/
WORKDIR /build/pdf

# Pure Go wrapper (shells out to the Python analysis script) -> static binary
# so it runs on the glibc-based runtime below.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/pdfscan .

####################################################
# PDF RUNTIME
####################################################
FROM python:3.12-slim

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/pdf.git"
LABEL malice.plugin.category="document"
LABEL malice.plugin.mime="application/pdf"
LABEL malice.plugin.docker.engine="*"

# curl/ca-certificates are needed to fetch the pinned single-file analysis
# tools at build time.
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Jinja2 renders the markdown.
RUN pip install --no-cache-dir "Jinja2==3.1.6"

# The Python analysis entry point and markdown template live in /app.
COPY pdfscan.py markdown.jinja2 /app/

# Pin the exact analysis tools: Didier Stevens' original public-domain
# single-file tools, the same lineage the classic engine vendored (it shipped
# pdfid 0.2.4 and pdf-parser 0.6.8). Neither is on PyPI at these versions, so
# fetch the pinned release from the upstream suite and verify the version
# before continuing (a bad/short download fails the build).
RUN set -eux; \
  curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /app/pdfid.py \
    https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py; \
  curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /app/pdf-parser.py \
    https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py; \
  grep -q "__version__ = '0.2.10'" /app/pdfid.py; \
  grep -q "__version__ = '0.7.14'" /app/pdf-parser.py

COPY --from=go_builder /bin/pdfscan /bin/pdfscan

# /malware is the read-only sample mount point (malice volume -> /malware:ro).
# Run as an unprivileged user: the engine only reads the sample and writes to
# Elasticsearch over the network (embedded-file dumps go to a private temp dir).
RUN useradd -r -u 1000 -m malice \
  && mkdir -p /malware \
  && chown malice:malice /malware

USER malice
WORKDIR /malware

ENTRYPOINT ["pdfscan"]
CMD ["--help"]

####################################################
####################################################
