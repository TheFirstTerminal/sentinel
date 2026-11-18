# syntax=docker/dockerfile:1

# Stage 1: compile. Dependencies are vendored (vendor/), so this step
# needs no internet access.
FROM golang:1.26.11-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/sentinel ./cmd/sentinel

# Stage 2: the OWASP Core Rule Set, pinned to an exact commit. A changed
# tag on GitHub makes the build fail instead of shipping unknown rules.
FROM alpine:3.20 AS crs
ARG CRS_VERSION=v4.25.2
ARG CRS_COMMIT=b9818c3718bc75b99403aed6c4b23773004c5412
RUN apk add --no-cache git \
 && git clone --quiet --depth 1 --branch "${CRS_VERSION}" https://github.com/coreruleset/coreruleset.git /crs \
 && test "$(git -C /crs rev-parse HEAD)" = "${CRS_COMMIT}" \
 && mkdir -p /out/crs /out/data && cp -r /crs/rules /crs/LICENSE /out/crs/

# Stage 3: tiny runtime image with only the binary and the rules (no shell,
# no compiler). Less inside means less for an attacker who gets in.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG DESCRIPTION="Security gateway for web apps, APIs and AI endpoints: WAF + OWASP CRS + ML"
ARG SOURCE="https://github.com/TheFirstTerminal/sentinel"
ARG LICENSE="LicenseRef-PolyForm-Shield-1.0.0"
LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="${LICENSE}"
COPY --from=build /out/sentinel /sentinel
COPY --from=crs /out/crs /etc/sentinel/crs
# Accounts, the secret key, exclusions and certificates. Mount a volume here
# (docker run -v sentinel-data:/var/lib/sentinel) to keep them.
COPY --from=crs --chown=65532:65532 /out/data /var/lib/sentinel
VOLUME /var/lib/sentinel
EXPOSE 8080 8443
# Numeric, so Kubernetes can verify runAsNonRoot (65532 = distroless "nonroot").
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/sentinel", "healthcheck"]
ENTRYPOINT ["/sentinel"]
