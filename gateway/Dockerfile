# syntax=docker/dockerfile:1

# Stage 1: compile. Dependencies are vendored (vendor/), so this step
# needs no internet access.
FROM golang:1.24-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/sentinel ./cmd/sentinel

# Stage 2: the OWASP Core Rule Set, pinned to an exact commit. A changed
# tag on GitHub makes the build fail instead of shipping unknown rules.
FROM alpine:3.20 AS crs
ARG CRS_VERSION=v4.8.0
ARG CRS_COMMIT=3dc7e0dbc971a6622ecc273a34c7febc14145b1c
RUN apk add --no-cache git \
 && git clone --quiet --depth 1 --branch "${CRS_VERSION}" https://github.com/coreruleset/coreruleset.git /crs \
 && test "$(git -C /crs rev-parse HEAD)" = "${CRS_COMMIT}" \
 && mkdir -p /out/crs /out/data && cp -r /crs/rules /crs/LICENSE /out/crs/

# Stage 3: tiny runtime image with only the binary and the rules (no shell,
# no compiler). Less inside means less for an attacker who gets in.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Security gateway for web apps, APIs and AI endpoints: WAF + OWASP CRS + ML" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/tsxmamii/sentinel" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Shield-1.0.0"
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
