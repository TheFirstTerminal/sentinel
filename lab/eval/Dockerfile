# The evaluation container: the "evaluate" replay tool and sqlmap.
# Built from the repository root: docker compose --profile eval build eval
FROM golang:1.26.11-alpine AS build
WORKDIR /src
COPY gateway/ .
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/evaluate ./cmd/evaluate

FROM python:3.12-slim
# sqlmap from PyPI (the latest release when the image is built).
RUN pip install --no-cache-dir sqlmap
COPY --from=build /out/evaluate /usr/local/bin/evaluate
COPY lab/eval/run.sh /run.sh
ENTRYPOINT ["bash", "/run.sh"]
