# Container packaging (NTRO requirement k). The air-gapped single binary stays
# the flagship; this image is the same static binary on a minimal base.
#
#   docker build -t drishti-nexus .
#   docker run --rm --read-only -v /var/log/case:/evidence:ro -v "$PWD/out:/out" \
#     drishti-nexus scan -audit-log /out/audit.log -output /out/report.json /evidence
#
# Evidence is mounted read-only; reports and the audit log go to a separate volume.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# CGO off: SQLite is the pure-Go modernc driver, so the binary is fully static.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X drishti-nexus/internal/version.Version=${VERSION}" -o /out/drishti ./cmd/drishti

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/drishti /usr/local/bin/drishti
COPY configs/ /etc/drishti/configs/
COPY parsers/ /etc/drishti/parsers/
WORKDIR /etc/drishti
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/drishti"]
CMD ["help"]
