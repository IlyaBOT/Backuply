FROM --platform=$BUILDPLATFORM golang:1.26.8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/backuply ./cmd/backuply
RUN mkdir -p /out/state && chmod 0700 /out/state

FROM scratch
COPY --from=build /out/backuply /usr/local/bin/backuply
COPY --from=build --chown=10001:10001 /out/state /var/lib/backuply
USER 10001:10001
EXPOSE 24800
HEALTHCHECK --interval=5s --timeout=5s --start-period=5s --retries=5 \
    CMD ["/usr/local/bin/backuply", "status", "-config", "/etc/backuply/backuply.conf"]
ENTRYPOINT ["/usr/local/bin/backuply"]
CMD ["run", "-config", "/etc/backuply/backuply.conf"]
