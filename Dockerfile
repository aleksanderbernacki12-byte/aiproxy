# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /aiproxy ./cmd/aiproxy

# distroless/static's nonroot variant: no shell, no package manager, and
# runs as an unprivileged user by default — fitting for a proxy whose
# whole job is handling secrets. Its ca-certificates are what let aiproxy
# verify the upstream's TLS certificate on the new HTTPS connection.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /aiproxy /aiproxy
WORKDIR /config
EXPOSE 8080
ENTRYPOINT ["/aiproxy"]
