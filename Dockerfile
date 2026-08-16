# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGET=./cmd/tunneld
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app $TARGET

FROM gcr.io/distroless/static-debian12 AS tunneld
COPY --from=build /out/app /tunneld
VOLUME ["/data"]
EXPOSE 443 80
ENTRYPOINT ["/tunneld", "-config", "/data/tunneld.yaml"]
