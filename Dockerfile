FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -mod=vendor -trimpath -ldflags="-s -w" -o /yandex2mqtt ./cmd/yandex2mqtt

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /yandex2mqtt /yandex2mqtt
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/yandex2mqtt"]
CMD ["-config", "/app/config.json"]
