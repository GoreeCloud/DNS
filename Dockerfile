FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod verify && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /dnsd ./cmd/dnsd

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /dnsd /dnsd
COPY config/rules.txt /app/config/rules.txt
EXPOSE 1053/udp 1053/tcp 8080/tcp
USER 65532:65532
ENTRYPOINT ["/dnsd"]
