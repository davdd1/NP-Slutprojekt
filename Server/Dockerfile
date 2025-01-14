FROM golang:latest AS build-stage

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /server

# Make the server executable
RUN chmod +x /server

FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /
COPY cert /cert
COPY mosquitto /mosquitto
COPY --from=build-stage /server /server

EXPOSE 9191

ENTRYPOINT [ "/server" ]