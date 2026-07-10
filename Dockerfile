FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /auth .

FROM alpine:3.20
RUN adduser -D app
USER app
COPY --from=build /auth /usr/local/bin/auth
EXPOSE 8081
CMD ["auth"]
