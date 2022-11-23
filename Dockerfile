# Use Alpine as base
FROM alpine:3.15

LABEL maintainer = "arnaud.fieffe@lacework.net"

RUN apk update && \
    apk add curl && \
    apk add vim && \
    apk add git
