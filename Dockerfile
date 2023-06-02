# Use Alpine as base
FROM alpine:3.16

LABEL maintainer = "clayton.sopel@lacework.net"

RUN apk update && \
    apk add curl && \
    apk add vim && \
    apk add git
