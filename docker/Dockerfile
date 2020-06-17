FROM debian:stretch
LABEL maintainer="Tiajians Developers <dev@tiajians.com>"
LABEL description="Dockerised TiajiansCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
