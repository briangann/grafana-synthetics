FROM debian:stretch

USER root

RUN apt-get update && apt-get install -y wget curl sudo procps net-tools
RUN curl -s https://packagecloud.io/install/repositories/raintank/raintank/script.deb.sh | sudo bash
RUN sudo apt-get install carbon-relay-ng=0.10.1-59-g6080fb1-1

RUN mkdir -p /etc/carbon-relay-ng

COPY carbon-relay-ng.conf /etc/carbon-relay-ng/
COPY storage-schemas.conf /etc/carbon-relay-ng/

EXPOSE 2003 2013

CMD exec /bin/sh -c "/usr/bin/carbon-relay-ng /etc/carbon-relay-ng/carbon-relay-ng.conf"
