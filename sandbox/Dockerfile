FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl wget ca-certificates gnupg lsb-release apt-utils tzdata sudo procps iproute2 iputils-ping nano bash \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash tester && echo "tester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/tester

WORKDIR /sandbox
COPY sandbox-entry.sh /usr/local/bin/sandbox-entry.sh
RUN chmod +x /usr/local/bin/sandbox-entry.sh

ENTRYPOINT ["/usr/local/bin/sandbox-entry.sh"]
CMD ["bash"]
