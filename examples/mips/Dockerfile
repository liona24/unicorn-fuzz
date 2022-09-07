FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
    gcc-10-mipsel-linux-gnu \
    libc6-dev-mipsel-cross \
    qemu-user-static \
    curl \
    gdb-multiarch \
    ca-certificates \
    python3-minimal \
    binutils \
    file

WORKDIR /home/user

RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

ADD examples/mips/build.sh .
RUN chmod +x build.sh

ADD examples/basic.c .
ADD examples/int_overflow.c .

ENTRYPOINT [ "./build.sh" ]
