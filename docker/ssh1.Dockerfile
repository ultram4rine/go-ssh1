FROM alpine:3.17.0 as builder

WORKDIR "/ssh1"

RUN apk update &&\
    apk add --no-cache gcc make musl-dev perl wget zlib-dev &&\
    apk del fortify-headers

RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz &&\
    wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.3p1.tar.gz

RUN echo "ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16  openssl-1.0.2u.tar.gz" | sha256sum -c &&\
    echo "$(echo "P/uYmm3KppWUw7VQ1IVaWi4XGMzd5/XjY4e0JCIPvsw=" | base64 -d | xxd -p -c 256)  openssh-7.3p1.tar.gz" | sha256sum -c

RUN tar -xf openssl-1.0.2u.tar.gz -C . &&\
    tar -xf openssh-7.3p1.tar.gz -C .

WORKDIR "/ssh1/openssl-1.0.2u"
RUN ./config --prefix=/opt --openssldir=/opt/openssl
RUN make --silent &&\
    make --silent test &&\
    make --silent install

WORKDIR "/ssh1/openssh-7.3p1"
RUN ./configure --prefix=/opt --with-ssh1 --with-ssl-dir=/opt
RUN make --silent &&\
    make --silent install

RUN sed -i 's/#Protocol 2/Protocol 1/g' /opt/etc/sshd_config &&\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/g' /opt/etc/sshd_config

FROM golang:1.17-alpine3.15

COPY --from=builder /opt /opt

RUN echo "root:alpine" | chpasswd

CMD /opt/sbin/sshd -p 2222