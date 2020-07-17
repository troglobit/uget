FROM alpine:latest
RUN apk --no-cache add musl-dev openssl-dev git automake autoconf gcc make

COPY . /tmp/build
RUN git clone --depth=1 file:///tmp/build /root/build
WORKDIR /root/build

RUN ./autogen.sh && ./configure --prefix=/usr && make && make install-strip

FROM alpine:latest
COPY --from=0 /usr/bin/uget /usr/bin/uget

CMD [ "/usr/bin/uget" ]
