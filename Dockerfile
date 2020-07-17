FROM alpine:latest
RUN apk --no-cache add musl-dev openssl-dev git gcc make

COPY . /tmp/repo
RUN git clone --depth=1 file:///tmp/repo /tmp/build
WORKDIR /tmp/build

RUN ./configure --prefix=/usr && make && make install-strip

FROM alpine:latest
COPY --from=0 /usr/bin/uget /usr/bin/uget

CMD [ "/usr/bin/uget" ]
