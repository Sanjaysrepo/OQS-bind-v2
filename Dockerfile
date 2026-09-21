# OQS-bind built and installed on top of the dependency image.
# e2e/ is not part of the image: docker-compose mounts it at /src/e2e.
# (see Dockerfile.deps).  Used by the end-to-end tests in e2e/.
#
#   docker build -t oqs-bind .
#   docker run --rm -it oqs-bind named -V
ARG DEPS_IMAGE=oqs-bind-deps
FROM ${DEPS_IMAGE}
COPY . /src
WORKDIR /src
RUN autoreconf -fi >/tmp/autoreconf.log 2>&1 \
    && ./configure --disable-doh --without-jemalloc --prefix=/usr/local \
                   --sysconfdir=/etc/bind --localstatedir=/var >/tmp/configure.log 2>&1 \
    && make -j"$(nproc)" >/tmp/make.log 2>&1 \
    && make install >/tmp/install.log 2>&1 \
    && ldconfig \
    && mkdir -p /etc/bind /var/cache/bind /var/run/named /captures /shared \
    && named -V | head -1
ENV PATH=/usr/local/sbin:/usr/local/bin:$PATH
ENTRYPOINT ["bash", "/src/e2e/entrypoint.sh"]
