FROM alpine:3.21 AS build
RUN apk add --no-cache curl xz
WORKDIR /build
ENV PATH="/usr/local/zig:${PATH}"
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ZIG_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then ZIG_ARCH="aarch64"; fi && \
    curl -fSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/0.14.1/zig-${ZIG_ARCH}-linux-0.14.1.tar.xz" && \
    mkdir -p /usr/local/zig && \
    tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /usr/local/zig && \
    rm /tmp/zig.tar.xz
COPY src/ src/
COPY build.zig .
RUN zig build -Doptimize=ReleaseSafe

FROM alpine:3.21
RUN adduser -D -h /home/ohmz ohmz
COPY --from=build /build/zig-out/bin/ohmz /usr/local/bin/ohmz
USER ohmz
ENTRYPOINT ["ohmz"]
