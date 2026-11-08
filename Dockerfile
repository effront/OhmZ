FROM alpine:3.21 AS build
RUN apk add --no-cache curl xz
WORKDIR /build
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ZIG_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then ZIG_ARCH="aarch64"; fi && \
    curl -sL "https://ziglang.org/download/0.14.1/zig-linux-${ZIG_ARCH}-0.14.1.tar.xz" \
      | tar -xJ --strip-components=1 -C /usr/local
COPY src/ src/
COPY build.zig .
RUN zig build -Doptimize=ReleaseSafe

FROM alpine:3.21
RUN adduser -D -h /home/ohmz ohmz
COPY --from=build /build/zig-out/bin/ohmz /usr/local/bin/ohmz
USER ohmz
ENTRYPOINT ["ohmz"]
