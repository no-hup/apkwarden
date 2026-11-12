# ─── Stage 1: Build ────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /src
COPY gradlew settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY apkwarden-core ./apkwarden-core
COPY apkwarden-cli ./apkwarden-cli

RUN chmod +x gradlew && ./gradlew :apkwarden-cli:fatJar --no-daemon

# ─── Stage 2: Minimal Secure Runtime ───────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

LABEL org.opencontainers.image.title="APKwarden" \
      org.opencontainers.image.description="Fast, reachability-first Android security analyzer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/shaurya/apkwarden"

# Create non-root user
RUN addgroup -g 10001 apkwarden && \
    adduser -D -u 10001 -G apkwarden apkwarden && \
    mkdir -p /opt/apkwarden /workspace && \
    chown -R apkwarden:apkwarden /opt/apkwarden /workspace

WORKDIR /workspace

# Copy fat JAR from builder
COPY --from=builder /src/apkwarden-cli/build/libs/*-all.jar /opt/apkwarden/apkwarden.jar

USER apkwarden:apkwarden

ENTRYPOINT ["java", "-jar", "/opt/apkwarden/apkwarden.jar"]
CMD ["--help"]
