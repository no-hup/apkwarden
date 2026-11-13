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
      org.opencontainers.image.source="https://github.com/no-hup/apkwarden"

# Install git and bash for diff --git-ref and script capabilities
RUN apk add --no-cache git bash ca-certificates && \
    mkdir -p /opt/apkwarden /workspace && \
    chmod 777 /workspace

WORKDIR /workspace

# Copy fat JAR from builder
COPY --from=builder /src/apkwarden-cli/build/libs/*-all.jar /opt/apkwarden/apkwarden.jar

ENTRYPOINT ["java", "-jar", "/opt/apkwarden/apkwarden.jar"]
CMD ["--help"]
