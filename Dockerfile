# syntax=docker/dockerfile:1.7

# ─── Build stage ─────────────────────────────────────────────────────────────
# Base images are pinned by digest for reproducible, tamper-evident builds (#41).
# The tag is kept for readability; the digest is what actually resolves. Dependabot
# (.github/dependabot.yml) opens PRs to bump these — do not hand-edit to a floating tag.
FROM maven:3.9-eclipse-temurin-21@sha256:2b4496088e7b80ae10a8c9f74e574ea21380325a006ec684532ad6bad5bc7273 AS build
WORKDIR /app

# Resolve dependencies in a separate layer so they cache across source changes
COPY pom.xml ./
COPY .mvn .mvn
COPY mvnw mvnw
RUN ./mvnw -B dependency:go-offline

# Build the application jar
COPY src ./src
RUN ./mvnw -B clean package -DskipTests

# ─── Runtime stage ───────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre@sha256:273396ed5998598ed1091e8d72711c2d36980a0e65103859c55a4e977a41ffd3
WORKDIR /app

# Run as non-root
RUN groupadd -r luke && useradd -r -g luke luke
USER luke

# Copy the built jar (version pattern matches pom artifactId-version)
COPY --from=build --chown=luke:luke /app/target/luke-auth-engine-*.jar app.jar

# Render injects $PORT at runtime; 8080 is the local default
EXPOSE 8080

# Container-aware JVM sizing; tune MaxRAMPercentage if you upgrade plan
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
