# syntax=docker/dockerfile:1.7

# ─── Build stage ─────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS build
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
FROM eclipse-temurin:21-jre
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
