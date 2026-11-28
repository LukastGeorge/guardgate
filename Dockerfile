# syntax=docker/dockerfile:1.7
# Một Dockerfile dùng chung cho cả 3 service (D14). Ví dụ:
#   docker build --build-arg MODULE=gateway --build-arg PORT=8080 -t guardgate-gateway:dev .
#
# 3 stage: build (có Maven + JDK) → extract (tách layer) → runtime (chỉ JRE).
# Image cuối KHÔNG chứa Maven, JDK, source code hay file .env: ít thứ để tấn công hơn, nhỏ hơn.

ARG RUNTIME_IMAGE=eclipse-temurin:21-jre-alpine

# ---------- 1. Build ----------
FROM maven:3.9-eclipse-temurin-21 AS build
ARG MODULE
WORKDIR /workspace

# Copy POM trước, tải dependency vào một layer riêng: đổi code không phải tải lại dependency
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY auth-service/pom.xml auth-service/
COPY gateway/pom.xml gateway/
COPY demo-service/pom.xml demo-service/
RUN --mount=type=cache,target=/root/.m2 sh mvnw -B -q -pl "${MODULE}" -am dependency:go-offline

COPY ${MODULE}/src ${MODULE}/src
RUN --mount=type=cache,target=/root/.m2 sh mvnw -B -q -pl "${MODULE}" -am package -DskipTests \
 && cp "${MODULE}/target/${MODULE}-"*.jar /workspace/app.jar

# ---------- 2. Tách layered jar ----------
# Layer ít thay đổi (dependencies) nằm dưới, code app nằm trên cùng: push/pull image chỉ tải layer đã đổi.
FROM ${RUNTIME_IMAGE} AS extract
WORKDIR /extract
COPY --from=build /workspace/app.jar app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --launcher --destination layers

# ---------- 3. Runtime ----------
FROM ${RUNTIME_IMAGE} AS runtime
ARG MODULE
ARG PORT
ARG REVISION=unknown
LABEL org.opencontainers.image.title="guardgate-${MODULE}" \
      org.opencontainers.image.source="https://github.com/LukastGeorge/guardgate" \
      org.opencontainers.image.revision="${REVISION}"

# User không có quyền root, không có home, không có shell đăng nhập
RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app -s /sbin/nologin app

WORKDIR /app
# File thuộc root, user 10001 chỉ đọc được => kẻ tấn công chiếm được app cũng không sửa được code
COPY --from=extract /extract/layers/dependencies/ ./
COPY --from=extract /extract/layers/spring-boot-loader/ ./
COPY --from=extract /extract/layers/snapshot-dependencies/ ./
COPY --from=extract /extract/layers/application/ ./

# ARG không tồn tại lúc chạy; HEALTHCHECK cần ENV
ENV PORT=${PORT}
EXPOSE ${PORT}
USER 10001:10001

HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=5 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/actuator/health/readiness" || exit 1

# Exec form: java là PID 1, nhận SIGTERM trực tiếp để shutdown gọn
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-Djava.io.tmpdir=/tmp", \
            "org.springframework.boot.loader.launch.JarLauncher"]
