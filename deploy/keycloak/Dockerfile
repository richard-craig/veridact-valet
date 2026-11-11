# Keycloak 26.4 with the Veridact Valet extension baked in, and the marula realm ready to import.
# Built from the repository root:  docker build -f deploy/keycloak/Dockerfile .
# The extension is compiled against this exact Keycloak's own libraries (no Maven Central needed).
ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.4.0

FROM ${KEYCLOAK_IMAGE} AS keycloak

FROM eclipse-temurin:21-jdk AS build
COPY --from=keycloak /opt/keycloak /opt/keycloak
COPY extensions/keycloak-valet /src
RUN cd /src && chmod +x build.sh && KEYCLOAK_HOME=/opt/keycloak ./build.sh

FROM ${KEYCLOAK_IMAGE}
COPY --from=build /src/target/keycloak-valet-0.1.0.jar /opt/keycloak/providers/
COPY deploy/keycloak/marula-realm.json /opt/keycloak/data/import/marula-realm.json
ENV KC_HEALTH_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build --health-enabled=true
