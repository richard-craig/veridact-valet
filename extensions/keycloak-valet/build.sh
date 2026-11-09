#!/usr/bin/env bash
# Build without Maven, against a local Keycloak install:  KEYCLOAK_HOME=/opt/keycloak ./build.sh
# (With Maven and access to Maven Central:  mvn -q package)
set -euo pipefail
cd "$(dirname "$0")"
: "${KEYCLOAK_HOME:?set KEYCLOAK_HOME to your Keycloak directory}"
rm -rf target/classes && mkdir -p target/classes
javac --release 17 -nowarn -d target/classes -cp "$KEYCLOAK_HOME/lib/lib/main/*:$KEYCLOAK_HOME/lib/lib/boot/*" $(find src/main/java -name '*.java')
cp -r src/main/resources/* target/classes/
jar --create --file target/keycloak-valet-0.1.0.jar -C target/classes .
echo "built target/keycloak-valet-0.1.0.jar -> copy it to $KEYCLOAK_HOME/providers/ and run kc.sh build (or start-dev)"
