#!/bin/bash

set -e
cd "$(dirname "$0")"

# --- Configuration ---
MAIN_CLASS="org.liuzx.jce.demo.Main"
LIB_DIR="target/lib"

# Locate the packaged main JAR (version agnostic; exclude -sources/-javadoc).
MAIN_JAR="$(ls -1t target/liuzx-sdf-jce-*.jar 2>/dev/null \
    | grep -vE -- '-(sources|javadoc)\.jar$' \
    | head -n1 || true)"

# --- Environment Variables ---
export LC_ALL=zh_CN.utf8
export LANG=zh_CN.utf8
export TZ=Asia/Shanghai

# --- Java Options ---
JAVA_OPTS="-Dfile.encoding=UTF-8"

# --- Pre-flight Checks ---
if [ -z "$MAIN_JAR" ] || [ ! -f "$MAIN_JAR" ]; then
    echo "Error: Main JAR file not found under target/."
    echo "Please run 'mvn clean package' first."
    exit 1
fi

# --- Build Classpath ---
# Start with the main application JAR itself
CP="$MAIN_JAR"

# Add all JARs from the lib directory to the classpath
if [ -d "$LIB_DIR" ]; then
    for jar in "$LIB_DIR"/*.jar; do
        if [ -e "$jar" ]; then
          CP="$CP:$jar"
        fi
    done
fi

# --- Execution ---
echo "Starting JCE Demo Application..."
echo "Classpath: $CP"

java $JAVA_OPTS -cp "$CP" "$MAIN_CLASS" "$@"
