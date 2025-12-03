#!/bin/bash

set -e
cd "$(dirname "$0")"

# --- Configuration ---
MAIN_JAR="target/liuzx-sdf-jce-1.0-SNAPSHOT.jar"
LIB_DIR="target/lib"
MAIN_CLASS="org.liuzx.jce.demo.Main"

# --- Environment Variables ---
export LC_ALL=zh_CN.utf8
export LANG=zh_CN.utf8
export TZ=Asia/Shanghai

# --- Java Options ---
JAVA_OPTS="-Dfile.encoding=UTF-8"

# --- Pre-flight Checks ---
if [ ! -f "$MAIN_JAR" ]; then
    echo "Error: Main JAR file not found at $MAIN_JAR"
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
