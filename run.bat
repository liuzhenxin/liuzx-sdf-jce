@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

# --- Configuration ---
set "MAIN_JAR=target\liuzx-sdf-jce-1.0-SNAPSHOT.jar"
set "LIB_DIR=target\lib"
set "MAIN_CLASS=org.liuzx.jce.demo.Main"

# --- Java Options ---
set "JAVA_OPTS=-Duser.language=zh -Duser.country=CN -Duser.timezone=Asia/Shanghai -Dfile.encoding=UTF-8"

# --- Pre-flight Checks ---
if not exist "%MAIN_JAR%" (
    echo Error: Main JAR file not found at %MAIN_JAR%
    echo Please run 'mvn clean package' first.
    pause
    exit /b 1
)

# --- Build Classpath ---
# Start with the main application JAR
set "CP=%MAIN_JAR%"

# Add all JARs from the lib directory to the classpath
if exist "%LIB_DIR%" (
    for %%j in ("%LIB_DIR%\*.jar") do (
        set "CP=!CP!;%%j"
    )
)

# --- Execution ---
echo Starting JCE Demo Application...
echo Classpath: %CP%

java %JAVA_OPTS% -cp "%CP%" %MAIN_CLASS% %*

pause
