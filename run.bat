@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

REM --- Configuration ---
set "LIB_DIR=target\lib"
set "MAIN_CLASS=org.liuzx.jce.demo.Main"

REM Locate the packaged main JAR (version agnostic; exclude -sources/-javadoc).
set "MAIN_JAR="
for %%f in ("target\liuzx-sdf-jce-*.jar") do (
    echo %%~nxf | findstr /I /E /C:"-sources.jar" /C:"-javadoc.jar" >nul
    if errorlevel 1 if not defined MAIN_JAR set "MAIN_JAR=%%f"
)

REM --- Java Options ---
set "JAVA_OPTS=-Duser.language=zh -Duser.country=CN -Duser.timezone=Asia/Shanghai -Dfile.encoding=UTF-8"

REM --- Pre-flight Checks ---
if not defined MAIN_JAR (
    echo Error: Main JAR file not found under target\.
    echo Please run 'mvn clean package' first.
    pause
    exit /b 1
)

if not exist "%MAIN_JAR%" (
    echo Error: Main JAR file not found at %MAIN_JAR%
    echo Please run 'mvn clean package' first.
    pause
    exit /b 1
)

REM --- Build Classpath ---
set "CP=%MAIN_JAR%"
if exist "%LIB_DIR%" (
    for %%j in ("%LIB_DIR%\*.jar") do (
        set "CP=!CP!;%%j"
    )
)

REM --- Execution ---
echo Starting JCE Demo Application...
echo Classpath: %CP%

java %JAVA_OPTS% -cp "%CP%" %MAIN_CLASS% %*

pause
