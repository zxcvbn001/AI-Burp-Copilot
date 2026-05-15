@echo off
title AI Burp Copilot v2 - Build
setlocal

echo ============================================
echo  AI Burp Copilot v2 - Build Script
echo ============================================
echo.

:: ========== 1. Setup paths ==========
set JAVA_HOME=D:\jdk\jdk21
set MAVEN_HOME=D:\jdk\apache-maven-3.9.15-bin\apache-maven-3.9.15
set JAVA_CMD=%JAVA_HOME%\bin\java.exe
set JAVAC_CMD=%JAVA_HOME%\bin\javac.exe
set MVN_CMD=%MAVEN_HOME%\bin\mvn.cmd
set PATH=%JAVA_HOME%\bin;%MAVEN_HOME%\bin;%PATH%

:: Check Java
if not exist "%JAVA_CMD%" (
    echo [ERROR] JDK not found at: %JAVA_HOME%
    echo Please check your JDK installation.
    pause
    exit /b 1
)

if not exist "%JAVAC_CMD%" (
    echo [ERROR] javac not found at: %JAVAC_CMD%
    echo Please check your JDK installation.
    pause
    exit /b 1
)

:: Check Maven
if not exist "%MVN_CMD%" (
    echo [ERROR] Maven not found at: %MAVEN_HOME%
    echo Please check your Maven installation.
    pause
    exit /b 1
)

echo [INFO] Java: %JAVA_HOME%
"%JAVA_CMD%" -version 2>&1
"%JAVAC_CMD%" -version 2>&1
echo.
echo [INFO] Maven: %MAVEN_HOME%
echo.

:: ========== 2. Choose build mode ==========
echo Build Mode:
echo   1) Compile only
echo   2) Package JAR
echo   3) Clean + Package
echo.
set /p mode="Select (1/2/3, default=2): "
if "%mode%"=="" set mode=2

:: ========== 3. Run build ==========
set PROJECT_DIR=%~dp0
cd /d "%PROJECT_DIR%"

set MVN_ARGS=-DskipTests -Dmaven.test.skip=true -Dmaven.compiler.useModulePath=false

if "%mode%"=="1" (
    echo [INFO] Compiling...
    call "%MVN_CMD%" compile %MVN_ARGS%
) else if "%mode%"=="2" (
    echo [INFO] Packaging JAR...
    call "%MVN_CMD%" package %MVN_ARGS%
) else if "%mode%"=="3" (
    echo [INFO] Full rebuild...
    call "%MVN_CMD%" clean package %MVN_ARGS%
) else (
    echo [ERROR] Invalid option: %mode%
    pause
    exit /b 1
)

:: ========== 4. Check result ==========
if %errorlevel% equ 0 (
    echo.
    echo ============================================
    echo  BUILD SUCCESS
    echo ============================================
    echo.
    dir /b "target\ai-burp-copilot-v2*.jar" 2>nul
    echo.
    echo Output files:
    if exist "target\ai-burp-copilot-v2.jar" (
        echo   [plugin] target\ai-burp-copilot-v2.jar
    )
    if exist "target\ai-burp-copilot-v2-jar-with-dependencies.jar" (
        echo   [fatjar] target\ai-burp-copilot-v2-jar-with-dependencies.jar
    )
) else (
    echo.
    echo ============================================
    echo  BUILD FAILED - check errors above
    echo ============================================
)

echo.
pause
