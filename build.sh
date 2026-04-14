#!/bin/bash

JDK21=/nix/store/3ilfkn8kxd9f6g5hgr0wpbnhghs4mq2m-openjdk-21.0.7+6
JDK25=/home/runner/jdk25
GRADLE=/nix/store/8cn9slibsf1pqzz8p3s4pm2vq2bivdzf-gradle-8.14.2/bin/gradle

echo "========================================"
echo "  AntiRat Mod Builder v1.1.0"
echo "  Author: Akar1881"
echo "========================================"
echo ""

echo "========================================"
echo "  [1/2] Building: 1.21.x"
echo "  Minecraft 1.21.1-1.21.11 | Fabric Loom 1.9 | Yarn Mappings | Java 21"
echo "========================================"
export JAVA_HOME=$JDK21
export PATH=$JAVA_HOME/bin:$PATH
echo "Java: $(java -version 2>&1 | head -1)"
$GRADLE build -x test --no-daemon 2>&1

BUILD1_EXIT=$?
if [ $BUILD1_EXIT -eq 0 ]; then
    echo ""
    echo "  [1.21.x] BUILD SUCCESSFUL!"
    ls -la build/libs/ 2>/dev/null | grep -v sources
else
    echo "  [1.21.x] BUILD FAILED"
fi

echo ""
echo "========================================"
echo "  [2/2] Building: 26.x"
echo "  Minecraft 26.1.2 | Fabric Loom 1.15 | Official Mojang Mappings | Java 25"
echo "========================================"
export JAVA_HOME=$JDK25
export PATH=$JAVA_HOME/bin:$PATH
echo "Java: $(java -version 2>&1 | head -1)"
cd v26 && ./gradlew build -x test --no-daemon 2>&1
V26_EXIT=$?
cd ..

if [ $V26_EXIT -eq 0 ]; then
    echo ""
    echo "  [26.x] BUILD SUCCESSFUL!"
    ls -la v26/build/libs/ 2>/dev/null | grep -v sources
else
    echo "  [26.x] BUILD FAILED"
fi

echo ""
echo "========================================"
echo "  SUMMARY"
if [ $BUILD1_EXIT -eq 0 ]; then
    echo "  [OK] 1.21.x: build/libs/anti-rat-1.1.0.jar"
else
    echo "  [FAIL] 1.21.x build failed"
fi
if [ $V26_EXIT -eq 0 ]; then
    echo "  [OK] 26.x:   v26/build/libs/anti-rat-26x-1.1.0.jar"
else
    echo "  [FAIL] 26.x build failed"
fi
echo "  Drop the JAR (not -sources) into .minecraft/mods/"
echo "========================================"
echo ""
echo "Watching... (Ctrl+C to stop)"
while true; do sleep 3600; done
