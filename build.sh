#!/bin/bash
export JAVA_HOME=/nix/store/3ilfkn8kxd9f6g5hgr0wpbnhghs4mq2m-openjdk-21.0.7+6
export PATH=$JAVA_HOME/bin:$PATH

echo "========================================"
echo "  AntiRat Mod Builder"
echo "  Building for Minecraft 1.21.1 (Fabric)"
echo "  Author: Akar1881"
echo "========================================"
echo ""
echo "Java version:"
java -version 2>&1
echo ""
echo "Starting build..."
echo ""

./gradlew build --no-daemon -x test 2>&1

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "  BUILD SUCCESSFUL!"
    echo "========================================"
    echo ""
    echo "Output JAR files:"
    ls -la build/libs/ 2>/dev/null
    echo ""
    echo "The mod JAR is in build/libs/"
    echo "Copy the JAR (not the -sources one) to your .minecraft/mods/ folder"
else
    echo ""
    echo "========================================"
    echo "  BUILD FAILED"
    echo "========================================"
fi

echo ""
echo "Build complete. Press Ctrl+C to exit."
while true; do sleep 3600; done
