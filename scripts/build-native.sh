#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  timeout 2400 powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-native.ps1
  exit $?
fi
flags=(-O1 -H:+UnlockExperimentalVMOptions -J-Xmx5g -H:NumberOfThreads=2 --no-fallback -march=compatibility -H:+ReportExceptionStackTraces --enable-url-protocols=http,https -H:IncludeResources=THIRD_PARTY_NOTICES -R:ReservedAddressSpaceSize=4g -R:MaxHeapSize=3072m)
if [[ "$(uname -s)" == Linux ]]; then
 flags+=(-H:+StaticExecutableWithDynamicLibC -H:NativeLinkerOption=-static-libstdc++ -H:NativeLinkerOption=-static-libgcc)
fi
cp target/lmaws-0.1.6.jar target/native-input.jar
timeout 2400 native-image "${flags[@]}" -jar target/native-input.jar target/lmaws
