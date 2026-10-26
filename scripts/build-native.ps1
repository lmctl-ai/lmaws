$ErrorActionPreference = "Stop"
$nativeImage = Join-Path $env:JAVA_HOME "bin/native-image.cmd"
Copy-Item 'target/lmaws-0.1.3.jar' 'target/native-input.jar'
& $nativeImage '-O1' '-H:+UnlockExperimentalVMOptions' '-J-Xmx5g' '-H:NumberOfThreads=2' '--no-fallback' '-march=compatibility' '-H:+ReportExceptionStackTraces' '--enable-url-protocols=http,https' '-H:IncludeResources=THIRD_PARTY_NOTICES' '-R:ReservedAddressSpaceSize=4g' '-R:MaxHeapSize=3072m' '-jar' 'target/native-input.jar' 'target/lmaws'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (!(Test-Path 'target/lmaws.exe')) { throw 'native executable missing' }
