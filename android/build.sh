#!/bin/sh
# Builds the Keystore benchmark APK with the Android SDK command-line tools
# (no Gradle). Requires ANDROID_SDK (default ~/Library/Android/sdk) and a JDK.
set -e
cd "$(dirname "$0")"
SDK=${ANDROID_SDK:-$HOME/Library/Android/sdk}
BT=$SDK/build-tools/36.0.0
JAR=$SDK/platforms/android-36/android.jar
rm -rf build && mkdir -p build/classes build/dex
"$BT/aapt2" link -o build/base.apk -I "$JAR" --manifest AndroidManifest.xml \
    --min-sdk-version 31 --target-sdk-version 34
javac --release 11 -cp "$JAR" -d build/classes $(find src -name '*.java')
"$BT/d8" --min-api 31 --lib "$JAR" --output build/dex \
    $(find build/classes -name '*.class')
cp build/base.apk build/unsigned.apk
(cd build/dex && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
[ -f build_key.jks ] || keytool -genkeypair -keystore build_key.jks \
    -storepass android -keypass android -alias bench -keyalg EC \
    -dname "CN=KeyLease Bench" -validity 3650 >/dev/null 2>&1
"$BT/apksigner" sign --ks build_key.jks --ks-pass pass:android \
    --out keylease-bench.apk build/aligned.apk
echo "built $(pwd)/keylease-bench.apk"
