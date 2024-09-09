#!/bin/sh -e

./blst-tangem/build.sh 'CC="xcrun -sdk iphoneos cc -arch arm64"'
cp ./libblst.a ./Libraries/lib/iphoneos/
rm -rf libblst.a

./blst-tangem/build.sh 'CC="xcrun -sdk iphonesimulator cc -arch arm64"'
cp ./libblst.a ./Libraries/lib/iphone-simulator/arm64/
rm -rf libblst.a

./blst-tangem/build.sh 'CC="xcrun -sdk iphonesimulator cc -arch x86_64"'
cp ./libblst.a ./Libraries/lib/iphone-simulator/x86_64/
rm -rf libblst.a