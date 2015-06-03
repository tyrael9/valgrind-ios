# Valgrind on iOS
This port of Valgrind runs on jail-broken iOS devices.

## Prepare
* Checkout the source: `git clone git://github.com/tyrael9/valgrind-ios.git`
* Get into the source directory: `cd valgrind-ios`
* Initialize the VEX submodule: `git submodule update --init --recursive`

## Build
The following build environment is required:
* Mac OS X >= 10.9
* Xcode >= 5.0 
* iOS SDK >= 7.0

You also need the standard `autoconf` tools to build Valgrind, which
you can install with homebrew on OS X.

Make sure you are in the root directory of the source repository. 
Use the following commands to build:
```
./autogen.sh

./configure CPPFLAGS="-arch armv7 -isysroot $(xcrun --sdk iphoneos --show-sdk-path)" \
LDFLAGS="-arch armv7 -isysroot $(xcrun --sdk iphoneos --show-sdk-path)" \
--prefix=/where/you/want/it/installed --host=armv7-unknown-darwin --with-iosver=8.0

make

make install
```
The Valgrind should now be installed at your specified directory.

## Usage
To use Valgrind, copy the directory where you installed it to your iOS device.

Usually, the access permission of the files in the directory are not preserved after copy. 
In that case, SSH to your device and add executable permission to the following files in the 
valgrind directory:
```
bin/valgrind
bin/vgdb
lib/valgrind/none-arm-darwin
lib/valgrind/vgpreload_core-arm-darwin.so
```

Suppose the directory is copied to `/var/root/valgrind-ios`, you could use the following command
to run Valgrind on ls. Note that you must be root in order to run Valgrind.
```
VALGRIND_LIB=/var/root/valgrind-ios/lib/valgrind /var/root/valgrind-ios/bin/valgrind ls -l
```
