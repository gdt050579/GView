#!/bin/sh
brew install --build-from-source --verbose --debug ncurses
brew install --build-from-source --verbose --debug openssl@1.1


OPENSSL_ROOT_DIR=$(brew --prefix openssl@1.1)
BUILD_TYPE="Debug"

cmake -B ./build -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR" -DOPENSSL_LIBRARIES="$OPENSSL_ROOT_DIR/lib"
cmake --build "$BUILD_TYPE/build" --config "$BUILD_TYPE"

cmake -Bbuild -G Xcode .
cmake --build build
