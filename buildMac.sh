#!/bin/sh

rm -rf bin
rm -rf build
cmake -Bbuild -G Xcode .
cmake --build build
