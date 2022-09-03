#!/bin/sh
cmake -Bbuild -DCMAKE_PREFIX_PATH=/opt/homebrew/Cellar/ncurses/6.3 -G Xcode .
cmake --build build
