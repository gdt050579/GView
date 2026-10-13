target_sources(GViewCore PRIVATE
        Base64.cpp
        LZXPRESS.cpp
        QuotedPrintable.cpp
        zip.cpp
        zlib.cpp
        HexCharactersToAscii.cpp
        VBSEncoding.cpp
        XOREncoding.cpp
        HTMLCharactersEncoding.cpp
)

add_testing_sources(GViewCore "tests_base64.cpp;tests_utf16.cpp")
