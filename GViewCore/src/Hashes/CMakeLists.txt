target_sources(GViewCore PRIVATE
        Adler32.cpp
        CRC16.cpp
        CRC32.cpp
        CRC64.cpp
        OpenSSL.cpp
)

add_testing_sources(GViewCore tests_hashes.cpp)
