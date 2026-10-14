target_sources(GViewCore PRIVATE
    CharacterSet.cpp
    Demangle.cpp
    ErrorList.cpp
    DataCache.cpp
    Selection.cpp
    CharacterEncoding.cpp
    ZonesList.cpp
    JsonBuilder.cpp
)

add_testing_sources(GViewCore "tests_datacache.cpp;tests_encoding.cpp")

