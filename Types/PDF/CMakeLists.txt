include(type)
create_type(PDF)

find_package(OpenJPEG CONFIG REQUIRED)

message(STATUS "OpenJPEG_INCLUDE_DIRS: ${OpenJPEG_INCLUDE_DIRS}")
message(STATUS "OpenJPEG_LIBRARIES: ${OpenJPEG_LIBRARIES}")

target_include_directories(PDF PRIVATE ${OpenJPEG_INCLUDE_DIRS})

# Link OpenJPEG (use dynamic or static depending on availability)
target_link_libraries(PDF PRIVATE openjp2)

find_package(TIFF REQUIRED)

message(STATUS "TIFF_INCLUDE_DIRS: ${TIFF_INCLUDE_DIRS}")
message(STATUS "TIFF_LIBRARIES: ${TIFF_LIBRARIES}")

target_include_directories(PDF PRIVATE ${TIFF_INCLUDE_DIRS})

target_link_libraries(PDF PRIVATE TIFF::TIFF)

if(DEFINED ENV{VCPKG_ROOT})
    set(VCPKG_INSTALLED_DIR "$ENV{VCPKG_ROOT}/installed")
endif()

set(JBIG2DEC_INCLUDE_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")

if(WIN32)
    find_library(JBIG2DEC_LIBRARY NAMES jbig2dec PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib")
else()
    find_library(JBIG2DEC_LIBRARY NAMES jbig2dec PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib")
endif()

# Add include directory
target_include_directories(PDF PRIVATE ${JBIG2DEC_INCLUDE_DIR})

# Link the library
target_link_libraries(PDF PRIVATE ${JBIG2DEC_LIBRARY})

message(STATUS "JBIG2DEC include path: ${JBIG2DEC_INCLUDE_DIR}")
message(STATUS "JBIG2DEC library path: ${JBIG2DEC_LIBRARY}")

find_package(podofo CONFIG REQUIRED)
target_link_libraries(PDF PRIVATE $<IF:$<TARGET_EXISTS:podofo_shared>,podofo_shared,podofo_static>)

find_package(OpenSSL REQUIRED)
target_link_libraries(PDF PRIVATE OpenSSL::SSL)
target_link_libraries(PDF PRIVATE OpenSSL::Crypto)