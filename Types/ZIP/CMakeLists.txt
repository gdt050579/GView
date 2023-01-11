include(type)
create_type(ZIP)

find_package(minizip-ng CONFIG REQUIRED)
message(STATUS "minizip-ng_DIR => ${minizip-ng_DIR}")

# vcpkg directory structure
get_filename_component(MINIZIP_SHARE_INCLUDE_DIR ${minizip-ng_DIR} DIRECTORY)
get_filename_component(MINIZIP_PARENT_DIR ${MINIZIP_SHARE_INCLUDE_DIR} DIRECTORY)
set(MINIZIP_INCLUDE_DIR "${MINIZIP_PARENT_DIR}/include/minizip-ng")

message(STATUS "MINIZIP_INCLUDE_DIR => ${MINIZIP_INCLUDE_DIR}")
target_include_directories(ZIP PRIVATE ${MINIZIP_INCLUDE_DIR}) # hardcoded project name (ZIP) as it is declared function scope only (create_type from type)
target_link_libraries(ZIP PRIVATE MINIZIP::minizip-ng)         # hardcoded project name (ZIP) as it is declared function scope only (create_type from type)
