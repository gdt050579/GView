# macro(make_filters _source_list)
#     foreach(_source IN ITEMS ${_source_list})
#         get_filename_component(_source_path "${_source}" PATH)
#         string(REPLACE "${CMAKE_SOURCE_DIR}" "" _group_path "${_source_path}")
#         string(REPLACE "/" "\\" _group_path "${_group_path}")
#         source_group("${_group_path}" FILES "${_source}")
#     endforeach()
# endmacro()

add_subdirectory("src/Panels")

# file(GLOB_RECURSE SRC_ALL "src/*.cpp" "src/*.h")
# SOURCE_GROUP(TREE "${PROJECT_SOURCE_DIR}/Types/PE/src" FILES ${SRC_ALL})
# message(STATUS "${PROJECT_SOURCE_DIR}/Types/PE/src => SRC = ${SRC_ALL}")
# make_filters("${SRC_ALL}")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(type)
create_type(PE)
