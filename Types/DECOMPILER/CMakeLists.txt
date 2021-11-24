include(type)

add_subdirectory(libs/distorm)

create_type(DECOMPILER)

target_link_libraries(DECOMPILER PRIVATE ${DISTORM_STATIC_LIB_NAME})
