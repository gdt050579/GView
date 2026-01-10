include(generic_plugin)
create_generic_plugin(Yara)

find_package(unofficial-libyara CONFIG REQUIRED)
target_link_libraries(Yara PRIVATE unofficial::libyara::libyara)
