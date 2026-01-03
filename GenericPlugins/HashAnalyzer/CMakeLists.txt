include(generic_plugin)
create_generic_plugin(HashAnalyzer)

find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(HashAnalyzer PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)
