include(generic_plugin)
create_generic_plugin(OnlineAnalytics)

find_package(CURL REQUIRED)
target_link_libraries(OnlineAnalytics PRIVATE CURL::libcurl)

find_package(nlohmann_json REQUIRED)
target_link_libraries(OnlineAnalytics PRIVATE nlohmann_json::nlohmann_json)