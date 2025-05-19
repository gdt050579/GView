include(generic_plugin)
create_generic_plugin(FileDownloader)

find_package(CURL REQUIRED)
target_link_libraries(FileDownloader PRIVATE CURL::libcurl)
