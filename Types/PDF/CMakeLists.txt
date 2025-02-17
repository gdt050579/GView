include(type)
create_type(PDF)

find_package(OpenJPEG CONFIG REQUIRED)

message(STATUS "OpenJPEG_INCLUDE_DIRS: ${OpenJPEG_INCLUDE_DIRS}")
message(STATUS "OpenJPEG_LIBRARIES: ${OpenJPEG_LIBRARIES}")

target_include_directories(PDF PRIVATE ${OpenJPEG_INCLUDE_DIRS})

# Link OpenJPEG (use dynamic or static depending on availability)
target_link_libraries(PDF PRIVATE openjp2)