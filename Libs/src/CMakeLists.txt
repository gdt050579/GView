project(Libs)

file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp)
target_sources(${PROJECT_NAME} PRIVATE ${sources_all})


