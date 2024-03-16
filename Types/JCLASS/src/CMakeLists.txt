file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp *.h *.hpp)

file(GLOB sources_top     *.cpp *.h *.hpp)
file(GLOB sources_panels Panels/*.cpp Panels/*.h Panels/*.hpp)

source_group("Panels" ${sources_panels})

target_sources(JCLASS PRIVATE ${sources_all})

