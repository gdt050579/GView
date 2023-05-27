file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp *.h)

file(GLOB sources_top     *.cpp *.h)
file(GLOB sources_panels Panels/*.cpp Panels/*.h)

source_group("Panels" ${sources_panels})

target_sources(ZIP PRIVATE ${sources_all})

