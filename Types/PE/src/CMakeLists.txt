file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp *.h)

file(GLOB sources_top     *.cpp *.h)
file(GLOB sources_panels Panels/*.cpp Panels/*.h)
file(GLOB sources_commands Commands/*.cpp Commands/*.h)

source_group("Panels" ${sources_panels})
source_group("Commands" ${sources_commands})

target_sources(PE PRIVATE ${sources_all})

