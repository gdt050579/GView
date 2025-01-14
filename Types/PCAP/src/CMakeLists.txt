file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp *.hpp)

file(GLOB sources_top     *.cpp *.hpp)
file(GLOB sources_panels Panels/*.cpp Panels/*.h Panels/*.hpp)

source_group("Panels" ${sources_panels})

target_sources(PCAP PRIVATE ${sources_all})

