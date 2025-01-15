file(GLOB_RECURSE sources_all CONFIGURE_DEPENDS *.cpp *.hpp)

file(GLOB sources_top     *.cpp *.hpp)
file(GLOB sources_panels Panels/*.cpp Panels/*.h Panels/*.hpp)
file(GLOB sources_payload_parser PayloadParsers/*.cpp PayloadParsers/*.h PayloadParsers/*.hpp)

source_group("Panels" ${sources_panels})
source_group("PayloadParsers" ${sources_payload_parser})

target_sources(PCAP PRIVATE ${sources_all})

