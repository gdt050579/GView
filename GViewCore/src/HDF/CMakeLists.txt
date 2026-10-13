# Hybrid Disclosure Framework (docs/source/hdf.rst, plans/HDF_IMPLEMENTATION.md)
set(HDF_SOURCES
    Term.hpp
    ConstantPool.hpp
    ConstantPool.cpp
    Signature.hpp
    Signature.cpp
    Specification.hpp
    Specification.cpp
    SpecificationLoader.hpp
    SpecificationLoader.cpp
    AssertionBase.hpp
    AssertionBase.cpp
    DerivationIndex.hpp
    DerivationIndex.cpp
    GroundAction.hpp
    Entailment.hpp
    Entailment.cpp
    DisclosureTrace.hpp
    SubjectRegistry.hpp
    SubjectRegistry.cpp
    DisclosureSink.cpp
    DisclosureSession.hpp
    DisclosureSession.cpp
    Interpretation.hpp
    Interpretation.cpp
    Explanation.hpp
    Explanation.cpp
    VocabularyRegistry.hpp
    VocabularyRegistry.cpp
    CoreVocabulary.cpp
    Tooling.hpp
    Tooling.cpp
    Engine.hpp
    Engine.cpp
    HDFWindow.hpp
    HDFWindow.cpp
    SummaryAssistant.hpp
    SummaryAssistant.cpp
)
target_sources(GViewCore PRIVATE ${HDF_SOURCES})

add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_hdf.cpp)
add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_hdf_running_example.cpp)
add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_hdf_tooling.cpp)

