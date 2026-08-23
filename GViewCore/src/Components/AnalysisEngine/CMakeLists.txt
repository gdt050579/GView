set(ANALYSIS_ENGINE_SOURCES
    AnalysisEngine.cpp
    AnalysisEngine.hpp
    AnalysisEngineConfig.cpp
    AnalysisEngineData.cpp
    AnalysisEngineData.hpp
    AnalysisEngineInternal.hpp
    AnalysisEngineWindow.cpp
    AnalysisEngineWindow.hpp
    ActionViewProvider.cpp
    ActionViewProvider.hpp
    KnowledgeBase.cpp
    KnowledgeBase.hpp
    PatternMatcher.cpp
    PatternMatcher.hpp
    ReportGenerator.cpp
    ReportGenerator.hpp
    SummaryController.cpp
    SummaryController.hpp
)
target_sources(GViewCore PRIVATE ${ANALYSIS_ENGINE_SOURCES})

add_testing_sources(GViewCore tests_analysisengine.cpp)
