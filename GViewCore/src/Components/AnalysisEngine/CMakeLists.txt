set(ANALYSIS_ENGINE_SOURCES
    AnalysisEngine.cpp
    AnalysisEngine.hpp
    AnalysisEngineWindow.cpp
    AnalysisEngineWindow.hpp
)
target_sources(GViewCore PRIVATE ${ANALYSIS_ENGINE_SOURCES})