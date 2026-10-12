target_sources(GViewCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureMemory.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningProtocol.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningHttp.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ContentDelivery.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Telemetry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningHooks.cpp
)

if (EMSCRIPTEN)
    # no threads in a web page: the jobs run on the UI thread and are re-run when their response arrives (JobReplay.hpp)
    target_sources(GViewCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/BackgroundWorkerWasm.cpp)
else()
    target_sources(GViewCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/BackgroundWorker.cpp)
endif()

if (GVIEW_ENABLE_BROWSER_NETWORK)
    # the transport of the web build: fetch() of the page
    target_sources(GViewCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/LearningHttpFetch.cpp)
endif()

add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_learning.cpp)
