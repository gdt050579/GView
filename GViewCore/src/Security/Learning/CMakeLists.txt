target_sources(GViewCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureMemory.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningProtocol.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningHttp.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ContentDelivery.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Telemetry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/BackgroundWorker.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LearningHooks.cpp
)

add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_learning.cpp)
