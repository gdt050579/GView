target_sources(GViewCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/UpdateCore.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HttpClient.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Stager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Installer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/UpdateService.cpp
)

# the updater's apply/rollback logic is unit-tested inside GViewTesting (it is otherwise built only into GViewUpdater)
add_testing_sources(GViewCore "${CMAKE_CURRENT_SOURCE_DIR}/tests_update.cpp;${CMAKE_CURRENT_SOURCE_DIR}/tests_updater_apply.cpp")
