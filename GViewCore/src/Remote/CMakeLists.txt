if (GVIEW_ENABLE_REMOTE)
    target_sources(GViewCore PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteProtocol.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteNet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteTls.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteChannel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteServer.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteClient.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/RemoteCommands.cpp
    )
    add_testing_sources(GViewCore ${CMAKE_CURRENT_SOURCE_DIR}/tests_remote.cpp)
else()
    target_sources(GViewCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/RemoteDisabled.cpp)
endif()
