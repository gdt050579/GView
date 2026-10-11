if(NOT DEFINED CMAKE_TESTING_ENABLED)
        # Generic plugins supported by GView
        add_subdirectory(CharacterTable)
        add_subdirectory(Hashes)
        add_subdirectory(SyncCompare)
        add_subdirectory(EntropyVisualizer)
        add_subdirectory(Dropper)
        add_subdirectory(Unpacker)
        if (GVIEW_ENABLE_NETWORK) # libcurl
            add_subdirectory(FileDownloader)
        endif()
endif()