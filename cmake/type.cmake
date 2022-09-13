macro(make_filters _source_list)
    foreach(_source IN ITEMS ${_source_list})
        get_filename_component(_source_path "${_source}" PATH)
        string(REPLACE "${CMAKE_SOURCE_DIR}" "" _group_path "${_source_path}")
        string(REPLACE "/" "\\" _group_path "${_group_path}")
        source_group("${_group_path}" FILES "${_source}")
    endforeach()
endmacro()


function (create_type type_name)

	set(PROJECT_NAME ${type_name})	
	
	include_directories(../../GViewCore/include)
		
	file(GLOB_RECURSE SRC_ALL "src/*.cpp" "src/*.h")
        SOURCE_GROUP(TREE "${PROJECT_SOURCE_DIR}/Types/${type_name}/src" FILES ${SRC_ALL})
	message(STATUS "${PROJECT_SOURCE_DIR}/Types/${type_name}/src => SRC = ${SRC_ALL}")

	make_filters("${PROJECT_SOURCE_DIR}/Types/${type_name}/src")

	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	add_library(${PROJECT_NAME} SHARED)
	
	if (MSVC)
	    add_definitions(-DBUILD_FOR_WINDOWS)
	    add_compile_options(-W3)
	elseif (APPLE)
	    add_definitions(-DBUILD_FOR_OSX)
	    if (DEBUG_BUILD)
        	add_compile_options(-g)
	        add_compile_options(-W)
	    endif()
	elseif (UNIX)
	    add_definitions(-DBUILD_FOR_UNIX)
	    if (DEBUG_BUILD)
	        add_compile_options(-g)
	        add_compile_options(-W)
	    endif()
	endif()
	
	include_directories(include)	
	add_subdirectory(src)
                  
	file(GLOB_RECURSE PROJECT_HEADERS include/*.hpp)
	target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_HEADERS})

	add_dependencies(${PROJECT_NAME} GViewCore)
	add_dependencies(${PROJECT_NAME} AppCUI)
	
	target_link_libraries(${PROJECT_NAME} PRIVATE GViewCore)
	target_link_libraries(${PROJECT_NAME} PRIVATE AppCUI)
	
	set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "lib")
	set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".tpl")
	
	set_target_properties(${PROJECT_NAME} PROPERTIES
		FOLDER "Types"
		RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}/Types"
		RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}/Types")
					
	if (NOT MSVC)
		set_target_properties(${PROJECT_NAME} PROPERTIES
			ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/Types"
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Types")
	endif()
	
	get_target_property(F ${PROJECT_NAME} FOLDER)
	get_target_property(RODD ${PROJECT_NAME} RUNTIME_OUTPUT_DIRECTORY_DEBUG)
	get_target_property(RODR ${PROJECT_NAME} RUNTIME_OUTPUT_DIRECTORY_RELEASE)
	get_target_property(AOD ${PROJECT_NAME} ARCHIVE_OUTPUT_DIRECTORY)
	get_target_property(LOD ${PROJECT_NAME} LIBRARY_OUTPUT_DIRECTORY)
	
	message(STATUS "${PROJECT_NAME} => FOLDER = ${F}")
	message(STATUS "${PROJECT_NAME} => RUNTIME_OUTPUT_DIRECTORY_DEBUG = ${RODD}")
	message(STATUS "${PROJECT_NAME} => RUNTIME_OUTPUT_DIRECTORY_RELEASE = ${RODR}")
	message(STATUS "${PROJECT_NAME} => ARCHIVE_OUTPUT_DIRECTORY = ${AOD}")
	message(STATUS "${PROJECT_NAME} => LIBRARY_OUTPUT_DIRECTORY = ${LOD}")
endfunction()

