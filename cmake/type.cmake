function (create_type type_name)
	set(PROJECT_NAME ${type_name})
	include_directories(../../GViewCore/include)
	add_library(${PROJECT_NAME} SHARED)
	add_dependencies(${PROJECT_NAME} GViewCore)
	add_dependencies(${PROJECT_NAME} AppCUI)
	target_link_libraries(${PROJECT_NAME} PRIVATE GViewCore)
	target_link_libraries(${PROJECT_NAME} PRIVATE AppCUI)
	set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "Types")
	set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "lib")
endfunction()

