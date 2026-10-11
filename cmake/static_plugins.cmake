# GVIEW_STATIC_PLUGINS: every plugin is a static library (see create_type / create_generic_plugin) linked into the
# executable. Its entry points are reached through tables generated from StaticPlugins.cpp.in, which GViewCore uses
# instead of loading lib<Name>.tpl / lib<Name>.gpl (see GViewCore/src/include/StaticPlugins.hpp).
# Must be called after every plugin was added.
function (gview_link_static_plugins target)
	get_property(type_plugins GLOBAL PROPERTY GVIEW_STATIC_TYPE_PLUGINS)
	get_property(generic_plugins GLOBAL PROPERTY GVIEW_STATIC_GENERIC_PLUGINS)

	set(GVIEW_STATIC_PLUGIN_DECLARATIONS "")
	set(GVIEW_STATIC_TYPE_PLUGINS "")
	set(GVIEW_STATIC_GENERIC_PLUGINS "")
	foreach(plugin IN LISTS type_plugins)
		string(APPEND GVIEW_STATIC_PLUGIN_DECLARATIONS "GVIEW_DECLARE_TYPE_PLUGIN(${plugin})\n")
		string(APPEND GVIEW_STATIC_TYPE_PLUGINS "    GVIEW_TYPE_PLUGIN(${plugin}),\n")
	endforeach()
	foreach(plugin IN LISTS generic_plugins)
		string(APPEND GVIEW_STATIC_PLUGIN_DECLARATIONS "GVIEW_DECLARE_GENERIC_PLUGIN(${plugin})\n")
		string(APPEND GVIEW_STATIC_GENERIC_PLUGINS "    GVIEW_GENERIC_PLUGIN(${plugin}),\n")
	endforeach()

	set(generated "${CMAKE_BINARY_DIR}/generated/StaticPlugins.cpp")
	configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/StaticPlugins.cpp.in" "${generated}" @ONLY)
	target_sources(${target} PRIVATE "${generated}")
	target_include_directories(${target} PRIVATE
		"${CMAKE_SOURCE_DIR}/GViewCore/include"
		"${CMAKE_SOURCE_DIR}/GViewCore/src/include")
	target_link_libraries(${target} PRIVATE ${type_plugins} ${generic_plugins})

	list(LENGTH type_plugins type_count)
	list(LENGTH generic_plugins generic_count)
	message(STATUS "${target} => ${type_count} type plugins and ${generic_count} generic plugins linked statically")
endfunction()
