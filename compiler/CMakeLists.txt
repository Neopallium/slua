
#
# slua source
#
set(CORE_LUA_SRC
	lua_core.c
	lua_vm_ops_static.c
	load_jit_proto.c
)
set(CORE_LIB_INCLUDES
	lua_core.h
	lua_vm_ops.c
	lua_vm_ops.h
	load_jit_proto.h
	../src/ldebug.h
	../src/ldo.h
	../src/lfunc.h
	../src/lgc.h
	../src/lobject.h
	../src/lopcodes.h
	../src/lstate.h
	../src/lstring.h
	../src/ltable.h
	../src/ltm.h
	../src/lvm.h
	../src/llimits.h
	../src/lzio.h
	../src/lmem.h
	../src/lapi.h
	../src/lauxlib.h
	../src/lua.h
	../src/luaconf.h
	../src/lcoco.h
)
set(SLUA_COMMON_SRC
	slua_compiler.c
	codegen.c
	${CORE_LUA_SRC}
)
set(SLUA_SRC
	slua.c
	lua_interpreter.c
)
set(SLUAC_SRC
	sluac.c
	lua_compiler.c
	slua_dumper.c
)
set(SLUA_LIB_SRC
	lua_interpreter.c
	${SLUA_COMMON_SRC}
)
set(SLUA_BINS)
set(SLUA_COMPILER)

## generate build_config.h
set(BUILD_CONFIG_H ${CMAKE_CURRENT_BINARY_DIR}/build_config.h)
configure_file(build_config.h.cmake ${BUILD_CONFIG_H})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
				${PROJECT_SOURCE_DIR}/src
				${CMAKE_CURRENT_BINARY_DIR})

add_executable(bin2c bin2c.c)

#
# Embedded lua vm ops c code files
#
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lua_vm_ops_c.h
	COMMAND bin2c -z -c lua_vm_ops.c ${CMAKE_CURRENT_BINARY_DIR}/lua_vm_ops_c.h
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS bin2c lua_vm_ops.bc
)

#
# Lua library.
#
set(SLUA_LIBS)
# slua static library.
add_library(slua_static STATIC ${SLUA_LIB_SRC})
add_target_properties(slua_static COMPILE_FLAGS "${COMMON_CFLAGS}")
add_target_properties(slua_static LINK_FLAGS "${LD_FLAGS} ${COMMON_LDFLAGS}")
target_link_libraries(slua_static ${LIBS})
set(SLUA_MAIN_LIB slua_static)

if(WANT_SHARED_LIBRARY)
	# slua dynamic library
	add_library(slua_dynamic SHARED ${SLUA_LIB_SRC})
	add_target_properties(slua_dynamic COMPILE_FLAGS "${COMMON_CFLAGS}")
	add_target_properties(slua_dynamic LINK_FLAGS "${LD_FLAGS} ${COMMON_LDFLAGS}")
	target_link_libraries(slua_dynamic ${LIBS})
	set_target_properties(slua_dynamic PROPERTIES OUTPUT_NAME slua)

	# link lua interpreter with dynamic library
	set(SLUA_MAIN_LIB slua_dynamic)
	set(SLUA_LIBS ${SLUA_LIBS} slua_dynamic)
	if(WIN32)
		set(SLUA_BINS ${SLUA_BINS} slua_dynamic)
	endif(WIN32)
endif(WANT_SHARED_LIBRARY)

#
# static library liblua_main.a
#
add_library(lua_main STATIC lua_main.c ${CORE_LUA_SRC})
add_target_properties(lua_main COMPILE_FLAGS "${COMMON_CFLAGS}")
add_target_properties(lua_main LINK_FLAGS "${LD_FLAGS} ${COMMON_LDFLAGS}")
set(SLUA_LIBS ${SLUA_LIBS} lua_main)

# set library version & soversion
if(SLUA_LIBS)
	set_target_properties(${SLUA_LIBS} PROPERTIES
		VERSION ${SLUA_VERSION}
		SOVERSION ${SLUA_SOVERSION}
		CLEAN_DIRECT_OUTPUT 1
	)
endif(SLUA_LIBS)

# set rpath & handle framework
if(APPLE)
	set(INSTALL_NAME_DIR)
	# Set Dynamic Library and Framework properties
	if(WANT_FRAMEWORK)
		set_target_properties(slua_dynamic PROPERTIES
			FRAMEWORK TRUE
			FRAMEWORK_VERSION "${LUA_FRAMEWORK_VERSION_NUMBER}"
			PUBLIC_HEADER "${LUA_LIB_HEADERS}"
			RESOURCE "${RESOURCE_FILES}"
		)
		set(INSTALL_NAME_DIR ${CMAKE_FRAMEWORK_INSTALL_NAME_DIR})

		# Short Version is the "marketing version". It is the version
		# the user sees in an information panel.
		set(MACOSX_FRAMEWORK_SHORT_VERSION_STRING
						"${SLUA_VERSION_MAJOR}.${SLUA_VERSION_MINOR}.${SLUA_VERSION_PATCH}")
		# Bundle version is the version the OS looks at.
		set(MACOSX_FRAMEWORK_BUNDLE_VERSION
						"${SLUA_VERSION_MAJOR}.${SLUA_VERSION_MINOR}.${SLUA_VERSION_PATCH}")
		set(MACOSX_FRAMEWORK_IDENTIFIER "org.lua.slua")
	elseif(WANT_SHARED_LIBRARY)
		set_target_properties(slua_dynamic PROPERTIES
			FRAMEWORK FALSE
		)
		set(INSTALL_NAME_DIR ${CMAKE_DYLIB_INSTALL_NAME_DIR})
	endif(WANT_FRAMEWORK)

	if(INSTALL_NAME_DIR)
		set_target_properties(slua_dynamic PROPERTIES
			INSTALL_NAME_DIR ${INSTALL_NAME_DIR}
			BUILD_WITH_INSTALL_RPATH ${CMAKE_BUILD_WITH_INSTALL_RPATH}
		)
	else(INSTALL_NAME_DIR)
		# no install_name folder force BUILD_WITH_INSTALL_RPATH to OFF
		set_property(TARGET slua_dynamic PROPERTY BUILD_WITH_INSTALL_RPATH OFF)
	endif(INSTALL_NAME_DIR)

	set(CMAKE_OSX_ARCHITECTURES ${OSX_ARCHITECTURES})
elseif(WANT_SHARED_LIBRARY)
	set_target_properties(slua_dynamic PROPERTIES
		INSTALL_RPATH ${CMAKE_INSTALL_RPATH}
		BUILD_WITH_INSTALL_RPATH ${CMAKE_BUILD_WITH_INSTALL_RPATH}
	)
endif(APPLE)

#
# Lua compiler
#
add_executable(sluac ${SLUAC_SRC})
add_target_properties(sluac COMPILE_FLAGS "${COMMON_CFLAGS}")
add_target_properties(sluac LINK_FLAGS "${LD_FLAGS} ${COMMON_LDFLAGS}")
target_link_libraries(sluac slua_static)
set(SLUA_BINS ${SLUA_BINS} sluac)

#
# build as a cross-compiler
#
if(MINGW)
	set(SLUA_COMPILER "${CMAKE_CURRENT_BINARY_DIR}/slua-compiler")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/slua-compiler_mingw.in" "${SLUA_COMPILER}" @ONLY)
else(MINGW)
	set(SLUA_COMPILER "${CMAKE_CURRENT_BINARY_DIR}/slua-compiler")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/slua-compiler.in" "${SLUA_COMPILER}" @ONLY)
endif(MINGW)

#
# Lua stand-alone interpreter
#
add_executable(slua_binary ${SLUA_SRC})
add_target_properties(slua_binary COMPILE_FLAGS "${COMMON_CFLAGS}")
add_target_properties(slua_binary LINK_FLAGS "${LD_FLAGS} ${COMMON_LDFLAGS}")
target_link_libraries(slua_binary ${SLUA_MAIN_LIB})
# rename slua.bin to slua
set_target_properties(slua_binary PROPERTIES OUTPUT_NAME slua)
set(SLUA_BINS ${SLUA_BINS} slua_binary)

#
# install slua/sluac & library.
#
if(APPLE AND WANT_SHARED_LIBRARY AND WANT_FRAMEWORK)
	# Make directory: slua.framework/Versions/5.1/MacOS
	add_custom_command(
		TARGET slua_dynamic
		POST_BUILD
		COMMAND ${CMAKE_COMMAND}
		ARGS -E make_directory "${slua_BINARY_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_VERSIONED_EXECUTABLE_DIR}"
		COMMENT "Command line tools")

	# Make directory: slua.framework/Versions/5.1/lib
	add_custom_command(
		TARGET slua_dynamic
		POST_BUILD
		COMMAND ${CMAKE_COMMAND}
		ARGS -E make_directory "${slua_BINARY_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_VERSIONED_LIB_DIR}"
		COMMENT "Static lib")

	# Copy slua to: slua.framework/Versions/5.1/MacOS/slua
	add_custom_command(
		TARGET slua_dynamic slua_binary
		POST_BUILD
		COMMAND ${CMAKE_COMMAND}
		ARGS -E copy "${slua_BINARY_DIR}/slua" "${slua_BINARY_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_VERSIONED_EXECUTABLE_DIR}/slua"
		COMMENT "Command line tools")

	# Copy sluac to: slua.framework/Versions/5.1/MacOS/sluac
	add_custom_command(
		TARGET slua_dynamic sluac
		POST_BUILD
		COMMAND ${CMAKE_COMMAND}
		ARGS -E copy ${slua_BINARY_DIR}/sluac ${slua_BINARY_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_VERSIONED_EXECUTABLE_DIR}/sluac
		COMMENT "Command line tools")

	# Copy liblua.a to: slua.framework/Versions/5.1/lib/liblua.a
	add_custom_command(
		TARGET slua_dynamic slua_static
		POST_BUILD
		COMMAND ${CMAKE_COMMAND}
		ARGS -E copy "${slua_BINARY_DIR}/liblua.a" "${slua_BINARY_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_VERSIONED_LIB_DIR}/liblua.a"
		COMMENT "Static lib")

	# Will install framework to /Library/Frameworks directory or user specified
	install(TARGETS slua_dynamic
		FRAMEWORK DESTINATION ${CMAKE_FRAMEWORK_INSTALL_DIR}
	)

	if(LUA_FRAMEWORK_SYMLINKS)
		install(CODE "EXEC_PROGRAM(${CMAKE_COMMAND} ARGS -E make_directory \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin\")")

		# create a symbolic link for slua
		# and add it to the install manifest
		install(CODE "EXEC_PROGRAM(${CMAKE_COMMAND} ARGS -E create_symlink \"${CMAKE_FRAMEWORK_INSTALL_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_CURRENT_EXECUTABLE_DIR}/slua\" \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/lua\")
		list(APPEND CMAKE_INSTALL_MANIFEST_FILES \"${CMAKE_INSTALL_PREFIX}/bin/slua\")
		")

		# create a symbolic link for sluac
		# and add it to the install manifest
		install(CODE "EXEC_PROGRAM(${CMAKE_COMMAND} ARGS -E create_symlink \"${CMAKE_FRAMEWORK_INSTALL_DIR}/${LUA_FRAMEWORK_NAME}/${LUA_FRAMEWORK_CURRENT_EXECUTABLE_DIR}/sluac\" \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/luac\")
		list(APPEND CMAKE_INSTALL_MANIFEST_FILES \"${CMAKE_INSTALL_PREFIX}/bin/sluac\")
		")
	endif(LUA_FRAMEWORK_SYMLINKS)

else(APPLE AND WANT_SHARED_LIBRARY AND WANT_FRAMEWORK)
	install(TARGETS ${SLUA_BINS}
		RUNTIME DESTINATION bin
	)
	install(FILES ${SLUA_COMPILER}
		DESTINATION bin
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
		WORLD_WRITE WORLD_EXECUTE
	)

	if(SLUA_LIBS)
		install(TARGETS ${SLUA_LIBS}
			LIBRARY DESTINATION lib
			ARCHIVE DESTINATION lib
		)
		install(FILES ${CORE_LIB_INCLUDES} ${BUILD_CONFIG_H}
			DESTINATION include/slua)
	endif(SLUA_LIBS)

endif(APPLE AND WANT_SHARED_LIBRARY AND WANT_FRAMEWORK)

