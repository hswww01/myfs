cmake_minimum_required(VERSION 3.25)

project(cryptfs VERSION 0.1.0 LANGUAGES C RC)

if(NOT WIN32)
	message(FATAL_ERROR "cryptfs targets Windows + WinFsp only")
endif()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
	message(FATAL_ERROR "32-bit Windows builds are not supported")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(MSVC)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(zstd CONFIG REQUIRED)

set(WINFSP_ROOT "C:/Program Files (x86)/WinFsp" CACHE PATH "WinFsp installation root")
set(WINFSP_SOURCE_ROOT "D:/src/winfsp-memfs-static" CACHE PATH
	"Existing validated WinFsp source tree with static user-mode library")
set(WINFSP_EXPECTED_VERSION "2.1" CACHE STRING "Expected WinFsp major.minor version")
set(WINFSP_STATIC_LIBRARY "" CACHE FILEPATH "Prebuilt static WinFsp user-mode library")
set(WINFSP_DRIVER_X64_SOURCE "" CACHE FILEPATH "Signed WinFsp x64 driver to embed")
set(WINFSP_DRIVER_ARM64_SOURCE "" CACHE FILEPATH "Signed WinFsp ARM64 driver to embed")

set(_winfsp_inc_hints "${WINFSP_SOURCE_ROOT}/inc" "${WINFSP_ROOT}/inc")
set(_winfsp_bin_hints "${WINFSP_ROOT}/bin")
file(GLOB _winfsp_sxs_bin_hints LIST_DIRECTORIES true "${WINFSP_ROOT}/SxS/sxs.*/bin")
if(_winfsp_sxs_bin_hints)
	list(SORT _winfsp_sxs_bin_hints COMPARE NATURAL ORDER DESCENDING)
	list(PREPEND _winfsp_bin_hints ${_winfsp_sxs_bin_hints})
endif()

if(NOT WINFSP_STATIC_LIBRARY)
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(_winfsp_static_config Debug)
	else()
		set(_winfsp_static_config Release)
	endif()
	set(_winfsp_static_candidate
		"${WINFSP_SOURCE_ROOT}/build/VStudio/build/${_winfsp_static_config}/winfsp-static-x64.lib")
	if(EXISTS "${_winfsp_static_candidate}")
		set(WINFSP_STATIC_LIBRARY "${_winfsp_static_candidate}" CACHE FILEPATH
			"Prebuilt static WinFsp user-mode library" FORCE)
	endif()
endif()
if(NOT WINFSP_STATIC_LIBRARY OR NOT EXISTS "${WINFSP_STATIC_LIBRARY}")
	message(FATAL_ERROR "Set WINFSP_STATIC_LIBRARY or prepare the static library under WINFSP_SOURCE_ROOT")
endif()

if(NOT WINFSP_INCLUDE_DIR)
	find_path(WINFSP_INCLUDE_DIR NAMES winfsp/winfsp.h HINTS ${_winfsp_inc_hints} REQUIRED)
endif()
if(WINFSP_DRIVER_X64_SOURCE)
	set(WINFSP_DRIVER_X64 "${WINFSP_DRIVER_X64_SOURCE}")
else()
	find_file(WINFSP_DRIVER_X64 NAMES winfsp-x64.sys HINTS ${_winfsp_bin_hints} REQUIRED)
endif()
if(WINFSP_DRIVER_ARM64_SOURCE)
	set(WINFSP_DRIVER_ARM64 "${WINFSP_DRIVER_ARM64_SOURCE}")
else()
	find_file(WINFSP_DRIVER_ARM64 NAMES winfsp-a64.sys HINTS ${_winfsp_bin_hints} REQUIRED)
endif()
if(NOT EXISTS "${WINFSP_DRIVER_X64}" OR NOT EXISTS "${WINFSP_DRIVER_ARM64}")
	message(FATAL_ERROR "Matching signed x64 and ARM64 WinFsp drivers are required")
endif()

find_program(CRYPTFS_POWERSHELL_EXECUTABLE NAMES pwsh.exe powershell.exe REQUIRED)
set(_winfsp_driver_provenance_json "${CMAKE_CURRENT_BINARY_DIR}/winfsp-driver-provenance.json")
execute_process(
	COMMAND "${CRYPTFS_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive
		-ExecutionPolicy Bypass
		-File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/verify-winfsp-drivers.ps1"
		-X64Path "${WINFSP_DRIVER_X64}"
		-Arm64Path "${WINFSP_DRIVER_ARM64}"
		-OutputJson "${_winfsp_driver_provenance_json}"
	RESULT_VARIABLE _winfsp_provenance_result
	OUTPUT_VARIABLE _winfsp_provenance_output
	ERROR_VARIABLE _winfsp_provenance_error)
if(NOT _winfsp_provenance_result EQUAL 0)
	message(FATAL_ERROR "WinFsp driver provenance check failed: ${_winfsp_provenance_error}${_winfsp_provenance_output}")
endif()

# This check uses the user-mode static library and embeds only the matching
# signed WinFsp driver resources. It never changes the installed system driver.
get_filename_component(FS_FRONTEND_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../frontend" ABSOLUTE)
add_subdirectory("${FS_FRONTEND_SOURCE_DIR}"
	"${CMAKE_CURRENT_BINARY_DIR}/shared-frontend" EXCLUDE_FROM_ALL)

file(TO_CMAKE_PATH "${WINFSP_DRIVER_X64}" WINFSP_DRIVER_X64_RC)
file(TO_CMAKE_PATH "${WINFSP_DRIVER_ARM64}" WINFSP_DRIVER_ARM64_RC)
set(WINFSP_RUNTIME_RESOURCE "")
configure_file(src/cryptfs_resources.rc.in
	"${CMAKE_CURRENT_BINARY_DIR}/cryptfs_resources.rc" @ONLY)

add_library(cryptfs_core STATIC
	src/cryptfs_crypto.c
	src/cryptfs_store.c
	src/cryptfs_backend.c)
target_include_directories(cryptfs_core PUBLIC src "${FS_FRONTEND_SOURCE_DIR}/include")
target_include_directories(cryptfs_core SYSTEM PRIVATE "${WINFSP_INCLUDE_DIR}")
target_compile_definitions(cryptfs_core PRIVATE
	_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX WINFSP_STATIC CRYPTFS_WINFSP_STATIC=1)
target_link_libraries(cryptfs_core PUBLIC
	fs_frontend
	unofficial-sodium::sodium
	zstd::libzstd
	bcrypt
	advapi32
	credui netapi32 rpcrt4 secur32 shlwapi version wldap32)

add_executable(cryptfs
	src/main.c
	src/cryptfs_driver.c
	"${CMAKE_CURRENT_BINARY_DIR}/cryptfs_resources.rc")
target_include_directories(cryptfs PRIVATE src)
target_include_directories(cryptfs SYSTEM PRIVATE "${WINFSP_INCLUDE_DIR}")
target_compile_definitions(cryptfs PRIVATE
	_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE WINFSP_STATIC CRYPTFS_WINFSP_STATIC=1)
target_link_libraries(cryptfs PRIVATE cryptfs_core bcrypt advapi32 shell32 credui netapi32 rpcrt4 secur32 shlwapi version)
# Unlock validates the namespace recursively (depth up to 64, ~8 KiB per
# level plus block buffers); keep ample headroom over the 1 MiB default.
if(MSVC)
	target_link_options(cryptfs PRIVATE /STACK:8388608)
endif()

add_executable(cryptfs_static_import_test tests/cryptfs_static_import_test.c)
add_executable(cryptfs_resource_test tests/cryptfs_resource_test.c)
target_include_directories(cryptfs_resource_test PRIVATE src)
target_compile_definitions(cryptfs_resource_test PRIVATE CRYPTFS_WINFSP_STATIC=1)

add_executable(cryptfs_winfsp_version_test tests/cryptfs_winfsp_version_test.c)
target_include_directories(cryptfs_winfsp_version_test SYSTEM PRIVATE "${WINFSP_INCLUDE_DIR}")
if(NOT WINFSP_EXPECTED_VERSION MATCHES "^([0-9]+)\\.([0-9]+)$")
	message(FATAL_ERROR "WINFSP_EXPECTED_VERSION must be major.minor, got '${WINFSP_EXPECTED_VERSION}'")
endif()
math(EXPR _cryptfs_winfsp_version_hex "(${CMAKE_MATCH_1} << 16) | ${CMAKE_MATCH_2}" OUTPUT_FORMAT HEXADECIMAL)
target_compile_definitions(cryptfs_winfsp_version_test PRIVATE
	WINFSP_STATIC CRYPTFS_EXPECTED_WINFSP_VERSION=${_cryptfs_winfsp_version_hex}U)
target_link_libraries(cryptfs_winfsp_version_test PRIVATE
	"${WINFSP_STATIC_LIBRARY}" credui netapi32 rpcrt4 secur32 shlwapi version wldap32)

foreach(_target cryptfs_core cryptfs cryptfs_static_import_test cryptfs_resource_test cryptfs_winfsp_version_test)
	if(MSVC)
		target_compile_options(${_target} PRIVATE /W4 /utf-8 /permissive-)
	endif()
endforeach()

include(CTest)
if(BUILD_TESTING)
	add_test(NAME cryptfs_static_winfsp_no_dll_import
		COMMAND cryptfs_static_import_test $<TARGET_FILE:cryptfs>)
	add_test(NAME cryptfs_embedded_winfsp_resources
		COMMAND cryptfs_resource_test $<TARGET_FILE:cryptfs>)
	add_test(NAME cryptfs_winfsp_static_version COMMAND cryptfs_winfsp_version_test)
	add_test(NAME cryptfs_winfsp_driver_provenance
		COMMAND "${CRYPTFS_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive
			-ExecutionPolicy Bypass
			-File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/verify-winfsp-drivers.ps1"
			-X64Path "${WINFSP_DRIVER_X64}"
			-Arm64Path "${WINFSP_DRIVER_ARM64}")

	if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_crypto.c")
		add_executable(cryptfs_crypto_test tests/test_crypto.c src/cryptfs_crypto.c)
		target_include_directories(cryptfs_crypto_test PRIVATE src)
		target_link_libraries(cryptfs_crypto_test PRIVATE unofficial-sodium::sodium zstd::libzstd)
		target_compile_definitions(cryptfs_crypto_test PRIVATE _CRT_SECURE_NO_WARNINGS)
		if(MSVC)
			target_compile_options(cryptfs_crypto_test PRIVATE /W4 /utf-8 /permissive-)
		endif()
		add_test(NAME cryptfs_crypto_test COMMAND cryptfs_crypto_test)
	endif()

	if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_store.c")
		add_executable(cryptfs_store_test
			tests/test_store.c
			src/cryptfs_crypto.c
			src/cryptfs_store.c)
		target_include_directories(cryptfs_store_test PRIVATE src)
		target_compile_definitions(cryptfs_store_test PRIVATE CRYPTFS_TESTING _CRT_SECURE_NO_WARNINGS)
		target_link_libraries(cryptfs_store_test PRIVATE unofficial-sodium::sodium zstd::libzstd bcrypt advapi32)
		if(MSVC)
			target_compile_options(cryptfs_store_test PRIVATE /W4 /utf-8 /permissive-)
		endif()
		if(MSVC)
			target_link_options(cryptfs_store_test PRIVATE /STACK:8388608)
		endif()
		add_test(NAME cryptfs_store_test COMMAND cryptfs_store_test)
		set_tests_properties(cryptfs_store_test PROPERTIES TIMEOUT 900)
	endif()

	if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.c")
		add_executable(cryptfs_cli_test tests/test_cli.c src/main.c src/cryptfs_driver.c)
		target_include_directories(cryptfs_cli_test PRIVATE src "${FS_FRONTEND_SOURCE_DIR}/include")
		target_compile_definitions(cryptfs_cli_test PRIVATE
			CRYPTFS_CLI_TESTING _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
		target_link_libraries(cryptfs_cli_test PRIVATE cryptfs_core)
		if(MSVC)
			target_compile_options(cryptfs_cli_test PRIVATE /W4 /utf-8 /permissive-)
		endif()
		add_test(NAME cryptfs_cli_test COMMAND cryptfs_cli_test)
	endif()
endif()
