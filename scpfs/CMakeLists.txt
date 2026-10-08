cmake_minimum_required(VERSION 3.25)

project(scpfs VERSION 0.1.0 LANGUAGES C RC)

if(NOT WIN32)
	message(FATAL_ERROR "scpfs currently targets Windows + WinFsp only")
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

find_package(OpenSSL CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
if(NOT TARGET OpenSSL::Crypto)
	# vcpkg's single-config OpenSSL config may defer target creation to its
	# module wrapper; provide the static imported targets libssh2 expects.
	get_filename_component(_openssl_triplet_root
		"${OpenSSL_DIR}/../.." ABSOLUTE)
	add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
	set_target_properties(OpenSSL::Crypto PROPERTIES
		IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
		IMPORTED_LOCATION_DEBUG "${_openssl_triplet_root}/debug/lib/libcrypto.lib"
		IMPORTED_LOCATION_RELEASE "${_openssl_triplet_root}/lib/libcrypto.lib"
		INTERFACE_INCLUDE_DIRECTORIES "${_openssl_triplet_root}/include"
		INTERFACE_LINK_LIBRARIES "ws2_32;gdi32;advapi32;crypt32;user32")
	add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
	set_target_properties(OpenSSL::SSL PROPERTIES
		IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
		IMPORTED_LOCATION_DEBUG "${_openssl_triplet_root}/debug/lib/libssl.lib"
		IMPORTED_LOCATION_RELEASE "${_openssl_triplet_root}/lib/libssl.lib"
		INTERFACE_INCLUDE_DIRECTORIES "${_openssl_triplet_root}/include"
		INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto")
endif()
find_package(libssh2 CONFIG REQUIRED)
find_program(SCPFS_POWERSHELL_EXECUTABLE NAMES pwsh.exe powershell.exe REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(SCPFS_WATCH_EMBEDDED_HEADER "${CMAKE_CURRENT_BINARY_DIR}/scpfs_watch_embedded.h")
add_custom_command(
	OUTPUT "${SCPFS_WATCH_EMBEDDED_HEADER}"
	COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed-watch.py"
		--input "${CMAKE_CURRENT_SOURCE_DIR}/server/scpfs_watch.py"
		--output "${SCPFS_WATCH_EMBEDDED_HEADER}"
	DEPENDS
		"${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed-watch.py"
		"${CMAKE_CURRENT_SOURCE_DIR}/server/scpfs_watch.py"
	VERBATIM)

set(WINFSP_ROOT "C:/Program Files (x86)/WinFsp" CACHE PATH "WinFsp installation root")
set(WINFSP_SOURCE_ROOT "D:/src/winfsp-memfs-static" CACHE PATH
	"WinFsp source tree with static user-mode library")
set(WINFSP_EXPECTED_VERSION "" CACHE STRING "Expected WinFsp major.minor version")
set(WINFSP_STATIC_LIBRARY "" CACHE FILEPATH "Prebuilt static WinFsp user-mode library")
set(WINFSP_DRIVER_X64_SOURCE "" CACHE FILEPATH "Signed WinFsp x64 driver to embed")
set(WINFSP_DRIVER_ARM64_SOURCE "" CACHE FILEPATH "Signed WinFsp ARM64 driver to embed")

set(_winfsp_inc_hints "${WINFSP_SOURCE_ROOT}/inc" "${WINFSP_ROOT}/inc")
set(_winfsp_bin_hints "${WINFSP_ROOT}/bin")
file(GLOB _winfsp_sxs_bin_hints LIST_DIRECTORIES true
	"${WINFSP_ROOT}/SxS/sxs.*/bin")
if(_winfsp_sxs_bin_hints)
	list(SORT _winfsp_sxs_bin_hints COMPARE NATURAL ORDER DESCENDING)
	list(PREPEND _winfsp_bin_hints ${_winfsp_sxs_bin_hints})
endif()

if(NOT WINFSP_STATIC_LIBRARY AND WINFSP_SOURCE_ROOT)
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
	message(FATAL_ERROR
		"A static WinFsp library is required; set WINFSP_STATIC_LIBRARY or build it under WINFSP_SOURCE_ROOT")
endif()

find_path(WINFSP_INCLUDE_DIR NAMES winfsp/winfsp.h HINTS ${_winfsp_inc_hints} REQUIRED)
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
	message(FATAL_ERROR "Matching signed x64 and ARM64 WinFsp driver files are required")
endif()

set(_winfsp_driver_provenance_json "${CMAKE_CURRENT_BINARY_DIR}/winfsp-driver-provenance.json")
execute_process(
	COMMAND "${SCPFS_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive
		-ExecutionPolicy Bypass
		-File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/verify-winfsp-drivers.ps1"
		-X64Path "${WINFSP_DRIVER_X64}"
		-Arm64Path "${WINFSP_DRIVER_ARM64}"
		-OutputJson "${_winfsp_driver_provenance_json}"
	RESULT_VARIABLE _winfsp_provenance_result
	OUTPUT_VARIABLE _winfsp_provenance_output
	ERROR_VARIABLE _winfsp_provenance_error)
if(NOT _winfsp_provenance_result EQUAL 0)
	message(FATAL_ERROR "WinFsp embedded driver verification failed: ${_winfsp_provenance_error}${_winfsp_provenance_output}")
endif()

function(_scpfs_read_driver_version driver_path out_full out_canonical)
	execute_process(
		COMMAND "${SCPFS_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive -Command
			"(Get-Item -LiteralPath '${driver_path}').VersionInfo.FileVersion"
		RESULT_VARIABLE _version_result OUTPUT_VARIABLE _file_version
		ERROR_VARIABLE _version_error OUTPUT_STRIP_TRAILING_WHITESPACE)
	if(NOT _version_result EQUAL 0)
		message(FATAL_ERROR "Cannot read WinFsp driver version: ${_version_error}")
	endif()
	string(REGEX MATCH "^([0-9]+)\\.([0-9]+)" _version_match "${_file_version}")
	if(NOT _version_match)
		message(FATAL_ERROR "Cannot parse WinFsp driver version '${_file_version}'")
	endif()
	set(${out_full} "${_file_version}" PARENT_SCOPE)
	set(${out_canonical} "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}" PARENT_SCOPE)
endfunction()

set(_winfsp_source_version "")
if(WINFSP_SOURCE_ROOT AND EXISTS "${WINFSP_SOURCE_ROOT}/build/VStudio/build.version.props")
	file(STRINGS "${WINFSP_SOURCE_ROOT}/build/VStudio/build.version.props"
		_winfsp_version_line REGEX "<MyCanonicalVersion>[0-9]+\\.[0-9]+</MyCanonicalVersion>" LIMIT_COUNT 1)
	if(_winfsp_version_line)
		string(REGEX REPLACE ".*<MyCanonicalVersion>([0-9]+\\.[0-9]+)</MyCanonicalVersion>.*"
			"\\1" _winfsp_source_version "${_winfsp_version_line}")
	endif()
endif()
if(WINFSP_EXPECTED_VERSION)
	set(_winfsp_expected_version "${WINFSP_EXPECTED_VERSION}")
else()
	set(_winfsp_expected_version "${_winfsp_source_version}")
endif()
if(NOT _winfsp_expected_version)
	message(FATAL_ERROR "Set WINFSP_EXPECTED_VERSION or WINFSP_SOURCE_ROOT with build.version.props")
endif()
if(_winfsp_source_version AND NOT _winfsp_expected_version STREQUAL _winfsp_source_version)
	message(FATAL_ERROR "WINFSP_EXPECTED_VERSION disagrees with WinFsp source version")
endif()
_scpfs_read_driver_version("${WINFSP_DRIVER_X64}" _driver_x64_full _driver_x64_version)
_scpfs_read_driver_version("${WINFSP_DRIVER_ARM64}" _driver_arm64_full _driver_arm64_version)
if(NOT _driver_x64_version STREQUAL _winfsp_expected_version OR
	NOT _driver_arm64_version STREQUAL _winfsp_expected_version OR
	NOT _driver_x64_full STREQUAL _driver_arm64_full)
	message(FATAL_ERROR "Embedded drivers must match static WinFsp version ${_winfsp_expected_version}: x64=${_driver_x64_full}, ARM64=${_driver_arm64_full}")
endif()
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)$" _winfsp_version_match "${_winfsp_expected_version}")
if(NOT _winfsp_version_match)
	message(FATAL_ERROR "Expected WinFsp version must use major.minor form")
endif()
math(EXPR SCPFS_EXPECTED_WINFSP_VERSION "(${CMAKE_MATCH_1} << 16) | ${CMAKE_MATCH_2}" OUTPUT_FORMAT HEXADECIMAL)

add_subdirectory("D:/work/fs/frontend"
	"${CMAKE_CURRENT_BINARY_DIR}/shared-frontend" EXCLUDE_FROM_ALL)

file(TO_CMAKE_PATH "${WINFSP_DRIVER_X64}" WINFSP_DRIVER_X64_RC)
file(TO_CMAKE_PATH "${WINFSP_DRIVER_ARM64}" WINFSP_DRIVER_ARM64_RC)
set(WINFSP_RUNTIME_RESOURCE "")
configure_file(src/scpfs_resources.rc.in "${CMAKE_CURRENT_BINARY_DIR}/scpfs_resources.rc" @ONLY)

add_library(scpfs_core STATIC
	src/scp_cache.c
	src/scpfs.c
	src/scp_backend.c
	src/scp_watch.c
	"${SCPFS_WATCH_EMBEDDED_HEADER}")
target_include_directories(scpfs_core PUBLIC src)
target_include_directories(scpfs_core PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(scpfs_core SYSTEM PRIVATE "${WINFSP_INCLUDE_DIR}")
target_link_libraries(scpfs_core PUBLIC fs_frontend libssh2::libssh2 ole32 advapi32 dnsapi iphlpapi)
target_compile_definitions(scpfs_core PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX WINFSP_STATIC SCPFS_WINFSP_STATIC=1)
if(MSVC)
	target_compile_options(scpfs_core PRIVATE /W4 /utf-8 /permissive-)
endif()

add_executable(scpfs src/main.c src/scpfs_driver.c "${CMAKE_CURRENT_BINARY_DIR}/scpfs_resources.rc")
target_include_directories(scpfs PRIVATE "${WINFSP_INCLUDE_DIR}")
target_compile_definitions(scpfs PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE WINFSP_STATIC SCPFS_WINFSP_STATIC=1)
target_link_libraries(scpfs PRIVATE scpfs_core bcrypt advapi32 credui netapi32 rpcrt4 secur32 shlwapi version wldap32)
if(MSVC)
	target_compile_options(scpfs PRIVATE /W4 /utf-8 /permissive-)
endif()

add_executable(scpfs_static_import_test tests/scpfs_static_import_test.c)
target_compile_definitions(scpfs_static_import_test PRIVATE _CRT_SECURE_NO_WARNINGS)

add_executable(scpfs_cache_test tests/scp_cache_test.c src/scp_cache.c)
target_include_directories(scpfs_cache_test PRIVATE src)
target_compile_definitions(scpfs_cache_test PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(scpfs_cache_test PRIVATE ole32)
if(MSVC)
	target_compile_options(scpfs_cache_test PRIVATE /W4 /utf-8 /permissive-)
endif()

include(CTest)
if(BUILD_TESTING)
	add_test(NAME scpfs_help COMMAND scpfs --help)
	add_test(NAME scpfs_cli_invalid_options COMMAND scpfs --invalid-option)
	set_tests_properties(scpfs_cli_invalid_options PROPERTIES WILL_FAIL TRUE)
	add_test(NAME scpfs_cli_cache_options
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_cache_options_test.py"
		--exe "$<TARGET_FILE:scpfs>")
	add_test(NAME scpfs_version COMMAND scpfs --version)
	add_test(NAME scpfs_static_import_gate COMMAND scpfs_static_import_test $<TARGET_FILE:scpfs>)
	add_test(NAME scpfs_cache_unit COMMAND scpfs_cache_test)
	add_test(NAME scpfs_watch_helper_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/watch_helper_test.py"
		"${CMAKE_CURRENT_SOURCE_DIR}/server/scpfs_watch.py")
	set_tests_properties(scpfs_watch_helper_integration PROPERTIES
		LABELS "integration;watch;wsl" TIMEOUT 120)
	add_test(NAME scpfs_ssh_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/ssh_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/ssh-integration")
	file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/gui-validation-tmp")
	set_tests_properties(scpfs_ssh_integration PROPERTIES
		LABELS "integration;ssh" TIMEOUT 120
		ENVIRONMENT "TMP=${CMAKE_CURRENT_BINARY_DIR}/gui-validation-tmp;TEMP=${CMAKE_CURRENT_BINARY_DIR}/gui-validation-tmp")
	add_test(NAME scpfs_mount_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/mount_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/mount-integration")
	set_tests_properties(scpfs_mount_integration PROPERTIES LABELS "integration;winfsp" TIMEOUT 180)
	add_test(NAME scpfs_cache_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/cache_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/cache-integration")
	set_tests_properties(scpfs_cache_integration PROPERTIES LABELS "integration;cache;winfsp;wsl" TIMEOUT 240)
	add_test(NAME scpfs_cache_access_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/cache_access_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/cache-access-integration")
	set_tests_properties(scpfs_cache_access_integration PROPERTIES
		LABELS "integration;cache;winfsp;wsl" TIMEOUT 240)
	add_test(NAME scpfs_gui_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/gui_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/gui-integration")
	set_tests_properties(scpfs_gui_integration PROPERTIES LABELS "integration;gui;winfsp" TIMEOUT 240)
	add_test(NAME scpfs_service_integration
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/service_integration.py"
		--exe "$<TARGET_FILE:scpfs>" --build-dir "${CMAKE_CURRENT_BINARY_DIR}/service-integration")
	set_tests_properties(scpfs_service_integration PROPERTIES
		LABELS "integration;scm;winfsp" TIMEOUT 300)
	set_tests_properties(scpfs_ssh_integration scpfs_mount_integration scpfs_cache_integration scpfs_cache_access_integration scpfs_gui_integration scpfs_service_integration
		PROPERTIES SKIP_RETURN_CODE 77)
endif()
