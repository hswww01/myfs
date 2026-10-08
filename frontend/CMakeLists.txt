cmake_minimum_required(VERSION 3.25)

if(NOT WIN32)
	message(FATAL_ERROR "fs_frontend targets Windows and WinFsp only")
endif()

if(NOT DEFINED WINFSP_INCLUDE_DIR OR NOT EXISTS "${WINFSP_INCLUDE_DIR}/winfsp/winfsp.h")
	message(FATAL_ERROR "Set WINFSP_INCLUDE_DIR before adding fs_frontend")
endif()

if(DEFINED WINFSP_STATIC_LIBRARY AND EXISTS "${WINFSP_STATIC_LIBRARY}")
	set(_fs_frontend_winfsp_library "${WINFSP_STATIC_LIBRARY}")
elseif(DEFINED WINFSP_LIBRARY AND EXISTS "${WINFSP_LIBRARY}")
	set(_fs_frontend_winfsp_library "${WINFSP_LIBRARY}")
else()
	message(FATAL_ERROR "Set WINFSP_STATIC_LIBRARY or WINFSP_LIBRARY before adding fs_frontend")
endif()

add_library(fs_frontend STATIC
	src/fs_frontend_winfsp.c
	src/fs_frontend_service.c
	src/fs_frontend_gui.c)
target_compile_features(fs_frontend PUBLIC c_std_17)
target_include_directories(fs_frontend
	PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(fs_frontend SYSTEM
	PUBLIC "${WINFSP_INCLUDE_DIR}")
target_compile_definitions(fs_frontend
	PUBLIC WINFSP_STATIC
	PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(fs_frontend
	PUBLIC "${_fs_frontend_winfsp_library}" advapi32
	PRIVATE user32 gdi32 comctl32 comdlg32 shell32 ole32)

if(MSVC)
	target_compile_options(fs_frontend PRIVATE /W4 /utf-8 /permissive-)
endif()
