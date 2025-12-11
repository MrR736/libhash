# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
#

#[=======================================================================[.rst:
CMakeWindowsMingw32
--------------



Creating And Installing JARs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. write_resource_file:

.. command:: write_resource_file

  Creates a resource file::

    write_resource_file(<target_name>
                        [FILEFLAGSMASK (SIGNATURE|STRUCVERSION|[MASK|FILEMASK])]
                        [FILEFLAGS (RELEASE|DEBUG|PRERELEASE|PATCHED|PRIVATEBUILD|INFOINFERRED|SPECIALBUILD)]
                        [FILEOS (DOS|OS216|OS232|NT|[NT_WINDOWS32|NTWIN32]|WINCE|BASE|PM16|PM32|
                                [WINDOWS16|WIN16]|[WINDOWS32|WIN32]|[OS2PM16|OS216_PM16]|
                                [OS2PM32|OS232_PM32]|[DOS_WINDOWS16|DOS16]|[DOS_WINDOWS32|DOS32]|[UNKNOWN|NONE])]
                        [FILETYPE ([APP|EXE|EXECUTABLE]|[DLL|SHARED]|DRV|[STATIC_LIB|STATIC]|VXD|FONT|[UNKNOWN|NONE])]
                        [FILESUBTYPE (PRINTER|KEYBOARD|LANGUAGE|DISPLAY|MOUSE|NETWORK|SYSTEM|
                                     INSTALLABLE|SOUND|[COMMON|COMM]|INPUTMETHOD|VERSIONED_PRINTER|
                                     RASTER|VECTOR|TRUETYPE|[UNKNOWN|NONE])]
                        [DESCRIPTION <description>]
                        [DATE <date>]
                        [WRITER <writer>]
                        [LICENSE <license>]
                        [HOMEPAGE_URL <url>]
                        [VERSION major.minor.patch]
                        [INTERNAL_NAME <name>]
                        [OUTPUT_NAME <name>]
                        [OUTPUT_DIR <dir>]
                       )

  ``VERSION``
    Adds a version.

.. add_resource:

.. command:: add_resource

  Creates a resource object file::

    add_resource(<target_name>
                 [RESOURCE <resource>]
                 [FLAGS <flag>...]
                 [DEFINES <define>...]
                 [INCLUDES <include>...]]
                 [HEADERS <header>...]
                )

  ``RESOURCES``

    Adds the named ``<resource>`` the source file.

    For example::

      RESOURCE "a/path/to/resource.rc"

  ``FLAGS``

    Adds the named ``<flag>`` the Compile Flags.

    For example::
      FLAGS -Wall

  ``DEFINES``

    Adds the named ``<define>`` the Define Flags.

    For example::
      DEFINES _FILE_OFFSET_BITS=64

  ``INCLUDES``

    Adds the named ``<include>`` the include directorys.

    For example::
      INCLUDES a/path/include b/path/include

  ``HEADERS``

    Adds the named ``<header>`` the headers.

    For example::
      HEADERS a/path/include/myproj.h b/path/include/myproj2.h



#]=======================================================================]

include(Platform/Windows)
include(Platform/Windows-windres)

set(MINGW32 1)

set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")          # lib
if(CMAKE_SYSTEM_NAME STREQUAL "WindowsKernelModeDriver")
  set(CMAKE_SHARED_LIBRARY_SUFFIX ".sys")          # .so
else()
  set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")          # .so
endif()
set(CMAKE_IMPORT_LIBRARY_PREFIX "")
set(CMAKE_IMPORT_LIBRARY_SUFFIX ".lib")
set(CMAKE_EXECUTABLE_SUFFIX ".exe")          # .exe
set(CMAKE_LINK_LIBRARY_SUFFIX ".lib")
set(CMAKE_DL_LIBS "")
set(CMAKE_EXTRA_LINK_EXTENSIONS ".targets")

set(CMAKE_C_OUTPUT_EXTENSION .obj)
set(CMAKE_CXX_OUTPUT_EXTENSION .obj)

set(CMAKE_FIND_LIBRARY_PREFIXES
  "" # static or import library from MSVC tooling
  "lib" # static library from Meson with MSVC tooling
  )
set(CMAKE_FIND_LIBRARY_SUFFIXES
  ".dll.lib" # import library from Rust toolchain for MSVC ABI
  ".lib" # static or import library from MSVC tooling
  ".a" # static library from Meson with MSVC tooling
  )

if(WIN32)
	set(CMAKE_C_COMPILER "gcc.exe")
	set(CMAKE_CXX_COMPILER "g++.exe")
	set(CMAKE_CXX_COMPILER_AR "gcc-ar.exe")
	set(CMAKE_CXX_COMPILER_RANLIB "gcc-ranlib.exe")
	set(CMAKE_CXX_COMPILER_LINKER "ld.exe")
	set(CMAKE_RANLIB "ranlib.exe")
	set(CMAKE_AR "ar.exe")
	set(CMAKE_OBJDUMP "objdump.exe")
	set(CMAKE_OBJCOPY "objcopy.exe")
	set(CMAKE_READELF "readelf.exe")
	set(CMAKE_NM "nm.exe")
	set(CMAKE_LINKER "ld.exe")
	set(CMAKE_STRIP "strip.exe")
	set(CMAKE_ADDR2LINE "addr2line.exe")

	set(CMAKE_RC_COMPILER "windres.exe")
	set(CMAKE_DLLTOOL "dlltool.exe")
	set(CMAKE_DLLWRAP "dllwrap.exe")
else()
	if(	${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
		set(MINGW32_REQUIRED "x86_64-w64-mingw32")
	elseif(	${CMAKE_SYSTEM_PROCESSOR} MATCHES "i[4-6]86")
		set(MINGW32_REQUIRED "i686-w64-mingw32")
	endif()

	set(CMAKE_C_COMPILER "${MINGW32_REQUIRED}-gcc")
	set(CMAKE_CXX_COMPILER "${MINGW32_REQUIRED}-g++")
	set(CMAKE_CXX_COMPILER_AR "${MINGW32_REQUIRED}-gcc-ar")
	set(CMAKE_CXX_COMPILER_RANLIB "${MINGW32_REQUIRED}-gcc-ranlib")
	set(CMAKE_CXX_COMPILER_LINKER "${MINGW32_REQUIRED}-ld")

	set(CMAKE_AR "${MINGW32_REQUIRED}-ar")
	set(CMAKE_RANLIB "${MINGW32_REQUIRED}-ranlib")

	set(CMAKE_OBJDUMP "${MINGW32_REQUIRED}-objdump")
	set(CMAKE_OBJCOPY "${MINGW32_REQUIRED}-objcopy")
	set(CMAKE_READELF "${MINGW32_REQUIRED}-readelf")
	set(CMAKE_NM "${MINGW32_REQUIRED}-nm")
	set(CMAKE_LINKER "${MINGW32_REQUIRED}-ld")
	set(CMAKE_STRIP "${MINGW32_REQUIRED}-strip")
	set(CMAKE_ADDR2LINE "${MINGW32_REQUIRED}-addr2line")

	set(CMAKE_DLLTOOL "${MINGW32_REQUIRED}-dlltool")
	set(CMAKE_DLLWRAP "${MINGW32_REQUIRED}-dllwrap")
	set(CMAKE_RC_COMPILER "${MINGW32_REQUIRED}-windres")
endif()

macro(__mingw32_compiler lang)
	if(	CMAKE_${lang}_COMPILER_LINKER_ID STREQUAL "GNU"
		OR CMAKE_${lang}_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
		include(Platform/Windows-GNU-${lang})
	else()
		include(Platform/Windows-MSVC-${lang})
	endif()
endmacro()

function(WRITE_RESOURCE_FILE _TARGET_NAME)
	set(options)  # currently there are no zero value args (aka: options)
	set(oneValueArgs "FILEFLAGSMASK;FILEFLAGS;FILEOS;FILETYPE;FILESUBTYPE;DESCRIPTION;DATE;WRITER;LICENSE;HOMEPAGE_URL;OUTPUT_DIR;OUTPUT_NAME;VERSION;INTERNAL_NAME" )
	set(multiValueArgs "" )
	cmake_parse_arguments(	PARSE_ARGV 1 _WRF "${options}" "${oneValueArgs}" "${multiValueArgs}" )

	if (NOT DEFINED _WRF_OUTPUT_DIR)
		set(RESOURCE_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
	else()
		get_filename_component(RESOURCE_OUTPUT_DIR ${_WRF_OUTPUT_DIR} ABSOLUTE)
	endif()

	file (MAKE_DIRECTORY "${RESOURCE_OUTPUT_DIR}") # ensure output directory exists

	if(NOT DEFINED _WRF_OUTPUT_NAME AND NOT DEFINED _WRF_VERSION)
		set(RESOURCE_OUTPUT_NAME "${_TARGET_NAME}")
	elseif(NOT DEFINED _WRF_OUTPUT_NAME AND DEFINED _WRF_VERSION)
		set(RESOURCE_OUTPUT_NAME "${_TARGET_NAME}-${RESOURCE_VERSION}")
	elseif(DEFINED _WRF_OUTPUT_NAME AND DEFINED _WRF_VERSION)
		set(RESOURCE_OUTPUT_NAME "${_WRF_OUTPUT_NAME}-${RESOURCE_VERSION}")
	else()
		set(RESOURCE_OUTPUT_NAME "${_WRF_OUTPUT_NAME}")
	endif()

	if(NOT DEFINED _WRF_INTERNAL_NAME)
		set(RESOURCE_INTERNAL_NAME "${_TARGET_NAME}")
	else()
		set(RESOURCE_INTERNAL_NAME "${_WRF_INTERNAL_NAME}")
	endif()

	if (NOT DEFINED _WRF_DESCRIPTION)
		set(RESOURCE_DESCRIPTION "")
	else()
		set(RESOURCE_DESCRIPTION "${_WRF_DESCRIPTION}")
	endif()

	if (NOT DEFINED _WRF_DATE)
		string(TIMESTAMP RESOURCE_DATE "%Y" UTC)
	else()
		set(RESOURCE_DATE ${_WRF_DATE})
	endif()

	if (NOT DEFINED _WRF_WRITER)
		set(RESOURCE_WRITER "Unknown")
	else()
		set(RESOURCE_WRITER "${_WRF_WRITER}")
	endif()

	if (NOT DEFINED _WRF_LICENSE)
		set(RESOURCE_LICENSE "")
	else()
		set(RESOURCE_LICENSE " (${_WRF_LICENSE})")
	endif()

	if (NOT DEFINED _WRF_HOMEPAGE_URL)
		set(RESOURCE_HOMEPAGE_URL "")
	else()
		set(RESOURCE_HOMEPAGE_URL "${_WRF_HOMEPAGE_URL}")
	endif()

	if(	DEFINED _WRF_VERSION
		AND _WRF_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)")
		set(RESOURCE_VERSION_MAJOR "${CMAKE_MATCH_1}")
		set(RESOURCE_VERSION_MINOR "${CMAKE_MATCH_2}")
		set(RESOURCE_VERSION_PATCH "${CMAKE_MATCH_3}")

		if(NOT RESOURCE_VERSION_MAJOR VERSION_EQUAL 0)
			string(REGEX REPLACE "^0+" "" RESOURCE_VERSION_MAJOR "${RESOURCE_VERSION_MAJOR}")
		endif()
		if(NOT RESOURCE_VERSION_MINOR VERSION_EQUAL 0)
			string(REGEX REPLACE "^0+" "" RESOURCE_VERSION_MINOR "${RESOURCE_VERSION_MINOR}")
		endif()
		if(NOT RESOURCE_VERSION_PATCH VERSION_EQUAL 0)
			string(REGEX REPLACE "^0+" "" RESOURCE_VERSION_PATCH "${RESOURCE_VERSION_PATCH}")
		endif()

		set(RESOURCE_VERSION "${RESOURCE_VERSION_MAJOR}.${RESOURCE_VERSION_MINOR}.${RESOURCE_VERSION_PATCH}")
	elseif(DEFINED PROJECT_VERSION)
		set(RESOURCE_VERSION "${PROJECT_VERSION}")
		set(RESOURCE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
		set(RESOURCE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
		set(RESOURCE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
	else()
		set(RESOURCE_VERSION "0.0.0")
		set(RESOURCE_VERSION_MAJOR "0")
		set(RESOURCE_VERSION_MINOR "0")
		set(RESOURCE_VERSION_PATCH "0")
	endif()

	if (NOT DEFINED _WRF_FILEFLAGSMASK)
		set(RESOURCE_FILEFLAGSMASK "VS_FFI_FILEFLAGSMASK")
	elseif(_WRF_FILEFLAGSMASK STREQUAL "SIGNATURE"
			OR _WRF_FILEFLAGSMASK STREQUAL "STRUCVERSION")
		set(RESOURCE_FILEFLAGSMASK "VS_FFI_${_WRF_FILEFLAGSMASK}")
	elseif(	_WRF_FILEFLAGSMASK STREQUAL "MASK"
			OR _WRF_FILEFLAGSMASK STREQUAL "FILEMASK")
		set(RESOURCE_FILEFLAGSMASK "VS_FFI_FILEFLAGSMASK")
	else()
		if (DEFINED _WRF_FILEFLAGSMASK
			AND NOT (	_WRF_FILEFLAGSMASK STREQUAL "MASK"
					OR _WRF_FILEFLAGSMASK STREQUAL "FILEMASK"))
			message(STATUS "WARNING: File Flags Mask Unknown: \"${_WRF_FILEFLAGSMASK}\"")
		endif()
		set(RESOURCE_FILEFLAGSMASK "VS_FFI_FILEFLAGSMASK")
	endif()

	if (_WRF_FILEFLAGS STREQUAL "DEBUG"
		OR _WRF_FILEFLAGS STREQUAL "PRERELEASE"
		OR _WRF_FILEFLAGS STREQUAL "PATCHED"
		OR _WRF_FILEFLAGS STREQUAL "PRIVATEBUILD"
		OR _WRF_FILEFLAGS STREQUAL "INFOINFERRED"
		OR _WRF_FILEFLAGS STREQUAL "SPECIALBUILD")
		set(RESOURCE_FILEFLAGS "VS_FF_${_WRF_FILEOS}")
	else()
		if (DEFINED _WRF_FILEFLAGS
			AND NOT _WRF_FILEFLAGS STREQUAL "RELEASE")
			message(STATUS "WARNING: File Flags Unknown: \"${_WRF_FILEFLAGS}\"")
		endif()
		set(RESOURCE_FILEFLAGS "0")
	endif()

	if (NOT DEFINED _WRF_FILEOS)
		set(RESOURCE_FILEOS "VOS_UNKNOWN")
	elseif(_WRF_FILEOS STREQUAL "DOS"
		OR _WRF_FILEOS STREQUAL "OS216"
		OR _WRF_FILEOS STREQUAL "OS232"
		OR _WRF_FILEOS STREQUAL "NT"
		OR _WRF_FILEOS STREQUAL "DOS_WINDOWS16"
		OR _WRF_FILEOS STREQUAL "DOS_WINDOWS32"
		OR _WRF_FILEOS STREQUAL "NT_WINDOWS32"
		OR _WRF_FILEOS STREQUAL "OS216_PM16"
		OR _WRF_FILEOS STREQUAL "OS232_PM32"
		OR _WRF_FILEOS STREQUAL "WINCE")
		set(RESOURCE_FILEOS "VOS_${_WRF_FILEOS}")
	elseif(	_WRF_FILEOS STREQUAL "BASE"
			OR _WRF_FILEOS STREQUAL "PM16"
			OR _WRF_FILEOS STREQUAL "PM32"
			OR _WRF_FILEOS STREQUAL "WINDOWS16"
			OR _WRF_FILEOS STREQUAL "WINDOWS32")
		set(RESOURCE_FILEOS "VOS__${_WRF_FILEOS}")
	elseif(_WRF_FILEOS STREQUAL "WIN16")
		set(RESOURCE_FILEOS "VOS__WINDOWS16")
	elseif(_WRF_FILEOS STREQUAL "WIN32")
		set(RESOURCE_FILEOS "VOS__WINDOWS32")
	elseif(_WRF_FILEOS STREQUAL "OS2PM16")
		set(RESOURCE_FILEOS "VOS_OS216_PM16")
	elseif(_WRF_FILEOS STREQUAL "OS2PM32")
		set(RESOURCE_FILEOS "VOS_OS232_PM32")
	elseif(_WRF_FILEOS STREQUAL "DOS16")
		set(RESOURCE_FILEOS "VOS_DOS_WINDOWS16")
	elseif(_WRF_FILEOS STREQUAL "DOS32")
		set(RESOURCE_FILEOS "VOS_DOS_WINDOWS32")
	elseif(_WRF_FILEOS STREQUAL "NTWIN32")
		set(RESOURCE_FILEOS "VOS_NT_WINDOWS32")
	else()
		if (DEFINED _WRF_FILEOS
			AND NOT (	_WRF_FILEOS STREQUAL "UNKNOWN"
					OR _WRF_FILEOS STREQUAL "NONE"))
			message(STATUS "WARNING: File OS Unknown: \"${_WRF_FILEOS}\"")
		endif()
		set(RESOURCE_FILEOS "VOS_UNKNOWN")
	endif()

	if (_WRF_FILETYPE STREQUAL "APP"
		OR _WRF_FILETYPE STREQUAL "DLL"
		OR _WRF_FILETYPE STREQUAL "DRV"
		OR _WRF_FILETYPE STREQUAL "STATIC_LIB"
		OR _WRF_FILETYPE STREQUAL "VXD"
		OR _WRF_FILETYPE STREQUAL "FONT")
		set(RESOURCE_FILETYPE "VFT_${_WRF_FILETYPE}")
	elseif(	_WRF_FILETYPE STREQUAL "EXE"
			OR _WRF_FILETYPE STREQUAL "EXECUTABLE")
		set(RESOURCE_FILETYPE "VFT_APP")
	elseif(_WRF_FILETYPE STREQUAL "STATIC")
		set(RESOURCE_FILETYPE "VFT_STATIC_LIB")
	elseif(_WRF_FILETYPE STREQUAL "SHARED")
		set(RESOURCE_FILETYPE "VFT_DLL")
	else()
		if (DEFINED _WRF_FILETYPE
			AND NOT (	_WRF_FILETYPE STREQUAL "UNKNOWN"
						OR _WRF_FILETYPE STREQUAL "NONE"))
			message(STATUS "WARNING: File Type Unknown: \"${_WRF_FILETYPE}\"")
		endif()
		set(RESOURCE_FILETYPE "VFT_UNKNOWN")
	endif()

	if (_WRF_FILESUBTYPE STREQUAL "PRINTER"
		OR _WRF_FILESUBTYPE STREQUAL "KEYBOARD"
		OR _WRF_FILESUBTYPE STREQUAL "LANGUAGE"
		OR _WRF_FILESUBTYPE STREQUAL "DISPLAY"
		OR _WRF_FILESUBTYPE STREQUAL "MOUSE"
		OR _WRF_FILESUBTYPE STREQUAL "NETWORK"
		OR _WRF_FILESUBTYPE STREQUAL "SYSTEM"
		OR _WRF_FILESUBTYPE STREQUAL "INSTALLABLE"
		OR _WRF_FILESUBTYPE STREQUAL "SOUND"
		OR _WRF_FILESUBTYPE STREQUAL "COMM"
		OR _WRF_FILESUBTYPE STREQUAL "INPUTMETHOD"
		OR _WRF_FILESUBTYPE STREQUAL "VERSIONED_PRINTER")
		set(RESOURCE_FILESUBTYPE "VFT2_DRV_${_WRF_FILESUBTYPE}")
	elseif(	_WRF_FILESUBTYPE STREQUAL "COMMON")
		set(RESOURCE_FILESUBTYPE "VFT2_DRV_COMM")
	elseif(	_WRF_FILESUBTYPE STREQUAL "RASTER"
			OR _WRF_FILESUBTYPE STREQUAL "VECTOR"
			OR _WRF_FILESUBTYPE STREQUAL "TRUETYPE")
		set(RESOURCE_FILESUBTYPE "VFT2_FONT_${_WRF_FILESUBTYPE}")
	else()
		if (DEFINED _WRF_FILESUBTYPE
			AND NOT (	_WRF_FILESUBTYPE STREQUAL "UNKNOWN"
					OR _WRF_FILESUBTYPE STREQUAL "NONE"))
			message(STATUS "WARNING: File Sub Type Unknown: \"${_WRF_FILESUBTYPE}\"")
		endif()
		set(RESOURCE_FILESUBTYPE "VFT2_UNKNOWN")
	endif()

	configure_file(
		${CMAKE_CURRENT_SOURCE_DIR}/cmake/Resource.rc.in
		${RESOURCE_OUTPUT_DIR}/${RESOURCE_OUTPUT_NAME}.rc @ONLY
	)
endfunction()

function(ADD_RESOURCE _TARGET_NAME)
	set(options)  # currently there are no zero value args (aka: options)
	set(oneValueArgs "RESOURCE")
	set(multiValueArgs "FLAGS;DEFINES;INCLUDES;HEADERS")

	file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${_TARGET_NAME}.dir")

	cmake_parse_arguments(PARSE_ARGV 1 _FAR "${options}" "${oneValueArgs}" "${multiValueArgs}")

	if (_FAR_FLAGS)
		foreach(_RESOURCE_FLAGS IN LISTS _FAR_FLAGS)
			list(APPEND _RESOURCE_TARGET_FLAGS "${_RESOURCE_FLAGS}")
		endforeach()
	endif()

	if (_FAR_DEFINES)
		foreach(_RESOURCE_DEFINES IN LISTS _FAR_DEFINES)
			list(APPEND _RESOURCE_TARGET_FLAGS "-D${_RESOURCE_DEFINES}")
		endforeach()
	endif()

	if (_FAR_INCLUDES)
		foreach(_RESOURCE_INCLUDES IN LISTS _FAR_INCLUDES)
			list(APPEND _RESOURCE_TARGET_FLAGS "-I${_RESOURCE_INCLUDES}")
		endforeach()
	endif()

	if (_FAR_HEADERS)
		foreach(_RESOURCE_HEADERS IN LISTS _FAR_HEADERS)
			list(APPEND _RESOURCE_TARGET_FLAGS "-include ${_RESOURCE_HEADERS}")
		endforeach()
	endif()

	set(_RESOURCE_TARGET_OBJECT
		"${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${_TARGET_NAME}.dir/${_TARGET_NAME}.rc.o")
	add_custom_command(
		OUTPUT "${_RESOURCE_TARGET_OBJECT}"
		COMMAND	${CMAKE_RC_COMPILER} ${_RESOURCE_TARGET_FLAGS} -i ${_FAR_RESOURCE}
				-o "${_RESOURCE_TARGET_OBJECT}"
		COMMENT "Building WINRES object CMakeFiles/${_TARGET_NAME}.dir/${_TARGET_NAME}.rc.o"
	)

	add_library(${_TARGET_NAME} OBJECT IMPORTED)
	set_property(TARGET ${_TARGET_NAME} PROPERTY IMPORTED_OBJECTS "${_RESOURCE_TARGET_OBJECT}")
endfunction()
