#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "hv" for configuration "Release"
set_property(TARGET hv APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(hv PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/hv.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/hv.dll"
  )

list(APPEND _cmake_import_check_targets hv )
list(APPEND _cmake_import_check_files_for_hv "${_IMPORT_PREFIX}/lib/hv.lib" "${_IMPORT_PREFIX}/bin/hv.dll" )

# Import target "hv_static" for configuration "Release"
set_property(TARGET hv_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(hv_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C;CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/hv_static.lib"
  )

list(APPEND _cmake_import_check_targets hv_static )
list(APPEND _cmake_import_check_files_for_hv_static "${_IMPORT_PREFIX}/lib/hv_static.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
