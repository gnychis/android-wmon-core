#
# $Id: UseMakeTapReg.cmake 33616 2010-07-22 12:18:36Z stig $
#
MACRO(REGISTER_TAP_FILES _outputfile )
	set( _sources ${ARGN} )
    ADD_CUSTOM_COMMAND(
        OUTPUT
          ${_outputfile}
        COMMAND ${SHELL}
          ${CMAKE_SOURCE_DIR}/tools/make-tapreg-dotc
          ${_outputfile}
          ${CMAKE_CURRENT_SOURCE_DIR}
          ${_sources}
        DEPENDS
          ${CMAKE_SOURCE_DIR}/tools/make-tapreg-dotc
          ${_sources}
    )
ENDMACRO(REGISTER_TAP_FILES)

