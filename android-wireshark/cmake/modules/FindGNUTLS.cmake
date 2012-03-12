#
# $Id: FindGNUTLS.cmake 30104 2009-09-23 19:40:25Z jmayer $
#
# - Find gnutls
# Find the native GNUTLS includes and library
#
#  GNUTLS_INCLUDE_DIRS - where to find gnutls.h, etc.
#  GNUTLS_LIBRARIES    - List of libraries when using gnutls.
#  GNUTLS_FOUND        - True if gnutls found.


IF (GNUTLS_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(GNUTLS_FIND_QUIETLY TRUE)
ENDIF (GNUTLS_INCLUDE_DIRS)

FIND_PATH(GNUTLS_INCLUDE_DIR
	NAMES
	  gnutls.h
	  gnutls/gnutls.h
#	PATHS
)

SET(GNUTLS_NAMES gnutls)
FIND_LIBRARY(GNUTLS_LIBRARY NAMES ${GNUTLS_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set GNUTLS_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GNUTLS DEFAULT_MSG GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR)

IF(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES ${GNUTLS_LIBRARY} )
ELSE(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES )
ENDIF(GNUTLS_FOUND)

MARK_AS_ADVANCED( GNUTLS_LIBRARIES GNUTLS_INCLUDE_DIRS )
