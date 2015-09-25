PROJECT (analyseTCP CXX)
SET(CMAKE_VERBOSE_MAKEFILE off)
ENABLE_LANGUAGE(C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Available compile options:
# * WITH_DASH               - Compile with DASH
# * ONLY_DASH               - Only compile DASH
# * TESTS                   - Compile test executable
#
# Compile with dash:
# mkdir build && cd build
# cmake .. -DWITH_DASH=1
#
# To compile a debug build:
# cmake .. -DCMAKE_BUILD_TYPE=Debug
#
# To manually set compiler, e.g. gcc:
#  -DCMAKE_CXX_COMPILER=/usr/local/bin/gcc48
#
#
# Add more test files here when needed
SET (TEST_FILES tests/TestAnalyseTCP.h)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    ADD_DEFINITIONS(-DOS_LINUX)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    ADD_DEFINITIONS(-DOS_FREEBSD)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")

IF (APPLE)
    ADD_DEFINITIONS(-DOS_OSX)
ENDIF(APPLE)


INCLUDE (CheckTypeSize)

# Some problem with this check on OS X
IF (NOT APPLE)
   INCLUDE (CheckIncludeFiles)
   CHECK_INCLUDE_FILES ("arpa/inet.h" INET_H)
   CHECK_INCLUDE_FILES ("netinet/in.h" IN_H)
   CHECK_INCLUDE_FILES ("sys/socket.h" SOCKET_H)
   CHECK_INCLUDE_FILES ("getopt.h" GETOPT_H)
ENDIF (NOT APPLE)

# Check for library pcap
# If found, initialize include path and link path with correct values
FIND_LIBRARY (PCAP pcap ${LIB_DIRS})
IF (PCAP)
   MESSAGE (STATUS "Found pcap: ${PCAP}")
   FIND_PATH(PCAP_INCLUDE_PATH pcap.h ${INCLUDE_DIRS})
   GET_FILENAME_COMPONENT(PCAP_PATH ${PCAP} PATH)
   LINK_DIRECTORIES(${PCAP_PATH})
ELSE (PCAP)
   MESSAGE (FATAL_ERROR "ERROR: Could not find pcap")
ENDIF (PCAP)

SET (INCLUDE_FILES arpa/inet.h netinet/in.h sys/socket.h getopt.h)

CHECK_TYPE_SIZE(ulong HAVE_ULONG)

# test for C++11 flags
include(TestCXXAcceptsFlag)
CHECK_CXX_ACCEPTS_FLAG("-std=c++11" CXX_FLAG_CXX11)

IF (NOT CXX_FLAG_CXX11)
  MESSAGE(FATAL_ERROR "Compiler does not support c++11.")
ENDIF(NOT CXX_FLAG_CXX11)

# Set compiler flags for all configurations
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11") # We need c++11
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic") # Decent level of warnings
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-long-long -Wno-variadic-macros")
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow")

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wconversion -Wsign-conversion") # These two options are useless with gcc, as it's way too strict (See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=40752)
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfloat-equal") # Also too strict in gcc
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Qunused-arguments") # Clang warns about unused argument -std=c++11 in the linker command without this
endif()

# Add NDEBUG only for release version
# To activate: cmake -DCMAKE_BUILD_TYPE=Release ..
SET (CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wno-unused-parameter")

# Set debug compiler flags
# To activate: cmake -DCMAKE_BUILD_TYPE=Debug ..
SET (CMAKE_CXX_FLAGS_DEBUG "-g3 -DDEBUG")

# Must be below the compiler flags
INCLUDE(FindSharedPtr)
FIND_SHARED_PTR()
IF (NOT SHARED_PTR_FOUND)
  MESSAGE(FATAL_ERROR "Unable to find shared_ptr.")
ENDIF (NOT SHARED_PTR_FOUND)


CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

SET (BASE_SRC
  Dump.cc Dump.h
  Statistics.cc Statistics.h
  statistics_common.cc statistics_common.h
  Connection.cc Connection.h
  RangeManager.cc RangeManager.h
  ByteRange.cc ByteRange.h
  common.cc common.h
  fourTuple.cc fourTuple.h
  util.cc util.h
  color_print.c color_print.h
  time_util.c time_util.h
  )

# Prepare sources for app.
SET (TCP_SRC ${BASE_SRC} analyseTCP.cc)

SET (DASH_SRC ${BASE_SRC} analyseDASH.cc)

IF (NOT ONLY_DASH)
  MESSAGE (STATUS "Build analyseTCP enabled")
  ADD_EXECUTABLE (analyseTCP ${TCP_SRC})
  TARGET_LINK_LIBRARIES (analyseTCP pcap)
ENDIF(NOT ONLY_DASH)

IF (WITH_DASH)
  MESSAGE (STATUS "Build analyseDASH enabled")
  ADD_EXECUTABLE (analyseDASH ${DASH_SRC})
  TARGET_LINK_LIBRARIES (analyseDASH pcap)
ENDIF(WITH_DASH)

# Please write more tests. Very important!! :-)
IF (TESTS)
  SET (INCLUDE_DIRS tests/ tests/cxxtest-4.4/)
  SET (TESTS_SRC ${BASE_SRC} time_util.c time_util.h tests/testrunner.cpp ${TEST_FILES})
  ADD_EXECUTABLE (test EXCLUDE_FROM_ALL ${TESTS_SRC})
  add_custom_target(buildTestRunner
	COMMAND ./cxxtest-4.4/bin/cxxtestgen --error-printer -o testrunner.cpp TestAnalyseTCP.h
	WORKING_DIRECTORY ../tests
	COMMENT "Build test runner" VERBATIM)
  add_dependencies(test buildTestRunner)
  TARGET_LINK_LIBRARIES (test pcap)
ENDIF(TESTS)

# SET (INCLUDE_DIRS include)

INCLUDE_DIRECTORIES (${INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})

# Distclean functionality (Remove cmake generated files)
IF (UNIX OR APPLE)
  ADD_CUSTOM_TARGET(distclean)
  # Doesn't work to add clean as dependency, so add binaries to DISTCLEANM_FILES instead.

  SET(DISTCLEAN_FILES
    Makefile
    analyseTCP
    cmake_install.cmake
    CMakeCache.txt
    config.h
    )

  SET(DISTCLEAN_DIRS
    CMakeFiles
    )

  # for 1.8.x:
  ADD_CUSTOM_COMMAND(
    TARGET distclean
    PRE_BUILD
    COMMAND rm
    ARGS    -Rf ${DISTCLEAN_FILES} ${DISTCLEAN_DIRS}
    COMMENT "Removing all cmake generated files."
    )
ENDIF (UNIX OR APPLE)
