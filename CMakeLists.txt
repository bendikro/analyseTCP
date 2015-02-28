PROJECT (analyseTCP CXX)
SET(CMAKE_VERBOSE_MAKEFILE off)
ENABLE_LANGUAGE(C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
#SET (INCLUDE_DIRS /work/include)
#SET (LIB_DIRS /work/lib)

# Available compile options:
# * WITH_DASH               - Compile with DASH
# * ONLY_DASH               - Only compile DASH
# * TESTS                   - Compile test executable
#
# Compile with dash:
# cmake .. -DWITH_DASH=1
#

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

INCLUDE (CheckTypeSize)

# Put executable files in custom dir
#SET(EXECUTABLE_OUTPUT_PATH dir)

#Added work/include to enable building with locally installed libs on
INCLUDE_DIRECTORIES (${INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})

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

# SET (CMAKE_CXX_FLAGS "-std=gnu++11 -lm -Wall -Wno-long-long -Wno-variadic-macros") # -Werror?

# Set compiler flags for all configurations
#SET (CMAKE_CXX_FLAGS "-std=gnu++11 -lm -Wall -Wno-long-long -Wno-variadic-macros") # -Werror?

SET (CMAKE_CXX_FLAGS "-Wall -Wno-long-long -Wno-variadic-macros") # -Werror?
IF (CMAKE_COMPILER_IS_GNUCXX)
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
ENDIF (CMAKE_COMPILER_IS_GNUCXX)

# Add NDEBUG only for release version
# To activate: cmake -DCMAKE_BUILD_TYPE=Release ..
SET (CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Set debug compiler flags
# To activate: cmake -DCMAKE_BUILD_TYPE=Debug ..
SET (CMAKE_CXX_FLAGS_DEBUG "-g3 -Wall -DDEBUG -Wextra -pedantic")

# Must be below the compiler flags
INCLUDE(FindSharedPtr)
FIND_SHARED_PTR()
IF (SHARED_PTR_FOUND)
  IF (SHARED_PTR_TR1_MEMORY_HEADER)
    SET(HAVE_TR1_MEMORY)
  ENDIF (SHARED_PTR_TR1_MEMORY_HEADER)
  IF (SHARED_PTR_TR1_NAMESPACE)
    SET(HAVE_TR1_NAMESPACE)
  ENDIF (SHARED_PTR_TR1_NAMESPACE)
ELSE (SHARED_PTR_FOUND)
  MESSAGE(FATAL_ERROR "Unable to find shared_ptr.")
ENDIF (SHARED_PTR_FOUND)


CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

SET (BASE_SRC
  Dump.cc Dump.h
  Connection.cc Connection.h
  RangeManager.cc RangeManager.h
  ByteRange.cc ByteRange.h
  common.cc common.h
  fourTuple.cc fourTuple.h
  color_print.cc color_print.h
  util.cc util.h)

# Prepare sources for app.
SET (TCP_SRC ${BASE_SRC}
  analyseTCP.cc
  time_util.cc time_util.h)

SET (DASH_SRC ${BASE_SRC}
  analyseDASH.cc analyseDASH.h)

IF (NOT ONLY_DASH)
  ADD_EXECUTABLE (analyseTCP ${TCP_SRC})
  TARGET_LINK_LIBRARIES (analyseTCP pcap)
ENDIF(NOT ONLY_DASH)

IF (WITH_DASH)
  ADD_EXECUTABLE (analyseDASH ${DASH_SRC})
  TARGET_LINK_LIBRARIES (analyseDASH pcap)
ENDIF(WITH_DASH)

IF (TESTS)
  SET (TEST_FILES tests/TestAnalyseTCP.h)
  SET (INCLUDE_DIRS tests/ tests/cxxtest-4.4)
  SET (TESTS_SRCS ${TCP_SRC} tests/testrunner.cpp ${TEST_FILES})
  ADD_EXECUTABLE (test EXCLUDE_FROM_ALL ${TESTS_SRCS})
  add_custom_target(buildTestRunner
	COMMAND ./cxxtest-4.4/bin/cxxtestgen --error-printer -o testrunner.cpp TestAnalyseTCP.h
	WORKING_DIRECTORY ../tests
	COMMENT "Build test runner" VERBATIM)
  add_dependencies(test buildTestRunner)
  TARGET_LINK_LIBRARIES (test pcap)
ENDIF(TESTS)

# Distclean functionality (Remove cmake generated files)
IF (UNIX OR APPLE)
  ADD_CUSTOM_TARGET(distclean)
  # Doesn't work to add clean as dependency, so add binaries to DISTCLEANMFILES instead.

  SET(DISTCLEAN_FILES
    Makefile
    analyseTCP
    cmake_install.cmake
    CMakeCache.txt
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
