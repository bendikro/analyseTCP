PROJECT (analyseTCP CXX)
SET(CMAKE_VERBOSE_MAKEFILE off)
ENABLE_LANGUAGE(C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.0)
#SET (INCLUDE_DIRS /work/include)
#SET (LIB_DIRS /work/lib)

SET (INCLUDE_DIRS tests/ tests/cxxtest-4.4)

# Put executable files in custom dir
#SET(EXECUTABLE_OUTPUT_PATH dir)

#Added work/include to enable building with locally installed libs on
INCLUDE_DIRECTORIES (${INCLUDE_DIRS})

# Prepare sources for app.
SET (APP_SRCS common.cc common.h
    	      Dump.cc Dump.h
			  Connection.h Connection.cc
			  RangeManager.cc RangeManager.h
			  ByteRange.cc ByteRange.h
			  color_print.cc color_print.h
			  time_util.cc time_util.h
			  util.cc util.h)

SET (TEST_FILES tests/TestAnalyseTCP.h)
# SET (TESTS_SRCS ${APP_SRCS} tests/testrunner.cpp ${TEST_FILES})
SET (APP_SRCS ${APP_SRCS} analyseTCP.cc)

ADD_EXECUTABLE (analyseTCP ${APP_SRCS})
# ADD_EXECUTABLE (test EXCLUDE_FROM_ALL ${TESTS_SRCS})

# add_custom_target(buildTestRunner
#   COMMAND ./cxxtest-4.4/bin/cxxtestgen --error-printer -o testrunner.cpp TestAnalyseTCP.h
#   WORKING_DIRECTORY ../tests
#   COMMENT "Build test runner" VERBATIM)
# add_dependencies(test buildTestRunner)

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

IF (APPLE)
  SET (ulong "unsigned long")
ENDIF (APPLE)


TARGET_LINK_LIBRARIES (analyseTCP pcap)
# TARGET_LINK_LIBRARIES (test pcap)

# Set compiler flags for all configurations
# SET (CMAKE_CXX_FLAGS "-std=gnu++11 -lm -Wall -Wno-long-long -Wno-variadic-macros") # -Werror?
SET (CMAKE_CXX_FLAGS "-lm -Wall -Wno-long-long -Wno-variadic-macros") # -Werror?
IF (CMAKE_COMPILER_IS_GNUCXX)
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
ENDIF (CMAKE_COMPILER_IS_GNUCXX)


# Add NDEBUG only for release version
# To activate: cmake -DCMAKE_BUILD_TYPE=Release ..
SET (CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Set debug compiler flags
# To activate: cmake -DCMAKE_BUILD_TYPE=Debug ..
SET (CMAKE_CXX_FLAGS_DEBUG "-g3 -Wall -DDEBUG -Wextra -pedantic")
# Platform specific debug flags


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
