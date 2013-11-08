PROJECT (analyseTCP CXX)
ENABLE_LANGUAGE(C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.0)
SET (INCLUDE_DIRS /work/include)

SET (LIB_DIRS /work/lib)

# Put executable files in custom dir
#SET(EXECUTABLE_OUTPUT_PATH dir)

#Added work/include to enable building with locally installed libs on
INCLUDE_DIRECTORIES (${INCLUDE_DIRS})

# Prepare sources for app.
SET (APP_SRCS analyseTCP.cc analyseTCP.h
    	      Dump.cc Dump.h
	      Connection.h Connection.cc
	      RangeManager.cc RangeManager.h
	      Range.cc Range.h
	      ByteRange.cc ByteRange.h
		  color_print.cc color_print.h
		  time_util.cc time_util.h)

ADD_EXECUTABLE (analyseTCP ${APP_SRCS})

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

TARGET_LINK_LIBRARIES (analyseTCP pcap)

# Set compiler flags for all configurations
#SET (CMAKE_CXX_FLAGS "-O2 -lm -Wall -g3") # -Werror?
SET (CMAKE_CXX_FLAGS "-lm -Wall -g3") # -Werror?

# Add NDEBUG only for release version
# To activate: cmake -DCMAKE_BUILD_TYPE=Release .
SET (CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")

# Platform specific debug flags
IF (APPLE)
   SET (CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wno-long-double")
ENDIF (APPLE)

# Set debug compiler flags
# To activate: cmake -DCMAKE_BUILD_TYPE=Debug .
SET (CMAKE_C_FLAGS_DEBUG "-g3 -Wall")
SET (CMAKE_CXX_FLAGS_DEBUG "-g3 -Wall")
# Platform specific debug flags
IF (UNIX)
   SET (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -gdwarf-2")
ENDIF (UNIX)

# -gstabs+ removed.
IF (APPLE)
   SET (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-long-double")
ENDIF (APPLE)

# Distclean functionality (Remove cmake generated files)
IF (UNIX OR APPLE)
  ADD_CUSTOM_TARGET(distclean DEPENDS clean)
  #ADD_DEPENDENCIES (distclean clean)

  SET(DISTCLEAN_FILES
    cmake.depends
    cmake.check_depends
    CMakeCache.txt
    cmake.check_cache
    CMakeOutput.log
    core core.*
    gmon.out bb.out
    *~
    *%
    SunWS_cache
    ii_files
    *.so
    *.o
    *.a
    CopyOfCMakeCache.txt
    CMakeCCompiler.cmake
    CMakeCCXXompiler.cmake
    CMakeSystem.cmake
    html latex Doxyfile
    )

  SET(DISTCLEAN_DIRS
    CMakeTmp
    )

SET(DISTCLEAN_RECURSIVE_FILES
  Makefile
  CMakeTmp
  cmake.depends
  cmake.check_depends
  CMakeCache.txt
  cmake.check_cache
  cmake_install.cmake
  CMakeOutput.log
  core core.*
  gmon.out bb.out
  bin
  *~
  *%
  *.o
  *.a
  CopyOfCMakeCache.txt
  CMakeCCompiler.cmake
  CMakeCCompiler.cmake
  CMakeSystem.cmake
  html latex Doxyfile
 )

 # for 1.8.x:
  ADD_CUSTOM_COMMAND(
    TARGET distclean
    PRE_BUILD
    COMMAND rm
    ARGS    -Rf ${DISTCLEAN_FILES} ${DISTCLEAN_DIRS}
   COMMENT
    )

  FOREACH(RMTARGET ${DISTCLEAN_RECURSIVE_FILES})
    ADD_CUSTOM_COMMAND(
      TARGET distclean
      PRE_BUILD
      COMMAND find
      ARGS . -name ${RMTARGET} -exec rm -rf {} '\;'
      COMMENT
      )
  ENDFOREACH(RMTARGET ${DISTCLEAN_RECURSIVE_FILES})
ENDIF (UNIX OR APPLE)
