cmake_minimum_required(VERSION 3.10)
project(cppquic LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

# Force dependencies in this directory scope and below to build as static libraries
set(BUILD_SHARED_LIBS OFF)

set(CPPQUIC_UDPNET_TAG "main" CACHE STRING "Git tag/branch to use for cpp-udpnet dependency")
FetchContent_Declare(
  cppudpnet
  GIT_REPOSITORY https://github.com/jonoton/cpp-udpnet.git
  GIT_TAG ${CPPQUIC_UDPNET_TAG}
)
FetchContent_MakeAvailable(cppudpnet)

# Option to use LibreSSL instead of system OpenSSL
option(CPPQUIC_USE_LIBRESSL "Build LibreSSL from source instead of finding system OpenSSL" ON)

if(CPPQUIC_USE_LIBRESSL)
        include(FetchContent)
        # Use CMAKE_POLICY_DEFAULT_CMPxxx variables to ensure policy choices propagate
        # to LibreSSL's subproject even after it calls cmake_minimum_required()
        set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
        set(CMAKE_POLICY_DEFAULT_CMP194 NEW)

        set(CPPQUIC_LIBRESSL_VERSION "3.9.2" CACHE STRING "Version of LibreSSL to use")

        # Disable LibreSSL apps and tests to keep build times fast
        set(LIBRESSL_APPS OFF CACHE BOOL "Build LibreSSL apps" FORCE)
        set(LIBRESSL_TESTS OFF CACHE BOOL "Build LibreSSL tests" FORCE)
        set(USE_STATIC_MSVC_RUNTIMES OFF CACHE BOOL "Use static MSVC runtimes" FORCE)

        if(WIN32)
            # Disable assembly on Windows to prevent register corruption/ABI mismatch crashes
            # in LibreSSL assembly optimizations (e.g. stack alignment or register preservation issues)
            set(ENABLE_ASM OFF CACHE BOOL "Enable assembly" FORCE)
        endif()

        FetchContent_Declare(
            libressl
            URL "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${CPPQUIC_LIBRESSL_VERSION}.tar.gz"
        )
        FetchContent_MakeAvailable(libressl)

        # Patch LibreSSL to prevent Debug CRT assertion crash in is_socket on Windows
        set(PATCH_FILE "${libressl_SOURCE_DIR}/crypto/compat/posix_win.c")
        if(EXISTS "${PATCH_FILE}")
            file(READ "${PATCH_FILE}" FILE_CONTENT)
            if(NOT FILE_CONTENT MATCHES "getsockopt\\(\\(SOCKET\\)fd")
                string(REGEX REPLACE "static int[ \t\r\n]+is_socket\\(int fd\\)[ \t\r\n]*\\{[^}]*if[ \t\r\n]*\\([^{}]*\\)[ \t\r\n]*\\{[^{}]*\\}[^{}]*\\}" "static int\nis_socket(int fd)\n{\n\tint optval;\n\tint optlen = sizeof(optval);\n\tif (getsockopt((SOCKET)fd, SOL_SOCKET, SO_TYPE, (char *)&optval, &optlen) == 0) {\n\t\treturn 1; /* fd is a socket */\n\t}\n\treturn 0; /* fd is not a socket */\n}" MODIFIED_CONTENT "${FILE_CONTENT}")
                file(WRITE "${PATCH_FILE}" "${MODIFIED_CONTENT}")
                message(STATUS "[cppquic] Patched LibreSSL posix_win.c to prevent Debug CRT crash")
            endif()
        endif()

        # Alias targets to match the OpenSSL target names expected
        if(NOT TARGET OpenSSL::Crypto)
            add_library(OpenSSL::Crypto ALIAS crypto)
        endif()
        if(NOT TARGET OpenSSL::SSL)
            add_library(OpenSSL::SSL ALIAS ssl)
        endif()
    else()
        find_package(OpenSSL REQUIRED)
    endif()

# Header-only library target
add_library(cppquic INTERFACE)
add_library(cppquic::cppquic ALIAS cppquic)

target_include_directories(cppquic INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cppquic INTERFACE
    cppudpnet::cppudpnet
)

target_link_libraries(cppquic INTERFACE OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(cppquic INTERFACE CPPQUIC_SSL_SUPPORT)

# Platform-specific link libraries
if(WIN32)
    target_link_libraries(cppquic INTERFACE ws2_32 bcrypt)
endif()

# Determine if this is the top-level project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CPPQUIC_IS_TOP_LEVEL ON)
else()
    set(CPPQUIC_IS_TOP_LEVEL OFF)
endif()

if(CPPQUIC_IS_TOP_LEVEL)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

option(CPPQUIC_BUILD_EXAMPLES "Build example programs" ${CPPQUIC_IS_TOP_LEVEL})
option(CPPQUIC_BUILD_TESTS "Build tests" ${CPPQUIC_IS_TOP_LEVEL})

if(CPPQUIC_BUILD_TESTS)
    # Fetch GoogleTest for tests
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_subdirectory(tests)
endif()

if(CPPQUIC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
