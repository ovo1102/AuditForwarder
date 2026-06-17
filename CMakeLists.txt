cmake_minimum_required(VERSION 3.16)
project(AuditForwarder
    VERSION 1.0.0
    DESCRIPTION "Enterprise Cross-Platform Security Audit Agent"
    LANGUAGES CXX)

# -----------------------------------------------------------------------------
# Global settings
# -----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Compile options
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 WINVER=0x0A00)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations)
endif()

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)
find_package(ZLIB REQUIRED)

find_package(nlohmann_json 3.7 QUIET)
find_package(yaml-cpp QUIET)
find_package(spdlog QUIET)

include(CTest)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest QUIET)
endif()

# -----------------------------------------------------------------------------
# Platform-specific
# -----------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(AF_PLATFORM_LINUX TRUE)
    add_compile_definitions(AF_PLATFORM_LINUX AF_PLATFORM_UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(AUDIT libaudit)
    if(AUDIT_FOUND)
        add_compile_definitions(AF_HAVE_LIBAUDIT)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(AF_PLATFORM_WINDOWS TRUE)
    add_compile_definitions(AF_PLATFORM_WINDOWS _WIN32_WINNT=0x0A00 WINVER=0x0A00)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(AF_PLATFORM_DARWIN TRUE)
    add_compile_definitions(AF_PLATFORM_DARWIN AF_PLATFORM_UNIX)
endif()

# -----------------------------------------------------------------------------
# Collect all sources (explicit list to control platform sources)
# -----------------------------------------------------------------------------
set(AF_CORE_SOURCES
    # Common
    src/common/types.cpp
    src/common/logger.cpp
    src/common/config.cpp
    src/common/config_parser.cpp
    src/common/fs.cpp
    src/common/thread_pool.cpp
    src/common/process.cpp
    src/common/event.cpp

    # Core
    src/core/agent.cpp
    src/core/self_protect.cpp

    # Crypto
    src/crypto/crypto.cpp
    src/crypto/chain.cpp

    # Processor
    src/processor/processor.cpp

    # Transport
    src/transport/https_transport.cpp

    # Detector
    src/detector/rule_engine.cpp

    # Manager
    src/manager/manager_server.cpp

    # Collector base
    src/collector/collector_base.cpp
)

if(AF_PLATFORM_LINUX)
    list(APPEND AF_CORE_SOURCES
        src/collector/linux/collectors_linux.cpp
        src/core/daemon_posix.cpp
    )
elseif(AF_PLATFORM_WINDOWS)
    list(APPEND AF_CORE_SOURCES
        src/collector/windows/collectors_win.cpp
        src/core/service_win.cpp
    )
else()
    list(APPEND AF_CORE_SOURCES
        src/collector/windows/collectors_win.cpp
        src/core/service_win.cpp
    )
    message(WARNING "Unknown platform, defaulting to Windows build")
endif()

add_library(auditforwarder_core STATIC ${AF_CORE_SOURCES})

target_include_directories(auditforwarder_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(auditforwarder_core
    PUBLIC
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
)

if(yaml-cpp_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC yaml-cpp)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_YAML_CPP)
endif()

if(nlohmann_json_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC nlohmann_json::nlohmann_json)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_JSON)
endif()

if(spdlog_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC spdlog::spdlog)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_SPDLOG)
endif()

if(AF_PLATFORM_LINUX AND AUDIT_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC ${AUDIT_LIBRARIES})
    target_include_directories(auditforwarder_core PUBLIC ${AUDIT_INCLUDE_DIRS})
endif()

if(AF_PLATFORM_WINDOWS)
    target_link_libraries(auditforwarder_core PUBLIC
        wevtapi advapi32 psapi iphlpapi ws2_32 user32 gdi32 shell32 tdh wtsapi32 userenv)
else()
    target_link_libraries(auditforwarder_core PUBLIC
        wevtapi advapi32 psapi iphlpapi ws2_32 user32 gdi32 shell32 tdh wtsapi32 userenv)
endif()

# -----------------------------------------------------------------------------
# Executable: auditforwarderd
# -----------------------------------------------------------------------------
add_executable(auditforwarderd src/main.cpp)
target_link_libraries(auditforwarderd PRIVATE auditforwarder_core)

if(AF_PLATFORM_WINDOWS)
    set_target_properties(auditforwarderd PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

install(TARGETS auditforwarderd
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(BUILD_TESTING AND GTest_FOUND)
    file(GLOB AF_TESTS CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/*.cpp"
    )
    if(AF_TESTS)
        add_executable(auditforwarder_tests ${AF_TESTS})
        target_link_libraries(auditforwarder_tests
            PRIVATE
                auditforwarder_core
                GTest::gtest
                GTest::gtest_main
        )
        target_include_directories(auditforwarder_tests
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/src"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        add_test(NAME auditforwarder_tests COMMAND auditforwarder_tests)
    endif()
endif()

# -----------------------------------------------------------------------------
# Install configuration & scripts
# -----------------------------------------------------------------------------
install(DIRECTORY config/ DESTINATION etc/auditforwarder OPTIONAL)
install(DIRECTORY scripts/ DESTINATION share/auditforwarder/scripts USE_SOURCE_PERMISSIONS OPTIONAL)
install(DIRECTORY docs/ DESTINATION share/auditforwarder/docs OPTIONAL)
