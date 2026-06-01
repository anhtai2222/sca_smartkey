# =============================================================================
# Host-side unit tests for the SCA Smart Key firmware logic.
#
#   cmake -S tests -B build && cmake --build build && ctest --test-dir build
#
# Builds the hardware-independent firmware sources with -DSCA_HOST_BUILD so the
# crypto / auth / state-machine / UWB logic can be tested with GoogleTest on a
# plain desktop (no ESP32 toolchain required).
# =============================================================================

cmake_minimum_required(VERSION 3.14)
project(sca_smartkey_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
include(GoogleTest)
enable_testing()

set(FW_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../firmware/src)
set(FW_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../firmware/lib/mbedtls_wrapper)

# Firmware logic compiled for the host (excludes BLE/main, which need ESP-IDF).
set(LOGIC_SOURCES
    ${FW_SRC}/auth_engine.cpp
    ${FW_SRC}/access_controller.cpp
    ${FW_SRC}/uwb_manager.cpp
    ${FW_SRC}/nfc_manager.cpp
    ${FW_LIB}/hmac_wrapper.cpp
)

add_library(sca_logic STATIC ${LOGIC_SOURCES})
target_include_directories(sca_logic PUBLIC ${FW_SRC} ${FW_LIB})
target_compile_definitions(sca_logic PUBLIC SCA_HOST_BUILD)

add_executable(sca_tests test_auth.cpp test_state_machine.cpp)
target_link_libraries(sca_tests PRIVATE sca_logic GTest::gtest GTest::gtest_main)

gtest_discover_tests(sca_tests)
