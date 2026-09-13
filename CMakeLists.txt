cmake_minimum_required(VERSION 3.28)

# ── vcpkg toolchain ─────────────────────────────────────────────────────────
# Must be set before project() so that find_package picks up vcpkg's cmake
# config files.  Prefer the externally-provided VCPKG_ROOT; fall back to the
# bundled vcpkg_installed tree committed in the repo.
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE
        "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

project(Kevlar-Ultimate LANGUAGES CXX C)

# ── C++ standard ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Fallback prefix path when VCPKG_ROOT is not provided ────────────────────
# Allows find_package / find_library to locate headers and libs from the
# committed vcpkg_installed directory without a full vcpkg installation.
if(NOT DEFINED ENV{VCPKG_ROOT})
    list(PREPEND CMAKE_PREFIX_PATH
        "${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows-static")
endif()

# Use the static CRT triplet that matches the committed vcpkg_installed tree.
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
endif()

# ── Output directories ───────────────────────────────────────────────────────
# Single-config generators (Ninja, NMake) pick up CMAKE_BUILD_TYPE.
# Multi-config generators (Visual Studio) use the per-config variables.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/builds/${CMAKE_BUILD_TYPE}")
foreach(_cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${_cfg}" _CFG)
    set("CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_CFG}"
        "${CMAKE_BINARY_DIR}/builds/${_cfg}")
endforeach()
unset(_cfg)
unset(_CFG)

# ── External packages ────────────────────────────────────────────────────────
# Zydis ships a proper CMake config package via vcpkg.
find_package(zydis CONFIG REQUIRED)   # exports Zydis::Zydis (and Zycore::Zycore)

# Unicorn 2.x does not ship a CMake config; locate the static lib directly.
find_library(UNICORN_LIBRARY NAMES unicorn REQUIRED)

# ── Local static libraries ───────────────────────────────────────────────────

# Logger
add_library(Logger STATIC
    libs/Logger/Logger.cpp
)
target_include_directories(Logger
    PUBLIC  "${CMAKE_SOURCE_DIR}/libs"
    PRIVATE "${CMAKE_SOURCE_DIR}/libs/external/spdlog-1.8.5/include"
)
target_compile_features(Logger PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(Logger PRIVATE /W3 /WX-)
endif()

# PEMapper  (exports symbol PEFile for historical compatibility with the .vcxproj)
add_library(PEFile STATIC
    libs/PEMapper/pefile.cpp
    libs/PEMapper/pch.cpp
    libs/PEMapper/PEMapper.cpp
)
target_include_directories(PEFile
    PUBLIC "${CMAKE_SOURCE_DIR}/libs"
)
target_compile_features(PEFile PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(PEFile PRIVATE /W3 /WX-)
    # pch.cpp is a VS precompiled-header stub; disable it for plain CMake builds.
    set_source_files_properties(libs/PEMapper/pch.cpp
        PROPERTIES COMPILE_FLAGS "/Y-")
endif()

# SymParser
add_library(SymParser STATIC
    libs/SymParser/symparser.cpp
)
target_include_directories(SymParser
    PUBLIC "${CMAKE_SOURCE_DIR}/libs"
)
target_compile_features(SymParser PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(SymParser PRIVATE /W3 /WX-)
endif()

# ── Main KEVLAR executable ───────────────────────────────────────────────────
file(GLOB_RECURSE KEVLAR_SOURCES "KEVLAR/*.cpp")

add_executable(KEVLAR ${KEVLAR_SOURCES})

target_include_directories(KEVLAR PRIVATE
    "${CMAKE_SOURCE_DIR}/KEVLAR"
    "${CMAKE_SOURCE_DIR}/libs"
    "${CMAKE_SOURCE_DIR}/extern/Zydis/include"
)

target_compile_definitions(KEVLAR PRIVATE
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
    ZYDIS_STATIC_BUILD
    ZYCORE_STATIC_BUILD
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(KEVLAR PRIVATE /W3 /WX-)
endif()

target_link_libraries(KEVLAR PRIVATE
    Logger
    PEFile
    SymParser
    Zydis::Zydis
    "${UNICORN_LIBRARY}"
    ntdll.lib
    psapi.lib
)

# Override per-target output dirs for multi-config generators.
set_target_properties(KEVLAR PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY
        "${CMAKE_BINARY_DIR}/builds/${CMAKE_BUILD_TYPE}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG
        "${CMAKE_BINARY_DIR}/builds/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE
        "${CMAKE_BINARY_DIR}/builds/Release"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO
        "${CMAKE_BINARY_DIR}/builds/RelWithDebInfo"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL
        "${CMAKE_BINARY_DIR}/builds/MinSizeRel"
)

# ── selftest custom target ───────────────────────────────────────────────────
add_custom_target(selftest
    COMMAND "$<TARGET_FILE:KEVLAR>" --selftest --no-pause
    DEPENDS KEVLAR
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:KEVLAR>"
    COMMENT "Running KEVLAR selftest"
    VERBATIM
)
