cmake_minimum_required(VERSION 3.20)
project(kevlar_vtil_bridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(VTIL_CORE_PATH "${CMAKE_CURRENT_LIST_DIR}/../VTIL-Core" CACHE PATH "Path to VTIL-Core")
set(NATIVE_LIFTERS_PATH "${CMAKE_CURRENT_LIST_DIR}/../VTIL-NativeLifters" CACHE PATH "Path to VTIL-NativeLifters")

add_subdirectory("${NATIVE_LIFTERS_PATH}" NativeLifters-Core)

add_library(kevlar-vtil SHARED vtil_bridge.cpp)
target_link_libraries(kevlar-vtil PRIVATE NativeLifters-Core)
target_include_directories(kevlar-vtil PRIVATE "${VTIL_CORE_PATH}/VTIL/includes")
set_target_properties(kevlar-vtil PROPERTIES OUTPUT_NAME "kevlar-vtil")
