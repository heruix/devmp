cmake_minimum_required(VERSION 3.18)

project(devmp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMakeModules")

find_package(CAPSTONE REQUIRED)
add_library(devmp
    core/InstInfo.cpp
    core/InstManager.cpp
    core/utils.cpp
    )
target_include_directories(devmp PUBLIC core/include)
target_link_libraries(devmp
    ${CAPSTONE_LIBRARIES}
    )
target_include_directories(devmp PRIVATE ${CAPSTONE_INCLUDE_DIRS})
set_target_properties(devmp PROPERTIES POSITION_INDEPENDENT_CODE ON)
link_libraries(devmp)

if(PYTHON_EXTENSION)
    find_package(PythonLibs ${PYTHON_VERSION} REQUIRED)
    add_library(pydevmp SHARED core/python_ext.cpp)
    target_link_libraries(pydevmp ${PYTHON_LIBRARY})
    target_include_directories(pydevmp PRIVATE ${PYTHON_INCLUDE_DIRS})
    set_target_properties(pydevmp PROPERTIES PREFIX "" )
    add_dependencies(pydevmp devmp)
endif()

if(TRITON_EXTENSION)
    find_package(triton REQUIRED)
    add_library(devmp_triton SHARED triton/TraceEngine.cpp triton/MemoryRange.cpp)
    target_link_libraries(devmp_triton ${TRITON_LIBRARY})
    target_include_directories(devmp_triton PUBLIC ${TRITON_INCLUDE_DIRS} PUBLIC triton/include PUBLIC core/include )
    add_dependencies(devmp_triton devmp)
endif()

if(EXAMPLE)
    add_executable(core_example core/example.cpp)
    target_include_directories(core_example PRIVATE ${CAPSTONE_INCLUDE_DIRS})
    add_dependencies(core_example devmp)
    if(TRITON_EXTENSION)
        add_executable(triton_example triton/example.cpp)
        target_include_directories(triton_example PUBLIC ${TRITON_INCLUDE_DIRS} PUBLIC triton/include)
        add_dependencies(triton_example devmp_triton)
    endif()
endif()