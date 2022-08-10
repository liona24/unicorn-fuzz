
find_package(GTest)

if (GTest_FOUND)
    message(STATUS "Found GTest, building tests")

    add_executable(
        lfu_tests
        test_allocator.cpp
    )
    target_include_directories(lfu_tests PRIVATE
        ../src
        ../include
        ${GTEST_INCLUDE_DIRS}
    )
    target_link_libraries(lfu_tests PRIVATE
        lfu
        ${GTEST_MAIN_LIBRARIES}
    )
endif()
