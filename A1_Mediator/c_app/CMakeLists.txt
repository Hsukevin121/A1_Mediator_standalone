cmake_minimum_required(VERSION 3.29)
project(APIRestClient)
set(CMAKE_CXX_STANDARD 20)
#add_executable(APIRestClient main.cpp)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lcurl")
set(SOURCE_FILES main.cpp)
add_executable(APIRestClient ${SOURCE_FILES})
target_link_libraries(APIRestClient curl)
target_link_libraries(APIRestClient jsoncpp)
