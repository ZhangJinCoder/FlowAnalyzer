cmake_minimum_required(VERSION 3.0)
# 设置项目版本和生成version.h
project(flowAnalyzer VERSION 3.0.0)
# 指定编程语言版本，c使用c99标准，c++使用c++11标准。
set(CMAKE_C_STANDARD 99)
# set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 配置编译选项
add_compile_options(-Wno-unused -Wall -g)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99 -lpthread -lm -O2 ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -std=c++11 -O3")

# 配置编译类型，类似于 cmake -B build -DCMAKE_BUILD_TYPE=Debug
set(CMAKE_BUILD_TYPE Release) # Debug/Release/RelWithDebInfo/MinSizeRel

# 添加include目录
include_directories(
    include
    src
)

link_directories(
    lib
)

link_libraries(
    -pthread
    -ldl
)

# 添加源文件到源列表变量中
aux_source_directory(./src          DIR_SRCS)

# 编译服务端可执行文件
add_executable(
    flowAnalyzer 
    ${DIR_SRCS}
)
target_link_libraries(
    flowAnalyzer 
)


