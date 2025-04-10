#!/bin/bash
# 开启 extglob 选项
shopt -s extglob
# 记录当前目录
current_dir=$(pwd)

# 编译 flowAnalyzer 项目
mkdir -p ${current_dir}/bin && \
cd ${current_dir}/bin && \
rm -rf -- !(compile.sh|flowAnalyzer)
cmake ..
make -j
# 删除除 compile.sh 和 vpntools 之外的所有文件和目录
rm -rf -- !(compile.sh|flowAnalyzer)