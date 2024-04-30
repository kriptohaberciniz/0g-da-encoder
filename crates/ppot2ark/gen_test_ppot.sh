#!/bin/bash

set -e

cd $(dirname "$0")

if [ ! -d "data" ]; then
    mkdir -p ./data
fi

# 检查参数数量
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <degree>"
    exit 1
fi

# 解析度数参数
degree=$1

# 计算powers of tau的数量
pot_size=$((2**degree))
echo $pot_size

# 克隆phase2-bn254库
cargo install --git https://github.com/kobigurk/phase2-bn254.git --rev dd6b966 powersoftau --bin new_constrained --bin compute_constrained

# 生成初始challenge文件
new_constrained data/challenge_$degree $degree $pot_size

# 生成response文件
compute_constrained data/challenge_$degree data/response_$degree $degree $pot_size <<< "some random text"

# 输出response文件的哈希值
echo "The BLAKE2b hash of the response file is:"
b2sum response_$degree

echo "Done! The response file contains the Powers of Tau parameters."
