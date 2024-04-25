#!/bin/bash

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
if [ ! -d "phase2-bn254" ]; then
    git clone https://github.com/kobigurk/phase2-bn254.git
    echo '' >> phase2-bn254/powersoftau/Cargo.toml
    echo '[workspace]' >> phase2-bn254/powersoftau/Cargo.toml
    cd phase2-bn254/powersoftau
    cargo build --release
    cd ../../
else
    echo "phase2-bn254 directory already exists, skipping clone and build."
fi

# 生成初始challenge文件
./phase2-bn254/powersoftau/target/release/new_constrained challenge_$degree $degree $pot_size

# 生成response文件
./phase2-bn254/powersoftau/target/release/compute_constrained challenge_$degree response_$degree $degree $pot_size <<< "some random text"

# 输出response文件的哈希值
echo "The BLAKE2b hash of the response file is:"
b2sum response_$degree

echo "Done! The response file contains the Powers of Tau parameters."