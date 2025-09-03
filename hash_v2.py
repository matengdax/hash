#!/usr/bin/env python3
# hash_tool.py (v2)

import hashlib
import argparse
import sys
import socket
import datetime
import os

def calculate_hashes(file_path: str, block_size: int = 1048576) -> dict:
    """分块计算一个文件的多种哈希值。"""
    try:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(block_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
        }
    except Exception as e:
        print(f"警告: 无法读取或计算文件 '{file_path}' 的哈希值: {e}", file=sys.stderr)
        return None

def save_result(target_path: str, hashes: dict, output_file: str):
    """将单次计算结果追加到指定的报告文件中。"""
    hostname = socket.gethostname()
    
    content = (
        f"Timestamp: {datetime.datetime.now().isoformat()}\n"
        f"Hostname: {hostname}\n"
        f"File Path: {os.path.abspath(target_path)}\n"
        f"MD5     : {hashes['md5']}\n"
        f"SHA1    : {hashes['sha1']}\n"
        f"SHA256  : {hashes['sha256']}\n"
        f"----------------------------------------\n"
    )
    
    try:
        with open(output_file, 'a') as f:
            f.write(content)
    except Exception as e:
        print(f"错误: 写入报告文件 '{output_file}' 时出错: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="计算文件或目录内所有文件的哈希值，并保存到报告中。"
    )
    parser.add_argument("path", help="要计算哈希值的文件或目录路径")
    parser.add_argument(
        "-o", "--output",
        help="指定输出报告文件的路径。如果未指定，则默认在当前目录下生成报告文件。"
    )
    args = parser.parse_args()

    input_path = args.path

    # --- 核心逻辑改动 ---
    
    # 决定输出文件的路径
    if args.output:
        output_file_path = args.output
    else:
        # 如果用户未指定输出路径，则在当前目录下生成默认文件名
        today_str = datetime.datetime.now().strftime('%Y-%m-%d')
        hostname = socket.gethostname()
        output_file_path = f"./{today_str}-{hostname}-hashes-report.txt"

    print(f"报告将保存到: {os.path.abspath(output_file_path)}")
    
    # 判断输入路径是文件还是目录
    if os.path.isfile(input_path):
        print(f"正在处理单个文件: {input_path}")
        results = calculate_hashes(input_path)
        if results:
            save_result(input_path, results, output_file_path)
        print("处理完成。")

    elif os.path.isdir(input_path):
        print(f"正在递归处理目录: {input_path}")
        # 使用 os.walk 递归遍历所有子目录和文件
        for root, dirs, files in os.walk(input_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                print(f"  -> 正在计算: {full_path}")
                results = calculate_hashes(full_path)
                if results:
                    save_result(full_path, results, output_file_path)
        print("所有文件处理完成。")
        
    else:
        print(f"错误: 路径 '{input_path}' 不是一个有效的文件或目录。", file=sys.stderr)
        sys.exit(1)
