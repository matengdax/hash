#!/usr/bin/env python3
# hash_tool_v7.py

import hashlib
import argparse
import sys
import socket
import datetime
import os
import csv # --- 新增: 导入CSV模块 ---

# --- 导入 ---
from google_crc32c import Checksum
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# 创建一个用于屏幕输出的 Console 对象
console = Console()

def calculate_hashes(file_path: str, block_size: int = 65536) -> dict:
    """分块计算一个文件的多种哈希值，现在包含 crc32c。"""
    try:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        crc32c_hash = Checksum()

        with open(file_path, 'rb') as f:
            while chunk := f.read(block_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                crc32c_hash.update(chunk)

        crc32c_hex = crc32c_hash.hexdigest().decode('ascii')
        
        return {
            'path': file_path, # --- 修改: 将路径也加入字典，方便CSV写入 ---
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
            'crc32c': crc32c_hex,
        }
    except Exception as e:
        console.print(f"[bold red]警告:[/bold red] 无法读取或计算文件 '{file_path}': {e}")
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
        f"CRC32C  : {hashes['crc32c']}\n"
        f"----------------------------------------\n"
    )
    
    try:
        with open(output_file, 'a') as f:
            f.write(content)
    except Exception as e:
        console.print(f"[bold red]错误:[/bold red] 写入报告文件 '{output_file}' 时出错: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="[bold green]一个强大且美观的文件哈希计算工具 by Gemini[/bold green]",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path", help="要计算哈希值的文件或目录路径")
    parser.add_argument(
        "-o", "--output",
        help="指定【日志式】报告文件的路径。\n如果未指定，则默认在当前目录下生成报告文件。"
    )
    parser.add_argument(
        "--summary",
        help="指定【CSV摘要】的输出路径。\n如果未指定，同样会在当前目录下默认生成。"
    )
    args = parser.parse_args()

    input_path = args.path
    today_str = datetime.datetime.now().strftime('%Y-%m-%d')
    hostname = socket.gethostname()
    
    # --- 修改: 提取目标文件夹名并格式化，用于默认文件名 ---
    # 使用abspath确保即使输入是"."也能获得正确的目录名
    target_folder_name = os.path.basename(os.path.abspath(input_path)).replace(' ', '_').replace('/', '_')

    if args.output:
        output_file_path = args.output
    else:
        # 在默认文件名中加入文件夹名
        output_file_path = f"./{today_str}-{hostname}-{target_folder_name}-hashes-report.txt"

    if args.summary:
        summary_file_path = args.summary
    else:
        # 在默认文件名中加入文件夹名，并改后缀为.csv
        summary_file_path = f"./{today_str}-{hostname}-{target_folder_name}-summary.csv"

    console.print(f"日志报告将保存到: [cyan]{os.path.abspath(output_file_path)}[/cyan]")
    console.print(f"CSV摘要将保存到: [cyan]{os.path.abspath(summary_file_path)}[/cyan]")
    
    all_results = []

    if os.path.isfile(input_path):
        console.print(f"正在处理单个文件: [yellow]{input_path}[/yellow]")
        results = calculate_hashes(input_path)
        if results:
            save_result(input_path, results, output_file_path)
            all_results.append(results) # 直接附加字典
        console.print("[bold green]处理完成。[/bold green]")

    elif os.path.isdir(input_path):
        console.print(f"正在递归处理目录: [yellow]{input_path}[/yellow]")
        file_list = [os.path.join(r, f) for r, d, files in os.walk(input_path) for f in files if os.path.isfile(os.path.join(r, f))]

        if not file_list:
            console.print("[yellow]该目录下没有找到文件，无需处理。[/yellow]")
        else:
            with Progress(
                TextColumn("[progress.description]{task.description}"), BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("[green]计算中...", total=len(file_list))
                for full_path in file_list:
                    progress.update(task, description=f"[green]计算中... [cyan]{os.path.basename(full_path)}[/cyan]")
                    results = calculate_hashes(full_path)
                    if results:
                        save_result(full_path, results, output_file_path)
                        all_results.append(results) # 直接附加字典
                    progress.update(task, advance=1)
            console.print("[bold green]所有文件处理完成。[/bold green]")
        
    else:
        console.print(f"[bold red]错误:[/bold red] 路径 '{input_path}' 不是一个有效的文件或目录。")
        sys.exit(1)

    if all_results:
        # (屏幕表格输出部分保持不变)
        console.print("\n[bold blue]--- 计算结果摘要 (屏幕预览) ---[/bold blue]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("File Path", style="dim", width=50)
        table.add_column("MD5")
        table.add_column("SHA1")
        table.add_column("SHA256")
        table.add_column("CRC32C")
        for result in all_results:
            table.add_row(
                result['path'], result['md5'], result['sha1'],
                result['sha256'], result['crc32c']
            )
        console.print(table)

        # --- 修改: 将摘要表格以CSV格式保存到文件 ---
        try:
            # 定义CSV文件的表头顺序
            fieldnames = ['path', 'md5', 'sha1', 'sha256', 'crc32c']
            with open(summary_file_path, "w", encoding="utf-8", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader() # 写入表头
                writer.writerows(all_results) # 批量写入数据
            console.print(f"\n[bold green]CSV摘要已成功保存到: {os.path.abspath(summary_file_path)}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]错误:[/bold red] 保存CSV摘要到 '{summary_file_path}' 时出错: {e}")