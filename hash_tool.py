#!/usr/bin/env python3
# hash_tool_v13.py (多进程 + 多线程混合模型)

import hashlib
import argparse
import sys
import socket
import datetime
import os
import csv
import multiprocessing
import threading # 1. 导入线程模块
import queue     # 2. 导入队列模块

# --- 导入 ---
from google_crc32c import Checksum
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# 创建一个用于屏幕输出的 Console 对象
console = Console()


# --- ======== 核心修改：重写 calculate_hashes 函数为流水线模式 ======== ---
def calculate_hashes(file_path: str, block_size: int = 4194304) -> dict:
    
    # 65536 64KiB
    # 1048576 1MiB
    # 4194304 4MiB
    # 8388608 8MiB
    
    """
    使用内部的多线程流水线来计算单个文件的哈希值。
    一个子线程负责从磁盘读取(I/O)，主线程负责计算(CPU)，形成重叠。
    """
    # 3. 创建一个线程安全的队列作为“传送带”
    # maxsize=2 意味着生产者(读线程)最多只预读2个数据块，防止内存占用过高
    q = queue.Queue(maxsize=2)
    
    # 4. 定义生产者（读线程）的工作
    def reader_thread(path, b_size, q_ref):
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(b_size):
                    q_ref.put(chunk)
        except Exception:
            # 如果读取失败，也放入一个标记，让消费者知道
            q_ref.put(None) 
        finally:
            # 5. 放入一个“任务结束”的标记 (哨兵值)
            q_ref.put(None)

    # 6. 创建并启动读线程
    reader = threading.Thread(target=reader_thread, args=(file_path, block_size, q))
    reader.start()

    # 7. 主线程作为消费者，开始计算
    try:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        crc32c_hash = Checksum()

        while True:
            # 从队列获取数据块，如果队列为空，会自动等待
            chunk = q.get()
            
            # 8. 如果获取到的是“任务结束”标记，则退出循环
            if chunk is None:
                break
            
            # 进行计算
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            crc32c_hash.update(chunk)

        # 9. 等待读线程完全结束
        reader.join()

        crc32c_hex = crc32c_hash.hexdigest().decode('ascii')
        
        return {
            'path': file_path,
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
            'crc32c': crc32c_hex,
        }
    except Exception:
        return None

# ... save_result 函数保持不变 ...
def save_result(target_path: str, hashes: dict, output_file: str):
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
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(content)
    except Exception:
        pass


if __name__ == "__main__":
    # --- 主程序逻辑与 v12 版本完全相同 ---
    # 唯一的区别就是 pool.imap_unordered 调用的函数是新版的流水线函数
    
    parser = argparse.ArgumentParser(
        description="[bold green]一个强大且美观的文件哈希计算工具 by Gemini (v13 - 混合模型)[/bold green]",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ... 参数解析部分不变 ...
    parser.add_argument("path", help="要计算哈希值的文件或目录路径")
    parser.add_argument("-o","--output",help="指定【日志式】报告文件的路径。\n如果未指定，则默认在当前目录下生成报告文件。")
    parser.add_argument("--summary",help="指定【CSV摘要】的输出路径。\n如果未指定，同样会在当前目录下默认生成。")
    args = parser.parse_args()

    input_path = args.path
    timestamp_str = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    hostname = socket.gethostname()
    target_folder_name = os.path.basename(os.path.abspath(input_path)).replace(' ', '_').replace('/', '_')

    if args.output:
        output_file_path = args.output
    else:
        output_file_path = f"./{timestamp_str}-{hostname}-{target_folder_name}-hashes-report.txt"
    if args.summary:
        summary_file_path = args.summary
    else:
        summary_file_path = f"./{timestamp_str}-{hostname}-{target_folder_name}-summary.csv"

    console.print(f"日志报告将保存到: [cyan]{os.path.abspath(output_file_path)}[/cyan]")
    console.print(f"CSV摘要将保存到: [cyan]{os.path.abspath(summary_file_path)}[/cyan]")
    
    all_results = []
    
    if os.path.isfile(input_path):
        console.print(f"正在处理单个文件: [yellow]{input_path}[/yellow]")
        # 单文件也使用新的流水线函数
        results = calculate_hashes(input_path)
        if results:
            save_result(input_path, results, output_file_path)
            all_results.append(results)
        console.print("[bold green]处理完成。[/bold green]")

    elif os.path.isdir(input_path):
        # ... 文件过滤逻辑不变 ...
        EXCLUDED_FOLDERS = {
            '$RECYCLE.BIN', 'System Volume Information', 'Config.Msi',
            'MSOCache', 'Recovery', '$WinREAgent', 'Documents and Settings'
        }
        console.print(f"正在递归处理目录: [yellow]{input_path}[/yellow]")
        console.print(f"将按规则忽略以 [dim].[/dim] 或 [dim]__[/dim] 开头的目录/文件。")
        console.print(f"还将按名称忽略以下目录: [dim]{EXCLUDED_FOLDERS}[/dim]")
        
        file_list = []
        for root, dirs, files in os.walk(input_path):
            dirs[:] = [
                d for d in dirs if
                not d.startswith('.') and not d.startswith('__') and d not in EXCLUDED_FOLDERS
            ]
            for filename in files:
                if not filename.startswith('.') and not filename.startswith('__'):
                    full_path = os.path.join(root, filename)
                    if os.path.isfile(full_path):
                        file_list.append(full_path)

        if not file_list:
            console.print("[yellow]该目录下没有找到符合条件的文件，无需处理。[/yellow]")
        else:
            num_processes = multiprocessing.cpu_count()
            console.print(f"发现 [bold green]{len(file_list)}[/bold green] 个文件，将使用 [bold blue]{num_processes}[/bold blue] 个CPU核心并行处理...")

            with multiprocessing.Pool(processes=num_processes) as pool:
                with Progress(
                    TextColumn("[progress.description]{task.description}"), BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(),
                ) as progress:
                    task = progress.add_task("[green]计算中...", total=len(file_list))
                    
                    # 唯一的区别：调用的函数是新版的流水线函数
                    for result in pool.imap_unordered(calculate_hashes, file_list):
                        if result:
                            save_result(result['path'], result, output_file_path)
                            all_results.append(result)
                        else:
                            pass
                        progress.update(task, advance=1)
            
            console.print("[bold green]所有文件处理完成。[/bold green]")
        
    else:
        console.print(f"[bold red]错误:[/bold red] 路径 '{input_path}' 不是一个有效的文件或目录。")
        sys.exit(1)

    if all_results:
        # ... 结果汇总与CSV写入部分不变 ...
        console.print("\n[bold blue]--- 计算结果摘要 (屏幕预览) ---[/bold blue]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("File Path", style="dim", width=50)
        table.add_column("MD5")
        table.add_column("SHA1")
        table.add_column("SHA256")
        table.add_column("CRC32C")
        all_results.sort(key=lambda x: x['path'])
        for result in all_results:
            table.add_row(
                result['path'], result['md5'], result['sha1'],
                result['sha256'], result['crc32c']
            )
        console.print(table)

        try:
            fieldnames = ['path', 'md5', 'sha1', 'sha256', 'crc32c']
            with open(summary_file_path, "w", encoding="utf-8", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_results)
            console.print(f"\n[bold green]CSV摘要已成功保存到: {os.path.abspath(summary_file_path)}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]错误:[/bold red] 保存CSV摘要到 '{summary_file_path}' 时出错: {e}")
