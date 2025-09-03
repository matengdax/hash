#!/usr/bin/env python3
# hash_tool_v11.py (精确时间戳文件名)

import hashlib
import argparse
import sys
import socket
import datetime
import os
import csv

# --- 导入 ---
from google_crc32c import Checksum
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# 创建一个用于屏幕输出的 Console 对象
console = Console()

# google-crc32c
# rich
def calculate_hashes(file_path: str, block_size: int = 1048576) -> dict:  # 默认块大小提升到1MB

    # 65536 64KiB
    # 1048576 1MiB
    # 4194304 4MiB
    # 8388608 8MiB
    # 从 64KB 提升到 1MB，性能的提升幅度通常非常巨大，因为I/O调用的开销被大幅减少了
    # 从 1MB 再提升到 4MB，性能的提升幅度会小很多，甚至可能由于上述的缓存问题而变为负增长
    # 大小要小于L2 缓存，是因为L2缓存处在一个承上启下的关键位置，但实际上，优化的真正目标是让数据块尽可能地留在 L2 或 L3 缓存中
    # 在kvm中,I/O 开销可能更高：在虚拟机中，文件读写需要经过一层虚拟化（例如 VirtIO 驱动）才能到达物理硬盘。这个过程会引入额外的开销和延迟。因此，减少 I/O 操作次数（即增大 block_size）可能会带来比物理机上更明显的效果
    # 在kvm中,物理 CPU 的特性：您提到宿主机是 Intel Xeon (Cascadelake) 处理器。这是服务器级别的 CPU，其 L2 和 L3 缓存通常都比较大
    # 考虑到虚拟化带来的 I/O 开销和强大的宿主机 CPU 缓存，我们可以采取比之前更激进一点的策略,可以设置到4MiB和8MiB

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
            'path': file_path,
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
            'crc32c': crc32c_hex,
        }
    except Exception as e:
        if isinstance(e, PermissionError):
            console.print(f"[bold yellow]跳过 (权限不足):[/bold yellow] '{file_path}'")
        else:
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
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        console.print(f"[bold red]错误:[/bold red] 写入报告文件 '{output_file}' 时出错: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="[bold green]一个强大且美观的文件哈希计算工具 by Gemini (v11 - 精确时间戳文件名)[/bold green]",
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

    # --- ======== 代码修改从这里开始 ======== ---

    # 将日期格式化字符串修改为包含时分秒的格式
    timestamp_str = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    hostname = socket.gethostname()

    target_folder_name = os.path.basename(os.path.abspath(input_path)).replace(' ', '_').replace('/', '_')

    if args.output:
        output_file_path = args.output
    else:
        # 使用新的、更精确的时间戳字符串
        output_file_path = f"./{timestamp_str}-{hostname}-{target_folder_name}-hashes-report.txt"

    if args.summary:
        summary_file_path = args.summary
    else:
        # 使用新的、更精确的时间戳字符串
        summary_file_path = f"./{timestamp_str}-{hostname}-{target_folder_name}-summary.csv"

    # --- ======== 代码修改在这里结束 ======== ---

    console.print(f"日志报告将保存到: [cyan]{os.path.abspath(output_file_path)}[/cyan]")
    console.print(f"CSV摘要将保存到: [cyan]{os.path.abspath(summary_file_path)}[/cyan]")

    all_results = []

    if os.path.isfile(input_path):
        console.print(f"正在处理单个文件: [yellow]{input_path}[/yellow]")
        results = calculate_hashes(input_path)
        if results:
            save_result(input_path, results, output_file_path)
            all_results.append(results)
        console.print("[bold green]处理完成。[/bold green]")

    elif os.path.isdir(input_path):
        # 定义要按名称排除的 Windows 系统文件夹集合
        EXCLUDED_FOLDERS = {
            '$RECYCLE.BIN',
            'System Volume Information',
            'Config.Msi',
            'MSOCache',
            'Recovery',
            '$WinREAgent',
            'Documents and Settings'
        }

        console.print(f"正在递归处理目录: [yellow]{input_path}[/yellow]")
        console.print(f"将按规则忽略以 [dim].[/dim] 或 [dim]__[/dim] 开头的目录/文件。")
        console.print(f"还将按名称忽略以下目录: [dim]{EXCLUDED_FOLDERS}[/dim]")

        file_list = []
        # 使用os.walk遍历目录
        for root, dirs, files in os.walk(input_path):
            # 核心修改1: 混合过滤不想访问的目录
            dirs[:] = [
                d for d in dirs if
                not d.startswith('.') and
                not d.startswith('__') and
                d not in EXCLUDED_FOLDERS
            ]

            # 核心修改2: 过滤不想处理的文件
            for filename in files:
                if not filename.startswith('.') and not filename.startswith('__'):
                    full_path = os.path.join(root, filename)
                    if os.path.isfile(full_path):
                        file_list.append(full_path)

        if not file_list:
            console.print("[yellow]该目录下没有找到符合条件的文件，无需处理。[/yellow]")
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
                        all_results.append(results)
                    progress.update(task, advance=1)
            console.print("[bold green]所有文件处理完成。[/bold green]")

    else:
        console.print(f"[bold red]错误:[/bold red] 路径 '{input_path}' 不是一个有效的文件或目录。")
        sys.exit(1)

    if all_results:
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

        try:
            fieldnames = ['path', 'md5', 'sha1', 'sha256', 'crc32c']
            with open(summary_file_path, "w", encoding="utf-8", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_results)
            console.print(f"\n[bold green]CSV摘要已成功保存到: {os.path.abspath(summary_file_path)}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]错误:[/bold red] 保存CSV摘要到 '{summary_file_path}' 时出错: {e}")








'''
hash_v2.py
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
'''
