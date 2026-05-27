<img width="211" height="442" alt="image" src="https://github.com/user-attachments/assets/37239d95-60c0-4666-a957-23bcfe3cf135" />#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TRON 靓号生成器（高级优化版 v2）
====================================================

特性：
✔ 低 CPU 占用（批处理 + 降载休眠）
✔ 多进程生成 + 独立写入进程（无文件锁竞争）
✔ 支持前缀/后缀/中间包含/连号（可组合）
✔ 优雅退出（Ctrl+C 安全结束所有进程）
✔ 无需 psutil（仅 Linux 下可选 nice）

依赖：
    pip install tronpy

运行：
    python tron_vanity.py
"""

import os
import sys
import time
import signal
import platform
from multiprocessing import Process, Queue, Value, cpu_count
from typing import List, Tuple, Optional

from tronpy.keys import PrivateKey


# =========================================================
# 平台相关的优先级设置（可选）
# =========================================================
def set_low_priority(nice_level: int = 10) -> None:
    """尝试降低当前进程的优先级（仅 Linux/macOS）"""
    if nice_level <= 0:
        return
    if platform.system() == "Windows":
        # Windows 下需要 pywin32 或 ctypes，这里省略避免额外依赖
        # 用户可以手动在任务管理器中设置优先级
        return
    try:
        os.nice(nice_level)
    except Exception:
        pass


# =========================================================
# 连号检测（末尾重复字符）
# =========================================================
def has_repeat_tail(addr: str, lengths: Tuple[int, ...]) -> bool:
    """检查地址末尾是否有指定长度的重复字符"""
    for length in lengths:
        if len(addr) < length:
            continue
        tail = addr[-length:]
        # 检查所有字符是否与首字符相同
        if all(ch == tail[0] for ch in tail):
            return True
    return False


# =========================================================
# 中间包含检测（已足够快，无需预过滤）
# =========================================================
def has_any_substring(addr: str, substrings: Tuple[str, ...]) -> bool:
    """检查地址是否包含任意一个子串"""
    for sub in substrings:
        if sub in addr:
            return True
    return False


# =========================================================
# 综合匹配逻辑（OR 模式）
# =========================================================
def is_match(
    addr: str,
    prefixes: Tuple[str, ...],
    suffixes: Tuple[str, ...],
    repeat_lengths: Tuple[int, ...],
    contains: Tuple[str, ...],
) -> bool:
    """按顺序检测，任一条件满足即返回 True"""
    # 前缀（最快）
    if prefixes and addr.startswith(prefixes):
        return True
    # 后缀
    if suffixes and addr.endswith(suffixes):
        return True
    # 连号
    if repeat_lengths and has_repeat_tail(addr, repeat_lengths):
        return True
    # 中间包含（相对最慢）
    if contains and has_any_substring(addr, contains):
        return True
    return False


# =========================================================
# 独立写入进程（使用哨兵退出）
# =========================================================
def writer_process(result_queue: Queue, output_file: str) -> None:
    """从队列中取出命中结果并写入文件"""
    with open(output_file, "a", encoding="utf-8") as f:
        while True:
            line = result_queue.get()  # 阻塞等待
            if line is None:           # 哨兵值，表示退出
                break
            f.write(line + "\n")
            f.flush()


# =========================================================
# 工作进程
# =========================================================
def worker(
    pid: int,
    prefixes: Tuple[str, ...],
    suffixes: Tuple[str, ...],
    repeat_lengths: Tuple[int, ...],
    contains: Tuple[str, ...],
    result_queue: Queue,
    total_counter: Value,
    hit_counter: Value,
    quiet: bool,
    nice_level: int,
    batch_size: int,
    sleep_time: float,
) -> None:
    """生成地址并检测靓号，结果放入队列"""
    set_low_priority(nice_level)

    local_checked = 0      # 本地生成计数（批量同步）
    local_hits = 0         # 本地命中计数（批量同步）

    while True:
        # 批量生成
        for _ in range(batch_size):
            pk = PrivateKey.random()
            addr = pk.public_key.to_base58check_address()
            local_checked += 1

            if is_match(addr, prefixes, suffixes, repeat_lengths, contains):
                local_hits += 1
                line = f"{addr} | {pk.hex()}"
                result_queue.put(line)

                if not quiet:
                    print("\n" + "=" * 70)
                    print(f"[进程 {pid}] 🎯 命中")
                    print(f"地址: {addr}")
                    print(f"私钥: {pk.hex()}")
                    print("=" * 70)

        # 批量同步全局计数器（减少锁竞争）
        with total_counter.get_lock():
            total_counter.value += local_checked
        with hit_counter.get_lock():
            hit_counter.value += local_hits
        local_checked = 0
        local_hits = 0

        # 主动降载
        time.sleep(sleep_time)

        # 定期输出状态
        if not quiet:
            # 每 50 万次打印一次（通过全局计数器判断）
            current_total = total_counter.value
            if current_total % 500_000 < batch_size:  # 避免每个进程都打
                print(f"[进程 {pid}] 总生成: {current_total:,} | 总命中: {hit_counter.value}")


# =========================================================
# 交互式配置（增强容错）
# =========================================================
def input_list(prompt: str) -> Tuple[str, ...]:
    """输入逗号分隔的列表，返回元组"""
    val = input(prompt).strip()
    if not val:
        return ()
    return tuple(x.strip() for x in val.split(",") if x.strip())


def input_int(prompt: str, default: int) -> int:
    val = input(prompt).strip()
    if val.isdigit():
        return int(val)
    return default


def input_float(prompt: str, default: float) -> float:
    val = input(prompt).strip()
    if not val:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def get_config():
    print("\n" + "=" * 70)
    print(" TRON 靓号生成器（高级优化版 v2）")
    print("=" * 70)
    print("\n支持：前缀 / 后缀 / 中间包含 / 连号（末尾重复）")
    print("可同时启用多项，任意匹配即命中\n")

    prefixes = input_list("前缀（如 TAAA,TTRX，可留空）: ")
    suffixes = input_list("后缀（如 888,666，可留空）: ")
    contains = input_list("中间包含（如 TRX,888，可留空）: ")

    repeat_input = input("连号长度（如 2,3,4，可留空）: ").strip()
    repeat_lengths = ()
    if repeat_input:
        lengths = []
        for x in repeat_input.split(","):
            x = x.strip()
            if x.isdigit():
                n = int(x)
                if n >= 2:
                    lengths.append(n)
        repeat_lengths = tuple(lengths)

    # 默认规则：若没有任何规则，自动使用 后缀888 + 连号2
    if not (prefixes or suffixes or contains or repeat_lengths):
        print("\n✨ 未设置任何规则，自动使用默认：后缀=888, 连号长度=2")
        suffixes = ("888",)
        repeat_lengths = (2,)

    # 系统资源设置
    cpu_cores = cpu_count()
    default_proc = max(1, cpu_cores - 2)   # 保留两个核心给系统
    processes = input_int(f"进程数（默认 {default_proc}，CPU核心={cpu_cores}）: ", default_proc)
    batch_size = input_int("批量生成（默认 1000）: ", 1000)
    sleep_time = input_float("CPU降载时间（秒，默认 0.001）: ", 0.001)

    nice_input = input("降低进程优先级（Linux/macOS有效，y/n 默认 y）: ").strip().lower()
    nice_level = 10 if nice_input != 'n' else 0

    output_file = input("输出文件（默认 wallets.txt）: ").strip()
    if not output_file:
        output_file = "wallets.txt"

    quiet = input("安静模式（不打印进度，y/n 默认 y）: ").strip().lower() != 'n'

    # 显示配置
    print("\n" + "=" * 70)
    print("配置确认")
    print("=" * 70)
    if prefixes:       print(f"前缀：      {', '.join(prefixes)}")
    if suffixes:       print(f"后缀：      {', '.join(suffixes)}")
    if contains:       print(f"中间包含：  {', '.join(contains)}")
    if repeat_lengths: print(f"连号长度：  {repeat_lengths}")
    print(f"进程数：     {processes}")
    print(f"批量大小：   {batch_size}")
    print(f"降载休眠：   {sleep_time} 秒")
    print(f"Nice等级：   {nice_level}")
    print(f"输出文件：   {output_file}")
    print(f"安静模式：   {'是' if quiet else '否'}")
    print("=" * 70 + "\n")

    return (
        prefixes, suffixes, repeat_lengths, contains,
        processes, output_file, quiet, nice_level, batch_size, sleep_time
    )


# =========================================================
# 主程序（带优雅退出）
# =========================================================
def main():
    (prefixes, suffixes, repeat_lengths, contains,
     processes, output_file, quiet, nice_level,
     batch_size, sleep_time) = get_config()

    # 共享队列和计数器
    result_queue = Queue()
    total_counter = Value('L', 0)   # 无符号长整型
    hit_counter = Value('L', 0)

    # 启动写入进程
    writer = Process(target=writer_process, args=(result_queue, output_file))
    writer.start()

    # 启动工作进程
    workers = []
    for i in range(processes):
        p = Process(
            target=worker,
            args=(
                i, prefixes, suffixes, repeat_lengths, contains,
                result_queue, total_counter, hit_counter,
                quiet, nice_level, batch_size, sleep_time
            )
        )
        p.start()
        workers.append(p)

    # 定义退出处理函数
    def graceful_shutdown(signum=None, frame=None):
        print("\n🛑 收到退出信号，正在停止所有进程...")
        # 发送哨兵值给写入进程
        result_queue.put(None)
        # 终止所有工作进程（强制）
        for p in workers:
            p.terminate()
        # 等待写入进程结束
        writer.join()
        print("所有进程已退出。")
        sys.exit(0)

    # 注册信号处理（Ctrl+C）
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    # 等待所有工作进程结束（正常情况下不会结束，除非强制终止）
    for p in workers:
        p.join()

    # 如果工作进程意外全部退出，通知写入进程退出
    result_queue.put(None)
    writer.join()


if __name__ == "__main__":
    main()
