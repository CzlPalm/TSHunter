#!/usr/bin/env python3
"""
tls_capture.py — TLS 密钥捕获 + 五元组关联 CLI 工具

示例：
  sudo $(which python3) tls_capture.py --auto
  sudo $(which python3) tls_capture.py --pid 12345
  sudo $(which python3) tls_capture.py --auto -o /tmp/keys.log --wireshark-export /tmp/ws.log
  sudo $(which python3) tls_capture.py --auto --no-tuple --user-data-dir /tmp/chrome_profile
"""

import argparse
import collections
import frida
import os
import pwd
import queue
import signal
import subprocess
import sys
import threading
import time

from lib.correlator import Correlator
from lib.net_lookup import lookup_src
from lib.output_writer import OutputWriter
from lib.version_detect import (
    build_hook_script,
    detect_chrome_version,
    find_chrome_network_pid,
    load_config,
)

DEFAULT_CHROME_BIN = '/opt/google/chrome/chrome'
DEFAULT_USER_DATA = '/tmp/chrome_p3_test'
DEFAULT_ENV_LOG = '/tmp/chrome_sslkeys_env.log'
DEFAULT_OUTPUT = '/tmp/chrome_tls_capture.log'
DEFAULT_CONNECT_WAIT_TIMEOUT = 0.35
FD_TRACKER_READY_TIMEOUT = 5.0
SHUTDOWN_DRAIN_TIMEOUT = 0.5
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FD_TRACKER_BIN = os.path.join(SCRIPT_DIR, 'ebpf', 'fd_tracker')
HOOKS_DIR = os.path.join(SCRIPT_DIR, 'hooks')


device = frida.get_local_device()
sessions = {}
correlator = Correlator()
writer = None
fd_tracker_proc = None
fd_tracker_reader_thread = None
fd_tracker_line_queue = None
spawned_proc = None
args = None
running = True
cleanup_started = False
inflight_callbacks = 0
lock = threading.Lock()

keycount = 0
tuple_hits = 0
src_counts = collections.Counter()
cr_to_tuple = {}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Chrome TLS 密钥捕获 + 五元组关联工具'
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--auto', action='store_true', help='以原始用户身份启动 Chrome 并自动附加')
    mode.add_argument('--pid', type=int, help='attach 指定 PID')

    parser.add_argument('-o', '--output', default=DEFAULT_OUTPUT, help='完整 keylog 输出路径')
    parser.add_argument('--wireshark-export', help='导出 Wireshark 纯净 keylog 文件路径')
    parser.add_argument('--no-tuple', action='store_true', help='跳过 eBPF 五元组关联')
    parser.add_argument('--user-data-dir', default=DEFAULT_USER_DATA, help='Chrome user-data-dir')
    parser.add_argument('--chrome-bin', default=DEFAULT_CHROME_BIN, help='Chrome 可执行文件路径')
    parser.add_argument('--env-log', default=DEFAULT_ENV_LOG, help='启用 SSLKEYLOGFILE 时的输出路径')
    parser.add_argument('--enable-env-keylog', action='store_true',
                        help='自动启动模式下同时设置 SSLKEYLOGFILE，便于与环境变量结果对比')
    parser.add_argument('--connect-wait-timeout', type=float, default=DEFAULT_CONNECT_WAIT_TIMEOUT,
                        help='等待 connect 事件补到的秒数')
    parser.add_argument('--verbose', action='store_true',
                        help='显示 fd_tracker connect 行和更多运行细节')
    return parser.parse_args()


def resolve_hook_script(chrome_bin):
    version = detect_chrome_version(chrome_bin)
    if not version:
        print('\033[31m[!] 无法检测 Chrome 版本\033[0m', flush=True)
        sys.exit(1)

    config = load_config(version, HOOKS_DIR)
    if not config:
        print(f'\033[31m[!] 未找到版本 {version} 的 Hook 配置\033[0m', flush=True)
        print(f'    请在 {HOOKS_DIR} 中添加对应 JSON', flush=True)
        sys.exit(1)

    match_type = config.get('_match_type', 'unknown')
    config_path = config.get('_config_path', '?')
    print(f'[*] Chrome 版本: {version}', flush=True)
    print(f'[*] Hook 配置: {os.path.basename(config_path)} ({match_type})', flush=True)

    return build_hook_script(config, HOOKS_DIR)


def on_message(pid):
    def handler(message, _data):
        global keycount, tuple_hits, inflight_callbacks

        with lock:
            inflight_callbacks += 1

        try:
            if message.get('type') != 'send':
                if message.get('type') == 'error':
                    print(f'\033[31m[ERR pid={pid}]\033[0m {message.get("stack", "")}', flush=True)
                return

            payload = message.get('payload', {})
            msg_type = payload.get('t', '')

            if msg_type == 'key':
                _handle_key(pid, payload)
            elif msg_type == 'dbg':
                print(f'\033[36m[DBG pid={pid}]\033[0m {payload["v"]}', flush=True)
            elif msg_type == 'ready':
                prf = '✓' if payload.get('prf') else '✗'
                keyexp = '✓' if payload.get('keyexp') else '✗'
                hkdf = '✓' if payload.get('hkdf') else '✗'
                print(f'\033[32m[+]\033[0m pid={pid}  PRF={prf}  key_exp={keyexp}  HKDF={hkdf}', flush=True)
        finally:
            with lock:
                inflight_callbacks -= 1

    return handler


def _handle_key(pid, payload):
    global keycount, tuple_hits

    line = payload['v']
    src = payload.get('src', '?')
    fpid = payload.get('pid', pid)
    fd = payload.get('fd', -1)

    with lock:
        keycount += 1
        src_counts[src] += 1
        n = keycount

    parts = line.split(' ')
    cr_hex = parts[1] if len(parts) >= 3 else ''

    tup = cr_to_tuple.get(cr_hex)
    if not tup and not args.no_tuple:
        dst_ip, dst_port, _method = correlator.find_connect(
            fpid, fd, wait_timeout=args.connect_wait_timeout
        )
        if dst_ip:
            src_ip, src_port = lookup_src(fpid, dst_ip, dst_port)
            tup = (src_ip or '?', src_port or 0, dst_ip, dst_port)
            cr_to_tuple[cr_hex] = tup

    if tup:
        with lock:
            tuple_hits += 1
        comment = writer.write_tuple_comment(tup[0], tup[1], tup[2], tup[3], fpid, fd)
        print(f'\033[36m{comment}\033[0m', flush=True)

    writer.write_key(line)

    short = (line[:80] + '...') if len(line) > 80 else line
    colors = {'hkdf': '\033[32m', 'prf': '\033[34m', 'key_exp': '\033[33m'}
    color = colors.get(src, '\033[0m')
    tup_s = f' ->{tup[2]}:{tup[3]}' if tup else ''
    fd_s = f' fd={fd}' if fd and fd > 0 else ''
    print(f'{color}[KEY #{n:4d} {src:7s}{fd_s}{tup_s}]\033[0m {short}', flush=True)


def attach_pid(pid, hook_js, label=''):
    try:
        sess = device.attach(pid)
        script = sess.create_script(hook_js)
        script.on('message', on_message(pid))
        script.load()
        sessions[pid] = sess
        print(f'\033[32m[+]\033[0m 附加 pid={pid} {label}', flush=True)
        return True
    except Exception as exc:
        print(f'\033[31m[-]\033[0m 附加失败 pid={pid}: {exc}', flush=True)
        return False


def _fd_tracker_reader(proc, line_queue):
    try:
        for raw in proc.stderr:
            line = raw.decode('utf-8', errors='ignore').rstrip()
            if not line:
                continue
            is_connect_line = line.startswith('[connect] ')
            if (not is_connect_line) or args.verbose:
                print(line, flush=True)
            line_queue.put(line)
    except Exception:
        pass


def _wait_fd_tracker_ready(proc, line_queue):
    deadline = time.monotonic() + FD_TRACKER_READY_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        remaining = max(0.05, deadline - time.monotonic())
        try:
            line = line_queue.get(timeout=min(0.2, remaining))
        except queue.Empty:
            continue
        if '[+] fd_tracker' in line:
            return True
    return False


def start_fd_tracker():
    global fd_tracker_proc, fd_tracker_reader_thread, fd_tracker_line_queue

    if args.no_tuple:
        print('[*] --no-tuple 已启用：跳过 fd_tracker', flush=True)
        return False

    if not os.path.exists(FD_TRACKER_BIN):
        print(f'\033[33m[!] fd_tracker 未找到: {FD_TRACKER_BIN}\033[0m', flush=True)
        print(f'    cd {os.path.join(SCRIPT_DIR, "ebpf")} && make', flush=True)
        print('    五元组关联将不可用', flush=True)
        return False

    print('[*] 启动 fd_tracker ...', flush=True)
    fd_tracker_proc = subprocess.Popen(
        [FD_TRACKER_BIN, '-v'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    fd_tracker_line_queue = queue.Queue()
    fd_tracker_reader_thread = threading.Thread(
        target=_fd_tracker_reader,
        args=(fd_tracker_proc, fd_tracker_line_queue),
        daemon=True,
    )
    fd_tracker_reader_thread.start()

    if not _wait_fd_tracker_ready(fd_tracker_proc, fd_tracker_line_queue):
        print('\033[31m[!] fd_tracker ready 超时或启动失败\033[0m', flush=True)
        try:
            fd_tracker_proc.terminate()
            fd_tracker_proc.wait(timeout=1)
        except Exception:
            pass
        fd_tracker_proc = None
        return False

    print(f'[+] fd_tracker PID={fd_tracker_proc.pid}', flush=True)
    threading.Thread(
        target=correlator.parse_fd_tracker_lines,
        args=(fd_tracker_line_queue,),
        daemon=True,
    ).start()
    return True


def _sudo_ids():
    sudo_uid = int(os.environ.get('SUDO_UID', os.getuid()))
    sudo_gid = int(os.environ.get('SUDO_GID', os.getgid()))
    return sudo_uid, sudo_gid


def _sudo_user_info():
    try:
        sudo_uid, _ = _sudo_ids()
        return pwd.getpwuid(sudo_uid)
    except Exception:
        return None


def build_spawn_env():
    env = os.environ.copy()
    user_info = _sudo_user_info()
    sudo_uid, _ = _sudo_ids()
    user_home = user_info.pw_dir if user_info else os.path.expanduser('~')

    inherited = {
        'DISPLAY': os.environ.get('DISPLAY'),
        'XAUTHORITY': os.environ.get('XAUTHORITY') or os.path.join(user_home, '.Xauthority'),
        'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{sudo_uid}',
        'WAYLAND_DISPLAY': os.environ.get('WAYLAND_DISPLAY'),
        'HOME': user_home,
        'USER': user_info.pw_name if user_info else os.environ.get('USER', ''),
        'LOGNAME': user_info.pw_name if user_info else os.environ.get('LOGNAME', ''),
    }

    for key, value in inherited.items():
        if value:
            env[key] = value

    if args.enable_env_keylog:
        env['SSLKEYLOGFILE'] = args.env_log
    else:
        env.pop('SSLKEYLOGFILE', None)

    return env


def _demote_preexec(uid, gid):
    def demote():
        os.setgid(gid)
        os.setuid(uid)
    return demote


def spawn_chrome_as_user():
    global spawned_proc

    print(f'[*] auto: 以原始用户身份启动 Chrome -> {args.chrome_bin}', flush=True)
    env = build_spawn_env()
    sudo_uid, sudo_gid = _sudo_ids()
    user_info = _sudo_user_info()
    username = user_info.pw_name if user_info else str(sudo_uid)

    if args.verbose:
        print(f'    user={username} uid={sudo_uid} gid={sudo_gid}', flush=True)
        for name in ('DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'HOME'):
            print(f'    {name}={env.get(name, "<unset>")}', flush=True)
        if args.enable_env_keylog:
            print(f'    SSLKEYLOGFILE={env.get("SSLKEYLOGFILE")}', flush=True)

    spawned_proc = subprocess.Popen(
        [
            args.chrome_bin,
            '--no-sandbox',
            '--log-level=3',
            '--v=0',
            f'--user-data-dir={args.user_data_dir}',
            '--disable-extensions',
        ],
        env=env,
        preexec_fn=_demote_preexec(sudo_uid, sudo_gid),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f'[*] Chrome PID = {spawned_proc.pid} ({username})', flush=True)
    print('[*] 等待 NetworkService 进程出现并自动附加 ...', flush=True)


def attach_existing(hook_js):
    if args.pid:
        print(f'[*] attach 指定 PID={args.pid}', flush=True)
        if not attach_pid(args.pid, hook_js, '[manual]'):
            cleanup(exit_code=1)
        return

    print(f'\n[*] 查找 Chrome NetworkService (--user-data-dir={args.user_data_dir}) ...', flush=True)
    print('[*] 如未启动 Chrome，请在另一终端执行:', flush=True)
    env_prefix = f'SSLKEYLOGFILE={args.env_log} ' if args.enable_env_keylog else ''
    print(f'    {env_prefix}{args.chrome_bin} --no-sandbox --log-level=3 --v=0 \\', flush=True)
    print(f'      --user-data-dir={args.user_data_dir} --disable-extensions &\n', flush=True)

    net_pid = None
    for attempt in range(60):
        net_pid = find_chrome_network_pid(args.user_data_dir)
        if net_pid:
            break
        time.sleep(1)
        if attempt % 10 == 9:
            print(f'    等待中... ({attempt + 1}s)', flush=True)

    if not net_pid:
        print('\033[31m[!] 60s 超时，未找到 NetworkService 进程\033[0m', flush=True)
        cleanup(exit_code=1)

    print(f'[*] NetworkService PID={net_pid}', flush=True)
    if not attach_pid(net_pid, hook_js, '[NetworkService]'):
        cleanup(exit_code=1)

    print('\n\033[32m[+]\033[0m 就绪！访问 HTTPS 站点，Ctrl+C 退出\n', flush=True)


def auto_mode(hook_js):
    spawn_chrome_as_user()
    attach_existing(hook_js)


def request_shutdown(sig=None, frame=None):
    global running
    running = False
    print('\n[*] 收到退出信号，准备清理并输出总结...', flush=True)


def cleanup(exit_code=0):
    global running, fd_tracker_proc, spawned_proc, fd_tracker_line_queue, cleanup_started

    if cleanup_started:
        return
    cleanup_started = True
    running = False

    print('[*] 等待回调线程排空...', flush=True)
    deadline = time.monotonic() + SHUTDOWN_DRAIN_TIMEOUT
    while time.monotonic() < deadline:
        with lock:
            if inflight_callbacks == 0:
                break
        time.sleep(0.01)

    print('[*] 开始执行清理...', flush=True)

    for sess in list(sessions.values()):
        try:
            sess.detach()
        except Exception:
            pass
    sessions.clear()

    if fd_tracker_line_queue is not None:
        try:
            fd_tracker_line_queue.put_nowait(None)
        except Exception:
            pass
        fd_tracker_line_queue = None

    if fd_tracker_proc:
        try:
            fd_tracker_proc.terminate()
            fd_tracker_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                fd_tracker_proc.kill()
                fd_tracker_proc.wait(timeout=1)
            except Exception:
                pass
        except Exception:
            pass
        fd_tracker_proc = None

    if spawned_proc:
        try:
            spawned_proc.terminate()
            spawned_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                spawned_proc.kill()
                spawned_proc.wait(timeout=1)
            except Exception:
                pass
        except Exception:
            pass
        spawned_proc = None

    stats = correlator.stats()
    cache_hits = max(0, tuple_hits - stats['fd_hits'] - stats['time_hits'])
    print(f'[*] 密钥: {keycount} 条', flush=True)
    print(f'    来源: {dict(src_counts)}', flush=True)
    if not args.no_tuple:
        print(f'    五元组命中: {tuple_hits}/{keycount}', flush=True)
        print(f'    关联方式: fd精确={stats["fd_hits"]}  时序={stats["time_hits"]}  缓存={cache_hits}', flush=True)
        print(f'    connect 事件: {stats["total_events"]}  唯一连接: {len(cr_to_tuple)}', flush=True)

    if writer:
        if args.wireshark_export:
            writer.export_wireshark(args.wireshark_export)
            print(f'[*] Wireshark 导出: {args.wireshark_export}', flush=True)
        print(f'[*] 输出文件: {writer.path}', flush=True)

    print('[*] 密钥验证:', flush=True)
    print(f'    diff <(grep -v "^#" {args.output} | sort) \\', flush=True)
    if args.enable_env_keylog:
        print(f'         <(grep -E "^(CLIENT|SERVER|EXPORTER)" {args.env_log} | sort)', flush=True)
    else:
        print('         <(未启用 SSLKEYLOGFILE，对比命令不可用)', flush=True)
    sys.exit(exit_code)


def main():
    global writer, args
    args = parse_args()

    print('=' * 68, flush=True)
    print('  TLS 密钥捕获 + 五元组关联', flush=True)
    print('  密钥: PRF + key_expansion + HKDF  (Frida)', flush=True)
    print('  五元组: eBPF connect() + 时序关联', flush=True)
    print('  颜色: \033[34m蓝\033[0m=PRF  \033[33m黄\033[0m=key_exp  \033[32m绿\033[0m=HKDF  \033[36m青\033[0m=五元组', flush=True)
    print('=' * 68, flush=True)

    if os.geteuid() != 0:
        print('\033[31m[!] 需要 root\033[0m', flush=True)
        print(f'    sudo $(which python3) {sys.argv[0]}', flush=True)
        sys.exit(1)

    writer = OutputWriter(args.output, args.wireshark_export)
    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    hook_js = resolve_hook_script(args.chrome_bin)
    start_fd_tracker()

    if args.auto:
        auto_mode(hook_js)
    else:
        attach_existing(hook_js)

    while running:
        time.sleep(0.1)

    cleanup()


if __name__ == '__main__':
    main()
