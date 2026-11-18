#!/usr/bin/env python3
import functools
import hashlib
import http.server
import io
import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import tarfile
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'site/install.sh').read_text()
VERSION = 'v1.2.3'
ARCHIVE = 'stoop-1.2.3-x86_64-unknown-linux-musl.tar.gz'


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(shell, script, env, *args):
    return subprocess.run([shell, '-s', '--', *args], input=script, text=True,
                          capture_output=True, env=env)


with tempfile.TemporaryDirectory(prefix='stoop-installer-test-') as temp:
    root = Path(temp)
    release = root / 'releases' / VERSION
    release.mkdir(parents=True)
    binary = b'#!/bin/sh\necho fixture\n'
    with tarfile.open(release / ARCHIVE, 'w:gz') as tar:
        info = tarfile.TarInfo('stoop')
        info.mode = 0o755
        info.size = len(binary)
        tar.addfile(info, io.BytesIO(binary))
    payload = (release / ARCHIVE).read_bytes()
    sums = release / 'SHA256SUMS'
    sums.write_text(hashlib.sha256(payload).hexdigest() + '  ' + ARCHIVE + '\n')
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root / 'releases'))
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
    with Server(('127.0.0.1', 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            tools = root / 'tools'
            tools.mkdir()
            for tool in ('uname', 'curl', 'sha256sum', 'shasum', 'grep', 'awk', 'tar', 'mkdir', 'mktemp', 'cat', 'chmod', 'mv', 'rm', 'sed', 'head', 'touch'):
                path = shutil.which(tool)
                if path:
                    (tools / tool).symlink_to(path)
            base = f'http://127.0.0.1:{server.server_address[1]}'
            for shell in ('dash', 'bash'):
                dest = root / shell / 'bin'
                env = dict(os.environ, HOME=str(root), PATH=str(tools), STOOP_VERSION=VERSION,
                           STOOP_RELEASE_BASE=base, STOOP_INSTALL_DIR=str(dest))
                result = run(shell, SCRIPT, env)
                check(result.returncode == 0 and 'SHA-256 verified' in result.stdout, result.stderr)
                check('provenance verification skipped' in result.stdout and 'Add ' in result.stdout, result.stdout)
                check((dest / 'stoop').read_bytes() == binary, 'install bytes')
                check(run(shell, SCRIPT, env).returncode == 0, 'repeat install')
                check(run(shell, SCRIPT, env, '--uninstall').returncode == 0 and not (dest / 'stoop').exists(), 'uninstall')
                check(run(shell, SCRIPT, env, '--dry-run').returncode == 0 and not (dest / 'stoop').exists(), 'dry run')
                check(run(shell, SCRIPT, env, '--help').returncode == 0, 'help')
                sums.write_text('0' * 64 + '  ' + ARCHIVE + '\n')
                result = run(shell, SCRIPT, env)
                check(result.returncode != 0 and not (dest / 'stoop').exists(), 'checksum mismatch must fail closed')
                broken = SCRIPT.replace('[ "$actual" = "$expected" ] ||', 'true ||')
                result = run(shell, broken, env)
                try:
                    check(result.returncode != 0 and not (dest / 'stoop').exists(), 'checksum mismatch must fail closed')
                except AssertionError:
                    print(shell, 'checksum negative control detected')
                else:
                    raise AssertionError('checksum negative control passed')
                (dest / 'stoop').unlink()
                sums.write_text(hashlib.sha256(payload).hexdigest() + '  ' + ARCHIVE + '\n')
                (release / ARCHIVE).write_bytes(payload[:len(payload) // 2])
                result = run(shell, SCRIPT, env)
                check(result.returncode != 0 and not (dest / 'stoop').exists(), 'truncated download')
                (release / ARCHIVE).write_bytes(payload)
                truncated = SCRIPT[:len(SCRIPT) // 2]
                result = run(shell, truncated, env)
                check(result.returncode != 0 and not (dest / 'stoop').exists(), 'truncated script')
                broken_truncated = f'mkdir -p "{dest}"; touch "{dest}/stoop"\n' + truncated
                run(shell, broken_truncated, env)
                try:
                    check(not (dest / 'stoop').exists(), 'truncated script must do nothing')
                except AssertionError:
                    print(shell, 'truncation negative control detected')
                else:
                    raise AssertionError('truncation negative control passed')
                (dest / 'stoop').unlink()
                fake_uname = root / 'fake-uname'
                fake_uname.mkdir(exist_ok=True)
                uname = fake_uname / 'uname'
                uname.write_text('#!/bin/sh\necho Unsupported\n')
                uname.chmod(0o755)
                bad_env = dict(env, PATH=f'{fake_uname}:{tools}')
                check(run(shell, SCRIPT, bad_env).returncode != 0, 'unsupported platform')
                check(run(shell, SCRIPT, dict(env, STOOP_VERSION='v2.0.0')).returncode != 0, 'version pin')
                check(run(shell, SCRIPT, dict(env, STOOP_RELEASE_BASE='http://example.com')).returncode != 0, 'remote HTTP')
                (tools / 'sha256sum').unlink(missing_ok=True)
                (tools / 'shasum').unlink(missing_ok=True)
                check(run(shell, SCRIPT, env).returncode != 0, 'missing checksum tool')
                for tool in ('sha256sum', 'shasum'):
                    path = shutil.which(tool)
                    if path:
                        (tools / tool).symlink_to(path)
                print(shell, 'installer tests passed')
        finally:
            server.shutdown()
            thread.join()
