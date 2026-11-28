#!/usr/bin/env python3
"""Exercise stoop against a real pytest in local-mode on a Linux runner.

The project generator and ordinary sequence originate in probe commit 1fd4998.
Each scenario has its own project and records its outputs and bundle state.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


EVIDENCE = Path(os.environ['RUNNER_TEMP']) / 'pytest-trial-evidence'
EVIDENCE.mkdir(parents=True, exist_ok=True)
RESULTS = EVIDENCE / 'results.jsonl'
WORK = Path(tempfile.mkdtemp(prefix='stoop-pytest-trial-', dir=os.environ['RUNNER_TEMP']))
STOOP = None
TESTS = None
TOUCH = '05-stale-bytecode-touch-is-a-documented-content-identity-skip'


def save(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def unit_path(i, flat=False):
    if flat:
        return f'tests/test_{i:02}.py'
    return f'tests/group_{i:02}/test_{i:02}.py'


def project(name, *, placeholder='changed', unit_env=True, flat=False, units_enabled=True):
    root = WORK / name
    root.mkdir()
    save(root / 'src/__init__.py', '')
    save(root / 'src/common.py', 'def compute(value, base):\n    return value * 2 + base\n')
    save(root / 'src/partial.py', 'def adjustment(value):\n    return value * 0\n')
    save(root / 'src/only07.py', 'def adjustment(value):\n    return value * 0\n')
    save(root / 'src/only08.py', 'def adjustment(value):\n    return value * 0\n')
    save(root / 'data/params.json', '[1, 2, 3]\n')
    save(root / 'pytest.ini', '[pytest]\ntestpaths = tests\naddopts = --collect-in-virtualenv\n')
    save(root / 'tests/conftest.py', '''import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

@pytest.fixture
def base():
    return 10

def pytest_sessionstart(session):
    print("PYTEST_LAUNCH " + json.dumps(sys.argv[1:]), flush=True)
''')
    for i in range(TESTS - 1):
        partial_import = 'from src.partial import adjustment\n' if i < 3 else ''
        expression = 'compute(value, base) + adjustment(value)' if i < 3 else 'compute(value, base)'
        if i in (7, 8):
            partial_import += f'from src.only{i:02} import adjustment as single_adjustment\n'
            expression += ' + single_adjustment(value)'
        save(root / unit_path(i, flat), f'''import pytest
from src.common import compute
{partial_import}
@pytest.mark.parametrize("value", [1, 3, 9])
def test_unit_{i:02}(value, base):
    assert {expression} == value * 2 + base
''')
    parent = 1 if flat else 2
    save(root / unit_path(TESTS - 1, flat), f'''import json
from pathlib import Path
import pytest
from src.common import compute

DATA = json.loads((Path(__file__).resolve().parents[{parent}] / 'data' / 'params.json').read_text())

@pytest.mark.parametrize("value", DATA)
def test_parametrized_data(value, base):
    assert value > 0
    assert compute(value, base) == value * 2 + base
''')
    save(root / '.stoopignore', '__pycache__\n.pytest_cache\n')
    arg = '{' + placeholder + ':tests/**/test_*.py}'
    cmd = ['pytest', '-q', '-s', '--', arg]
    match = ', '.join(json.dumps(word) for word in cmd)
    overlay = ('unit_env = { PYTHONDONTWRITEBYTECODE = "1", '
               'PYTHONPYCACHEPREFIX = "/dev/null/stoop" }\n') if unit_env else ''
    disabled = '' if units_enabled else '[units]\nenabled = false\n\n'
    save(root / '.stoop.toml', f'''{disabled}[[units.suite]]
id = "pytest-{name}"
cwd = "."
match = [{match}]
units = ["tests/**/test_*.py"]
{overlay}''')
    return root, cmd


def env_for(*, bytecode=True, split=True):
    env = {key: value for key, value in os.environ.items() if not key.startswith('STOOP_')}
    # This trial exercises local-mode completion on the hosted hardware; it does not
    # claim that completion runs under stoop's ordinary CI policy.
    env.pop('CI', None)
    env.pop('GITHUB_ACTIONS', None)
    env.pop('PYTHONPYCACHEPREFIX', None)
    env.pop('PYTEST_ADDOPTS', None)
    env.pop('PYTEST_PLUGINS', None)
    if bytecode:
        env.pop('PYTHONDONTWRITEBYTECODE', None)
    else:
        env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    if split:
        env['STOOP_SPLIT'] = '1'
        env['STOOP_SPLIT_GROUP'] = '1'
    env['STOOP_LEARN_VOLATILE'] = '0'
    return env


def invoke(argv, root, env):
    start = time.monotonic()
    completed = subprocess.run(argv, cwd=root, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return completed.returncode, time.monotonic() - start, completed.stdout, completed.stderr


def bundle_state(root):
    bundles = []
    store = root / '.stoop' / 'units' / 'v1'
    for file in sorted(store.glob('*.json')):
        data = json.loads(file.read_text(encoding='utf-8'))
        units = data.get('units', {})
        if not isinstance(units, dict):
            continue
        bundles.append({
            'file': str(file.relative_to(root)),
            'suite': data.get('suite'),
            'state': data.get('state'),
            'residue': data.get('residue'),
            'roster_count': len(data.get('roster', {}).get('units', [])),
            'proof_count': sum(bool(versions) for versions in units.values()),
            'units': units,
            'table': data.get('table'),
        })
    return bundles


def decision(lines):
    for line in lines:
        if line.startswith('stoop: run full '):
            return 'full'
        if line.startswith('stoop: skip '):
            return 'skip'
        if line.startswith('stoop: tracked ') and '; run ' in line:
            return 'subset'
        if line.startswith('stoop: attribution pass:'):
            return 'pass'
    return 'unknown'


def run_case(name, label, root, cmd, env, *, binary=None):
    folder = EVIDENCE / name / label
    folder.mkdir(parents=True, exist_ok=True)
    print(f'\n===== {name} / {label} =====', flush=True)
    binary = STOOP if binary is None else binary
    stoop_cmd = [str(binary), 'run', '--root', str(root), '--'] + cmd
    a, at, ao, ae = invoke(stoop_cmd, root, env)
    b, bt, bo, be = invoke(cmd[:-1], root, env)
    x, _, xo, xe = invoke([str(binary), 'explain', '--root', str(root), '--'] + cmd, root, env)
    states = bundle_state(root)
    for file, text in [('stoop.stdout', ao), ('stoop.stderr', ae),
                       ('direct.stdout', bo), ('direct.stderr', be),
                       ('explain.stdout', xo), ('explain.stderr', xe)]:
        save(folder / file, text)
    save(folder / 'bundles.json', json.dumps(states, indent=2) + '\n')
    lines = (ao + '\n' + ae).splitlines()
    launch_lines = [line for line in lines if line.startswith('PYTEST_LAUNCH ')]
    stoop_lines = [line for line in lines if line.startswith('stoop:')]
    item = {
        'scenario': name, 'step': label, 'decision': decision(stoop_lines),
        'launches': len(launch_lines), 'launch_args': launch_lines,
        'stoop_rc': a, 'direct_rc': b, 'stoop_seconds': round(at, 3),
        'direct_seconds': round(bt, 3), 'explain_rc': x,
        'stoop_lines': stoop_lines, 'bundles': states,
        'wrong_verdict': a == 0 and b != 0,
    }
    # This one skip is the deliberately reproduced hidden-cache limitation.
    # Every other stoop pass with a failing direct run remains a stop.
    documented_skip = (
        name in ('stale-bytecode', 'stale-bytecode-control-head-units-off',
                 'stale-bytecode-control-base-units-off')
        and label == TOUCH and item['decision'] == 'skip'
        and item['launches'] == 0 and a == 0 and b == 1
    )
    if documented_skip:
        item['documented_limitation'] = 'ignored stale bytecode and content-identity skip'
    with RESULTS.open('a', encoding='utf-8') as out:
        out.write(json.dumps(item) + '\n')
    print('RESULT ' + json.dumps({k: v for k, v in item.items() if k != 'bundles'}), flush=True)
    for state in states:
        print('BUNDLE ' + json.dumps({k: v for k, v in state.items() if k not in ('units', 'table')}), flush=True)
    if item['wrong_verdict'] and not documented_skip:
        save(EVIDENCE / 'WRONG_VERDICT.txt', f'{name}/{label}: stoop={a} direct={b}\n')
        raise AssertionError(f'WRONG VERDICT {name}/{label}: stoop={a}, direct={b}')
    return item


def expect(item, *, kind, launches, proofs, residue, status='ready',
           stoop=0, direct=0, reason=None):
    name = f"{item['scenario']}/{item['step']}"
    checks = {'decision': kind, 'launches': launches, 'stoop_rc': stoop, 'direct_rc': direct}
    for key, expected in checks.items():
        actual = item[key]
        assert actual == expected, f'{name}: {key}: expected {expected!r}, found {actual!r}'
    bundles = item['bundles']
    assert len(bundles) == 1, f'{name}: expected one suite bundle, found {len(bundles)}'
    bundle = bundles[0]
    assert bundle['proof_count'] == proofs, f"{name}: expected {proofs} unit proofs, found {bundle['proof_count']}"
    state = bundle['state'] or {}
    assert state.get('status') == status, f"{name}: expected suite {status}, found {state}"
    observed = bundle['residue'] or {}
    expected_state, expected_count = residue
    assert observed.get('state') == expected_state, f"{name}: expected residue {expected_state}, found {observed}"
    assert observed.get('count') == expected_count, f"{name}: expected residue count {expected_count}, found {observed}"
    if reason:
        assert reason in '\n'.join(item['stoop_lines']), f'{name}: expected reason {reason!r}'


def step(name, label, root, cmd, env, **expected):
    expect(run_case(name, label, root, cmd, env), **expected)


def append(root, path, text):
    with (root / path).open('a', encoding='utf-8') as file:
        file.write(text)

def nested(env):
    name = 'nested-unit-env'
    root, cmd = project(name)
    common = {'proofs': TESTS, 'residue': ('confirmed', 0)}
    step(name, '01-cold', root, cmd, env, kind='full', launches=TESTS + 1, **common)
    step(name, '02-unchanged', root, cmd, env, kind='skip', launches=0, **common)
    append(root, unit_path(4), '\n# changed one\n')
    step(name, '03-edit-one', root, cmd, env, kind='subset', launches=1, **common)
    append(root, unit_path(7), '\n# changed two A\n')
    append(root, unit_path(8), '\n# changed two B\n')
    step(name, '04-edit-two', root, cmd, env, kind='subset', launches=1,
         proofs=TESTS, residue=('none', 0))
    append(root, 'src/only07.py', '\n# changed private source\n')
    append(root, 'src/only08.py', '\n# changed private source\n')
    step(name, '05-two-private-sources', root, cmd, env, kind='full', launches=3, **common)
    append(root, 'src/partial.py', '\n# changed input for three units\n')
    step(name, '06-shared-source', root, cmd, env, kind='subset', launches=1,
         proofs=TESTS, residue=('none', 0))
    append(root, 'tests/conftest.py', '\n# shared fixture change\n')
    step(name, '07-conftest', root, cmd, env, kind='full', launches=TESTS + 1, **common)
    save(root / unit_path(TESTS), 'def test_new(base):\n    assert base == 10\n')
    step(name, '08-add', root, cmd, env, kind='full', launches=TESTS + 2,
         proofs=TESTS + 1, residue=('confirmed', 0))
    (root / unit_path(TESTS - 2)).unlink()
    step(name, '09-delete', root, cmd, env, kind='full', launches=1,
         proofs=TESTS, residue=('confirmed', 1))
    old = root / unit_path(TESTS - 3)
    old.rename(old.with_name(f'test_{TESTS + 1:02}.py'))
    after_delete = {'proofs': TESTS, 'residue': ('confirmed', 1)}
    step(name, '10-rename', root, cmd, env, kind='full', launches=2, **after_delete)
    test = root / unit_path(5)
    before = test.read_text(encoding='utf-8')
    save(test, before + '\ndef test_injected_failure():\n    assert False, "intentional trial failure"\n')
    step(name, '11-failing-test', root, cmd, env, kind='full', launches=1,
         stoop=1, direct=1, **after_delete)
    save(test, before)
    step(name, '12-fixed-test', root, cmd, env, kind='skip', launches=0, **after_delete)
    save(root / 'data/params.json', '[1, 2, 3, 4]\n')
    step(name, '13-parameter-data', root, cmd, env, kind='full', launches=2, **after_delete)
    save(root / 'data/params.json', '[1, -1, 3]\n')
    step(name, '14-parameter-data-fails', root, cmd, env, kind='full', launches=1,
         stoop=1, direct=1, **after_delete)
    save(root / 'data/params.json', '[1, 2, 3]\n')
    step(name, '15-parameter-data-fixed', root, cmd, env, kind='skip', launches=0, **after_delete)


def controls(env):
    name = 'nested-no-unit-env'
    root, cmd = project(name, unit_env=False)
    step(name, '01-cold', root, cmd, env, kind='full', launches=2, proofs=0,
         residue=('none', 0), status='disabled', reason='exited 0 without reading it')

    name = 'unit-per-launch-unit-env'
    root, cmd = project(name, placeholder='unit')
    common = {'proofs': TESTS, 'residue': ('confirmed', 0)}
    step(name, '01-cold', root, cmd, env, kind='full', launches=TESTS + 1, **common)
    append(root, unit_path(4), '\n# changed one\n')
    step(name, '02-edit-one', root, cmd, env, kind='subset', launches=1, **common)
    append(root, unit_path(7), '\n# changed two A\n')
    append(root, unit_path(8), '\n# changed two B\n')
    step(name, '03-edit-two', root, cmd, env, kind='subset', launches=2, **common)
    append(root, 'src/partial.py', '\n# changed input for three units\n')
    step(name, '04-shared-source', root, cmd, env, kind='subset', launches=3, **common)

    name = 'flat-unit-env'
    root, cmd = project(name, flat=True)
    step(name, '01-cold', root, cmd, env, kind='full', launches=TESTS + 1, **common)
    append(root, unit_path(4, flat=True), '\n# changed one\n')
    step(name, '02-edit-one', root, cmd, env, kind='full', launches=TESTS + 1, **common)


def legacy_stale_control(name, binary):
    # The units engine is explicitly disabled as well as STOOP_SPLIT being absent.
    # This isolates the legacy whole-command cache from unit attribution.
    root, cmd = project(name, unit_env=False, units_enabled=False)
    env = env_for(bytecode=True, split=False)

    def check(label, expected_kind, expected_launches, expected_stoop=0, expected_direct=0, run_env=None):
        item = run_case(name, label, root, cmd, run_env or env, binary=binary)
        expected = {'decision': expected_kind, 'launches': expected_launches,
                    'stoop_rc': expected_stoop, 'direct_rc': expected_direct}
        for key, value in expected.items():
            assert item[key] == value, f"{name}/{label}: {key}: expected {value!r}, found {item[key]!r}"
        assert sum(bundle['proof_count'] for bundle in item['bundles']) == 0, f'{name}/{label}: unexpected unit proofs'
        for bundle in item['bundles']:
            residue = bundle['residue'] or {}
            assert residue.get('state') == 'none' and residue.get('count') == 0, f'{name}/{label}: {residue}'

    check('01-cold', 'full', 1)
    check('02-unchanged', 'skip', 0)
    test = root / unit_path(4)
    before = test.read_text(encoding='utf-8')
    failing = before.replace(' == ', ' != ', 1)
    assert failing != before and len(failing.encode()) == len(before.encode())
    stat = test.stat()
    save(test, failing)
    os.utime(test, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    check('03-same-size-same-mtime', 'full', 1)
    check('04-forced-full', 'full', 1, run_env=dict(env, STOOP_FULL='1'))
    os.utime(test, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
    check(TOUCH, 'skip', 0, expected_stoop=0, expected_direct=1)


def stale_bytecode(env):
    name = 'stale-bytecode'
    root, cmd = project(name)
    step(name, '01-cold', root, cmd, env, kind='full', launches=TESTS + 1,
         proofs=TESTS, residue=('confirmed', 0))
    step(name, '02-unchanged', root, cmd, env, kind='skip', launches=0,
         proofs=TESTS, residue=('confirmed', 0))
    test = root / unit_path(4)
    before = test.read_text(encoding='utf-8')
    failing = before.replace(' == ', ' != ', 1)
    assert failing != before and len(failing.encode()) == len(before.encode())
    stat = test.stat()
    save(test, failing)
    os.utime(test, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    step(name, '03-same-size-same-mtime', root, cmd, env, kind='subset', launches=1,
         proofs=TESTS, residue=('confirmed', 0), stoop=1, direct=0)
    forced = dict(env, STOOP_FULL='1')
    step(name, '04-forced-full', root, cmd, forced, kind='full', launches=2,
         proofs=TESTS, residue=('none', 0), status='disabled',
         reason='failed alone while the full command passed')
    # The passing full run has recorded a whole proof for the changed content.
    # Touching only mtime makes pytest recompile, but does not change that proof's
    # content identity. The ignored pyc is outside its inputs (issue #99).
    os.utime(test, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
    step(name, TOUCH, root, cmd, env, kind='skip', launches=0,
         proofs=TESTS, residue=('none', 0), status='disabled', stoop=0, direct=1)


def main():
    global STOOP, TESTS
    parser = argparse.ArgumentParser()
    parser.add_argument('stoop', type=Path)
    parser.add_argument('--base-stoop', type=Path,
                        help='also run the units-off control against this pre-unit_env binary')
    parser.add_argument('--tests', type=int, default=12)
    args = parser.parse_args()
    if args.tests < 10:
        parser.error('--tests must be at least 10')
    STOOP, TESTS = args.stoop.resolve(), args.tests
    print('HEAD_COMMIT=' + os.environ.get('GITHUB_SHA', 'unknown'), flush=True)
    print('STOOP_VERSION=' + subprocess.check_output([str(STOOP), '--version'], text=True).strip(), flush=True)
    print('PYTEST_VERSION=' + subprocess.check_output(['pytest', '--version'], text=True).strip(), flush=True)
    print(f'RUNNER_ARCH={os.environ.get("RUNNER_ARCH", "unknown")} TEST_MODULES={TESTS}', flush=True)
    print('LOCAL_MODE: CI and GITHUB_ACTIONS unset for stoop; full pytest bytecode enabled', flush=True)
    env = env_for(bytecode=True)
    if args.base_stoop:
        legacy_stale_control('stale-bytecode-control-base-units-off', args.base_stoop.resolve())
    else:
        print('PRE_UNIT_ENV_BASE_CONTROL=not supplied', flush=True)
    legacy_stale_control('stale-bytecode-control-head-units-off', STOOP)
    nested(env)
    controls(env)
    stale_bytecode(env)
    print('TRIAL PASSED: results and timings are in the artifact.', flush=True)


try:
    main()
except BaseException as exc:
    save(EVIDENCE / 'FAILURE.txt', f'{type(exc).__name__}: {exc}\n')
    shutil.make_archive(str(EVIDENCE / 'project-on-failure'), 'zip', WORK)
    raise
finally:
    shutil.rmtree(WORK)
