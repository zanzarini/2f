"""Mutation testing for the SDKs: remove one check at a time, by line, and
see whether the SDK's own tests notice. See docs/TESTING.md.

    python3 scripts/mutate_sdk.py ts . /tmp/sdkmut-ts
    python3 scripts/mutate_sdk.py py . /tmp/sdkmut-py

The checks are named by line number, so the two tables below have to follow
the SDK sources when those change. The script prints the line it removed.
"""
import os
import shutil
import subprocess
import sys

which, repo, work = sys.argv[1], sys.argv[2], sys.argv[3]

if which == 'ts':
    target, command, cwd, blank = 'ts/index.js', ['node', '--test'], 'ts', ''
    lines = {
        26: 'floats accepted', 27: 'unsafe integers accepted', 74: 'receipt version unchecked',
        76: 'unknown key accepted', 78: 'receipt signature unchecked', 82: 'receipt field types unchecked',
        84: 'expired receipt accepted', 85: 'receipt from the future accepted',
        89: 'receipt for another action accepted', 127: 'plain http accepted', 139: 'redirects followed',
        186: 'receipt of another challenge accepted', 188: 'receipt not marked as used',
    }
else:
    target, command, cwd, blank = 'python/twof.py', [sys.executable, '-m', 'unittest', '-q'], 'python', 'pass'
    lines = {
        52: 'unsafe integers accepted', 55: 'floats accepted', 127: 'receipt version unchecked',
        132: 'receipt signature unchecked', 135: 'receipt field types unchecked', 139: 'expired receipt accepted',
        141: 'receipt from the future accepted', 143: 'receipt for another action accepted',
        196: 'plain http accepted', 252: 'receipt of another challenge accepted',
        254: 'receipt not marked as used',
    }

if os.path.exists(work):
    shutil.rmtree(work)
shutil.copytree(os.path.join(repo, 'sdk'), work, ignore=shutil.ignore_patterns('__pycache__', 'corpus.json'))
path = os.path.join(work, target)
original = open(path, encoding='utf-8').read().split('\n')


def passes():
    done = subprocess.run(command, cwd=os.path.join(work, cwd), capture_output=True, text=True)
    return done.returncode == 0


assert passes(), 'the unmutated SDK must pass'
survivors = []
for number, name in sorted(lines.items()):
    mutated = list(original)
    line = mutated[number - 1]
    indent = line[:len(line) - len(line.lstrip())]
    mutated[number - 1] = indent + blank if blank else ''
    open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(mutated))
    if passes():
        survivors.append(name)
        print(f'SURVIVED  {name}   (line {number}: {line.strip()[:70]})')
    else:
        print(f'caught    {name}')
open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(original))
print(f'{which}: {len(survivors)} survivor(s) {survivors}')
