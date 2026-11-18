import os
import sys

alias, directory, root = sys.argv[1:]
link = os.path.join(directory, 'alias')
next_link = os.path.join(directory, 'next')
child = os.fork()
if child == 0:
    for _ in range(100):
        with open(os.path.join(alias, 'alias', 'side'), 'w') as handle:
            handle.write('side')
    os._exit(0)
for index in range(100):
    os.symlink(os.path.join(root, 'sub') if index % 2 else root, next_link)
    os.replace(next_link, link)
os.waitpid(child, 0)
os.symlink(os.path.join(root, 'sub'), next_link)
os.replace(next_link, link)
with open(os.path.join(alias, 'alias', 'final'), 'w') as handle:
    handle.write('final')
