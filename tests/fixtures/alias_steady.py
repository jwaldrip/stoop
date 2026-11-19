import os
import sys

# Writes through an alias to the repository root, with nothing retargeting the alias.
alias = sys.argv[1]
for _ in range(100):
    with open(os.path.join(alias, 'alias', 'side'), 'w') as handle:
        handle.write('side')
with open(os.path.join(alias, 'alias', 'final'), 'w') as handle:
    handle.write('final')
