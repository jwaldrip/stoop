#!/usr/bin/env python3
import re
import sys
from pathlib import Path

source = Path('Cargo.toml').read_text()
package = re.search(r'^\[package\]\s*$(.*?)(?=^\[|\Z)', source, re.M | re.S)
version = re.search(r'^version\s*=\s*"([^"]+)"\s*$', package.group(1), re.M) if package else None
tag = sys.argv[1] if len(sys.argv) == 2 else ''
if not version or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag) or tag != 'v' + version.group(1):
    sys.exit('Release tag must equal v plus the Cargo.toml package version.')
print(version.group(1))
