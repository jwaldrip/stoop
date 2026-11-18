#!/usr/bin/env python3
import gzip
import io
import os
import sys
import tarfile

binary, output = sys.argv[1:]
with open(binary, 'rb') as source:
    data = source.read()
with open(output, 'wb') as raw:
    with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo('stoop')
            entry.size = len(data)
            entry.mode = 0o755
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ''
            entry.mtime = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
            archive.addfile(entry, io.BytesIO(data))
