import pefile
import glob
import json
import zlib

export_crc32 = {}
out = 'exports.json'

dlls = glob.glob("dlls/*.dll")
EXPORTS = []

for dll in dlls:
   pe = pefile.PE(dll)
   ee = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name is not None]
   EXPORTS += ee

for e in EXPORTS:
    checksum = hex(zlib.crc32(e) % (1<<32))
    export_crc32[checksum] = e

json.dump(export_crc32,open(out,'w'))