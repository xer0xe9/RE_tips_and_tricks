import pefile
import glob
import json

export_hash = {}
out = 'danabot_exports.json'

dlls = glob.glob("dlls/*.dll")
EXPORTS = []


def compute_API_Hash(api_name):
    apihash = 0
    elen = len(api_name)
    for i1 in range(1, len(api_name)+1):
    	i2 = elen - i1
        if elen == i1:
            i2 = 1

        chr1 = ord(api_name[i1-1])
        chr1 ^= elen
        chr1_caps = ord(api_name[i1-1].upper())
        chr1_caps ^= elen

        chr2 = ord(api_name[i2-1])
        chr2 ^= elen
        chr2_caps = ord(api_name[i2-1].upper())

        imul = chr1 * chr1_caps * chr2
        apihash += imul
        apihash ^= chr2_caps
        apihash ^= elen
        apihash &= 0xffffffff
    return apihash

if __name__ == "__main__":

    for dll in dlls:
        pe = pefile.PE(dll)
        ee = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name is not None]
        EXPORTS += ee
    # print EXPORTS

    for e in EXPORTS:
        ehash = hex(compute_API_Hash(e))
        export_hash[ehash] = e

    json.dump(export_hash,open(out,'w'))

    # e = "VirtualProtect"
    # print hex(compute_API_Hash(e))
