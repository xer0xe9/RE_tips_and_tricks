apis = ["GetModuleFileNameW", "ExitProcess", "CreateProcessW", "GetThreadContext", "ReadProcessMemory", "CloseHandle", "Wow64SetThreadContext", "GetCommandLineW", "TerminateProcess"]

for api in apis:
    seed = 0x2326
    for c in api:
       shr = seed >> 1
       shl = seed << 7
       bitwiseor = shr|shl
       add_char = bitwiseor + ord(c)
       new_seed = add_char+seed
       seed = new_seed
    hash = hex(seed)
    hash = hash[:-1]
    hash =  hash[-8:]
    print hash