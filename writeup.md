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

heres the state of the heap after these 3 allocations ; also pay mind to the data of chunk 1, ill explain its significance in a minute.

![step_1](https://github.com/kaslr/another_null_chal/blob/main/step_1.PNG)