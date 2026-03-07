# botguard - recaptcha disassembler

it's missing the token generation part this could be easily added but i didn't make this repo to provide an easy solution
for botguard, but rather a learning resource for those who are interested in reverse engineering it.

## short description of how the VM works

### loading
so it all starts in anchor.html where you can find the bg init call function which then loads the script (b64 encoded)
and bytecode (double b64 encoded). the vm has many anti-tampering techniques such as time-based check for anti-debugging
or integrity check within the values inside of registers.

### behaviour inside of the VM
inside of the VM at the beginning they load a string table (with NEW_ARRAY op) that's then used for loading strings.
in this version of botguard there are 3 opcodes which are dynamically loaded inside of the vm like this:
```
000005e4: LOAD_STRING        r63 = ""
000005fc: LOAD_IMM_32        r32 = 133120
0000062e: LOAD_STRING        r101 = "0,function(f){l2(f,1)}"
0000073e: NEW_OPCODE_EVAL    r49 = LoadImm8
00000758: SET_PROP           r49[r63] = r32
0000077a: LOAD_STRING        r118 = "0,function(f,w,W){q(f,(W=(w=(W=O(f),O(f)),f).G[W]&&h(W,f),w),W)}"
00000a1a: NEW_OPCODE_EVAL    r78 = Mov
00000a34: SET_PROP           r78[r63] = r32
00000a56: LOAD_STRING        r102 = "0,function(f){l2(f,2)}"
00000b66: NEW_OPCODE_EVAL    r51 = LoadImm16
00000b80: SET_PROP           r51[r63] = r32
00000ba2: LOAD_IMM_8         r87 = 1
00000bba: LOAD_IMM_8         r5 = 2
00000bd2: LOAD_IMM_8         r26 = 16
00000bea: LOAD_STRING        r118 = "B"
00000c12: LOAD_IMM_16        r74 = 628
00000c32: LOAD_IMM_32        r39 = 92748592
00000c64: SET_PROP           r450[r87] = r39
00000c88: LOAD_IMM_32        r95 = 2013947675
00000cba: SET_PROP           r450[r5] = r95
00000cfe: JUMP               12956
0000335e: JNZ                r42, r384
0000337a: REMOVE_EVENT       r349
000033b8: JNZ                r453, r53
00003424: JNZ                r455, r19
00003460: USHR               r38 = r188 >>> 92
000035d0: NOP               
0000363e: IN                 r271 = r85 in r48
00003688: CMP_EQ             r79 = (r444 == r203)
00003726: NEW_ARRAY          r92, [51 bytes]
00003992: MOV                r32 = r164
00003ac6: LOAD_IMM_16        r233 = 8462
00003bd8: INT_TO_BYTES_8     r107 -> r44
00003c14: REMOVE_EVENT       r98
00003c78: UTF8_ENCODE3       r484 -> r471
00003cbe: TYPEOF             r399 -> r448
00003e3e: JNZ                r374, r53
00003f5e: LOAD_IMM_16        r95 = 32055
00003fa2: ADD                r30 += r169
```
as you can tell other disassembled instructions are total bullshit, values that have never been created are being referenced or 
straight up non-sense jumps etc. it's all because of the token generation process. this VM isn't made to actually perform some
kind of checks or generate the token with opcodes, it's to verify the flow of the execution of the instructions. the token is 
built with emitting errors, utf8encode writes and int2bytes writes. each unkown register, opcode and operation gets written
to the token output. you may ask the question why's the bytecode so long but the disassembler only finds 40 instructions
is it broken? the answer is no, 90% of the opcodes that are being read are invalid for the token generation purposes.

## usage
if you can't figure out how to run it then you shouldn't be trying to finish this code.
TIP: script should be flattened with the flatten binary.

## contact me
xBBFF@proton.me
