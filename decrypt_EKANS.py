import re
import sys
import pefile
import struct
import binascii


data = open(sys.argv[1], 'rb').read()

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
memdata = pe.get_memory_mapped_image()


'''
.text:0054E4AA 8D 05 5B 8C 60 00                       lea     eax, unk_608C5B
.text:0054E4B0 89 44 24 04                             mov     [esp+210h+var_20C], eax
.text:0054E4B4 C7 44 24 08 AA 01 00 00                 mov     [esp+210h+var_208], 1AAh
.text:0054E4BC E8 2F 9D EE FF                          call    runtime_stringtoslicebyte
.text:0054E4C1 8B 44 24 0C                             mov     eax, [esp+210h+var_204]
.text:0054E4C5 89 84 24 0C 02 00 00                    mov     [esp+210h+var_4], eax
.text:0054E4CC 8B 4C 24 10                             mov     ecx, [esp+210h+var_200]
.text:0054E4D0 89 4C 24 18                             mov     [esp+210h+var_1F8], ecx
.text:0054E4D4 8D 54 24 1E                             lea     edx, [esp+210h+var_1F2]
.text:0054E4D8 89 14 24                                mov     [esp+210h+var_210], edx
.text:0054E4DB 8D 15 05 8E 60 00                       lea     edx, byte_608E05
.text:0054E4E1 89 54 24 04                             mov     [esp+210h+var_20C], edx
.text:0054E4E5 C7 44 24 08 AA 01 00 00                 mov     [esp+210h+var_208], 1AAh
.text:0054E4ED E8 FE 9C EE FF                          call    runtime_stringtoslicebyte
'''

#t = re.findall('''8d05......0089442404c7442408......00e8....eeff8b44240c.{34,70}89542404c7442408......00e8''', binascii.hexlify(data))


'''
.text:005623FA 8D 05 39 65 62 00                       lea     eax, unk_626539
.text:00562400 89 44 24 04                             mov     [esp+210h+var_20C], eax
.text:00562404 C7 44 24 08 AA 01 00 00                 mov     [esp+210h+var_208], 1AAh
.text:0056240C E8 2F 85 ED FF                          call    runtime_stringtoslicebyte
.text:00562411 8B 44 24 0C                             mov     eax, [esp+210h+var_204]
.text:00562415 89 84 24 0C 02 00 00                    mov     [esp+210h+var_4], eax
.text:0056241C 8B 4C 24 10                             mov     ecx, [esp+210h+var_200]
.text:00562420 89 4C 24 18                             mov     [esp+210h+size], ecx
.text:00562424 8D 54 24 1E                             lea     edx, [esp+210h+var_1F2]
.text:00562428 89 14 24                                mov     [esp+210h+var_210], edx
.text:0056242B 8D 15 E3 66 62 00                       lea     edx, unk_6266E3
.text:00562431 89 54 24 04                             mov     [esp+210h+var_20C], edx
.text:00562435 C7 44 24 08 AA 01 00 00                 mov     [esp+210h+var_208], 1AAh
.text:0056243D E8 FE 84 ED FF                          call    runtime_stringtoslicebyte
'''
t = re.findall('''8d05......0089442404c7442408......00e8......ff8b44240c.{34,70}89542404c7442408......00e8''', binascii.hexlify(data))
#t = re.findall('''8d05......0089442404c7442408......00e8....e.ff8b44240c.{34,70}89542404c7442408......00e8''', str(binascii.hexlify(data))) 


all = []
 
for val in t:
    #print val
    off1 = struct.unpack_from('<I', binascii.unhexlify(val)[2:])[0] - base
    l = struct.unpack_from('<I', binascii.unhexlify(val)[14:])[0]
    off2 = struct.unpack_from('<I', binascii.unhexlify(val)[-17:])[0] - base
    d1 = bytearray(memdata[off1:off1+l])
    d2 = bytearray(memdata[off2:off2+l])

    for i in range(len(d1)):
        d1[i] = (d1[i] + 0x2a) & 0xff
        d1[i] ^= d2[i]
    all.append(str(d1))
    #print(d1)
    print(hex(base + off1) + ' ' + d1)
