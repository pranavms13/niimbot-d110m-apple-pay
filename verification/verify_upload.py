"""Exercise the stock application's update receiver with virtual staging flash.

Uses the same 200-byte chunk size as NiimBlue. Does not simulate the bootloader
or send anything to a real printer. Flash I/O and its CRC read are substituted.
"""
import struct
import argparse
from pathlib import Path
from zlib import crc32
from verify_firmware import Thumb, BASE

ROOT=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image', type=Path, default=ROOT/'firmware/D110_M_V4.31_history-reset.bin')
image=parser.parse_args().image.read_bytes()
STAGING=0x01060000

def receiver():
    vm=Thumb();vm.writes=[];vm.responses=[]
    vm.write(0x204f4,struct.pack('<I',STAGING))
    vm.hooks[BASE+0x150]=lambda t:t.write(t.reg('r0'),t.read(t.reg('r1'),t.reg('r2')))
    vm.hooks[BASE+0x9624]=lambda t:t.responses.append(t.read(t.reg('r0'),6))
    def flash(t):
        address,size=t.reg('r0'),t.reg('r2')
        assert STAGING<=address and address+size<=STAGING+0x20000
        t.writes.append((address,size))
        t.write(address,t.read(t.reg('r1'),size));t.put('r0',1)
    vm.hooks[BASE+0xf28c]=flash
    # Device flash CRC helper is replaced by CRC32 of virtual flash; the
    # receiver's comparison with the header CRC is executed unchanged.
    vm.hooks[BASE+0xf200]=lambda t:t.put('r0',crc32(t.read(t.reg('r0'),t.reg('r1'))))
    vm.hooks[BASE+0x12e20]=lambda t:None  # separate settings persistence
    vm.hooks[BASE+0x12d8c]=lambda t:None  # log persistence
    vm.hooks[BASE+0xe13c]=lambda t:None
    return vm

def chunk(vm,sequence,data):
    vm.write(0x60000,struct.pack('<HBBB',sequence,0,0x9b,len(data))+data)
    assert vm.call(0x1b30,0x60000,0x60100,0x60200)==1

vm=receiver()
for sequence,offset in enumerate(range(0,len(image),200)):
    chunk(vm,sequence,image[offset:offset+200])
    assert vm.read(0x46b7d,1)==b'\x00'  # no rejection flag
    assert vm.responses[-1]==struct.pack('<HBBBB',sequence+1,0,0x9a,1,1)
# Command 0x9c flushes any remaining payload in a full 256-byte final page,
# checks the declared payload CRC, and replies 0x9d success before commit.
assert vm.call(0x1ec0,0x60000,0x60100,0x60200)==1
assert vm.responses[-1]==bytes.fromhex('0000009d0101')
assert vm.read(0x46b7c,1)==b'\x02'
assert vm.read(STAGING,len(image)-28)==image[28:]
assert len(vm.writes)==(len(image)-28+255)//256
print(f'PASS: {sequence+1} chunks plus finish stage the exact patched payload, including wrapper.')
print('PASS: stock receiver returns 0x9d success and update state 2 after payload CRC comparison.')

def header_with_version(version):
    result=bytearray(image)
    struct.pack_into('<H',result,20,version)
    normalized=bytearray(result[:24]);normalized[1:4]=bytes(3)
    struct.pack_into('<I',result,24,crc32(normalized))
    return bytes(result)

for version,accepted in [(430,False),(431,True),(432,True)]:
    v=receiver();chunk(v,0,header_with_version(version)[:200])
    assert (v.read(0x46b7d,1)==b'\x00')==accepted
print('PASS: first-chunk version check rejects 4.30, accepts 4.31 and 4.32.')
bad=bytearray(image);bad[24]^=1
v=receiver();chunk(v,0,bad[:200])
assert v.read(0x46b7d,1)==b'\x01'
print('PASS: damaged header CRC raises the stock rejection flag.')
print('LIMIT: outer transport CRC, radio, physical flash, commit worker and bootloader are not emulated.')
