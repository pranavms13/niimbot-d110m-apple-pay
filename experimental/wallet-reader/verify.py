"""Execute candidate ARM instructions with a scripted NFC register/FIFO model.
No real Bluetooth, NFC, flash, bootloader, or Apple Wallet is exercised.
"""
from collections import deque
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'verification')]
from patch_firmware import BASE,encode_bl,validate_container
from decompress import decompress_initializer
from wallet_reader import decode,tlvs,MAGIC
from wallet_transaction import decode_transaction
OUT=ROOT/'build/wallet-transaction'
manifest=json.loads((OUT/'manifest.json').read_text())
image=(OUT/manifest['image']).read_bytes();FW=image[28:]
assert validate_container(image)==(431,2320)
prior=(OUT/'refill-base/D110_M_V4.31_refill-reset_EXPERIMENTAL.bin').read_bytes()[28:]
assert all(a==b or 0x4eee<=i<0x4ef2 for i,(a,b) in enumerate(zip(prior,FW)))
assert FW[0x4eee:0x4ef2]==encode_bl(BASE+0x4eee,manifest['dispatch'])
STOP=0x0100f000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
PPSE=bytes.fromhex('00a404000e325041592e5359532e444446303100')
FCI=bytes.fromhex('6f19840e325041592e5359532e4444463031a507bf0c04610250009000')

class Device:
    def __init__(self, exchanges=()):
        self.u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
        for address,size in [(0x20000,0x50000),(STOP,0x1000),(BASE,0x20000)]:self.u.mem_map(address,size)
        self.u.mem_write(BASE,FW);self.u.mem_write(0x20004,decompress_initializer(FW))
        self.u.mem_write(0x207d0,b'\x02');self.u.mem_write(0x203a4,b'\x07')
        self.script=deque(exchanges);self.tx=[];self.rx=deque();self.registers={};self.frames=[]
        self.field=[];self.clock=0;self.sent=[];self.lowest_sp=0x6f000;self.crcs=[0,0];self.feeds=0
        self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
    def arg(self,n):return self.u.reg_read(REGS[n])
    def ret(self,v=0):
        self.u.reg_write(UC_ARM_REG_R0,v);self.u.reg_write(UC_ARM_REG_PC,self.u.reg_read(UC_ARM_REG_LR))
    def write(self,u,access,address,size,value,_):
        assert (0x6e000<=address<0x6f000 or 0x60100<=address<0x60201 or 0x207d4<=address<0x207d8),hex(address)
    def code(self,u,address,size,_):
        self.lowest_sp=min(self.lowest_sp,u.reg_read(UC_ARM_REG_SP))
        if address==STOP:u.emu_stop();return
        off=address-BASE
        if off==0x7252:self.field.append(self.arg(1));self.ret()
        elif off in (0x7324,0x72a0):self.crcs[off==0x72a0]=self.arg(1);self.ret()
        elif off==0x72b8:assert 1<=self.arg(1)<=1000;self.ret()
        elif off==0x7214:
            reg,value=self.arg(1),self.arg(2)
            if reg==0xa and value==0x80:self.tx=[];self.rx.clear()
            elif reg==9:self.tx.append(value)
            elif reg==0xd and value&0x80:
                assert self.script,'Unexpected RF transmission'
                expected,response,*opts=self.script.popleft()
                assert bytes(self.tx)==expected,(bytes(self.tx).hex(),expected.hex())
                assert self.crcs==([0,0] if expected in (b'\x52',b'\x93\x20',b'\x95\x20',b'\x97\x20') else [1,1])
                assert value&7==(7 if expected==b'\x52' else 0)
                self.frames.append(bytes(self.tx));self.rx=deque(response or b'')
                self.registers[4]=opts[0] if opts else (0x20 if response is not None else 1)
                self.registers[0xa]=len(self.rx);self.registers[6]=8
            elif reg!=4:self.registers[reg]=value
            self.ret()
        elif off==0x3c60:
            reg=self.arg(1)
            value=self.rx.popleft() if reg==9 else self.registers.get(reg,0)
            u.mem_write(self.arg(2),bytes([value]));self.ret()
        elif off==0x2100:self.feeds+=1;self.ret()
        elif off==0x78c8:self.clock+=1;self.ret(self.clock)
        elif off==0x78d4:self.clock+=1;self.ret(int(self.clock-self.arg(0)>=self.arg(1)))
        elif off==0x4dc4:
            self.sent.append(bytes(u.mem_read(self.arg(0),self.arg(1))));self.ret()
        elif off in (0x533c,0x539c,0x541c,0x556a,0xc6f0,0x118ac,0xc678,0x12e20):
            raise AssertionError(f'Forbidden tag authentication/write or persistence call: {off:x}')
    def command(self,payload=MAGIC,cmd=0xf2):
        self.u.mem_write(0x60000,bytes([0,0,0,cmd,len(payload)])+payload)
        self.u.mem_write(0x60100,b'\xcc'*256);self.u.mem_write(0x60200,b'\x00')
        for reg,value in zip(REGS,[0x60000,0x60100,0x60200,2]):self.u.reg_write(reg,value)
        self.u.reg_write(UC_ARM_REG_SP,0x6f000);self.u.reg_write(UC_ARM_REG_LR,STOP|1)
        self.u.emu_start((BASE+0x4ec0)|1,STOP,count=2000000)
        assert self.u.reg_read(UC_ARM_REG_PC)==STOP,'Did not return'
        assert self.u.reg_read(UC_ARM_REG_SP)==0x6f000
        assert self.lowest_sp>0x6e800,'Stack exceeds 2 KiB'
        assert self.sent and not self.script
        frame=self.sent[-1];check=0
        for b in frame[2:-3]:check^=b
        assert frame[:2]==b'UU' and frame[-2:]==b'\xaa\xaa' and check==frame[-3]
        assert len(frame)==frame[3]+7<=241
        assert bytes(self.u.mem_read(0x60100+241,15))==b'\xcc'*15
        if self.frames:assert self.field==[0,3,0]
        if cmd!=0xf2:return frame
        return decode_transaction(frame[4:-3]) if frame[4:6]==b'WT' else decode(frame[4:-3])

def select(uid=b'\x01\x02\x03\x04',sak=0x20,ats=b'\x02\x05'):
    steps=[(b'\x52',b'\x04\x00')]
    blocks=[uid] if len(uid)==4 else [b'\x88'+uid[:3],uid[3:]]
    for level,block in enumerate(blocks):
        bcc=0
        for b in block:bcc^=b
        response=block+bytes([bcc]);cascade=0x93+level*2
        steps.extend([(bytes([cascade,0x20]),response),(bytes([cascade,0x70])+response,bytes([4 if level+1<len(blocks) else sak]))])
    if sak&0x20:steps.append((b'\xe0\x50',ats))
    return steps

d=Device();assert d.command(b'\0')['status']==16 and not d.field
for payload in (b'',b'WALLET',MAGIC+b'1',MAGIC+b'x'*17):
    d=Device();assert d.command(payload)['status']==1 and not d.field
d=Device();d.u.mem_write(0x21cf1,b'\x01');assert d.command()['status']==2 and not d.field
d=Device();assert d.command(b'\0',0xf0)==bytes.fromhex('5555f10452460110f0aaaa')
print('PASS: capability, malformed/busy requests, prior refill protocol, output bounds')
for flag in (1,0):
    d=Device([(b'\x52',None,flag)]);r=d.command();assert r['status']==3 and r['stage']=='WUPA'
d=Device([(b'\x52',None,2)]);assert d.command()['hardware_error']=='08'
d=Device(select(sak=0));assert d.command()['status']==4
d=Device(select(ats=b'\x03\x05'));assert d.command()['status']==6
print('PASS: hardware/software timeout, collision, non-ISO-DEP tag, malformed ATS; field cleanup')
for uid in (bytes.fromhex('01020304'),bytes.fromhex('01020304050607')):
    d=Device(select(uid)+[(b'\x02'+PPSE,b'\x02'+FCI)])
    r=d.command();assert r['select_succeeded'] and r['uid']==uid.hex() and 'parse_error' not in r
d=Device(select()+[(b'\x02'+PPSE,b'\xf2\x02'),(b'\xf2\x02',b'\x02\x90\x00')])
assert d.command()['select_succeeded']
print('PASS: 4/7-byte UIDs, PPSE SELECT, ATS, WTX, status-word and TLV parsing')
d=Device(select(ats=b'\x02\x00')+[(b'\x12'+PPSE[:13],b'\xa2'),(b'\x03'+PPSE[13:],b'\x03\x90\x00')])
assert d.command()['select_succeeded']
d=Device(select()+[(b'\x02'+PPSE,b'\x12'+FCI[:10]),(b'\xa3',b'\x03'+FCI[10:])])
assert d.command()['select_succeeded']
aid=bytes.fromhex('a0000000031010');apdu=b'\x00\xa4\x04\x00'+bytes([len(aid)])+aid+b'\0'
d=Device(select()+[(b'\x02'+apdu,b'\x02\x6a\x82')]);r=d.command(MAGIC+aid)
assert r['status_word']=='6a82' and not r['select_succeeded']
print('PASS: command and response chaining, explicit AID, unsuccessful SELECT status')
d=Device(select()+[(b'\x02'+PPSE,b'\x03\x90\x00')]);assert d.command()['status']==6
d=Device(select()+[(b'\x02'+PPSE,b'\x12'+b'x'*61),(b'\xa3',b'\x13'+b'x'*61),(b'\xa2',b'\x02'+b'x'*61)])
assert d.command()['status']==7
d=Device(select(ats=b'\x03\x25\xb0')+[(b'\x02'+PPSE,b'\xf2\x02')]);assert d.command()['status']==8
for raw in (b'\x6f\x80',b'\x6f\x04\x01',b'\x9f',b'\x50\x82\x01'):
    try:tlvs(raw)
    except ValueError:pass
    else:raise AssertionError('Accepted malformed TLV')
print('PASS: wrong block number, overflow, excessive WTX, malformed TLV rejection')
print('LIMIT: RF timing, reader CRC stripping, iPhone behavior, Bluetooth and physical boot remain hardware tests.')
