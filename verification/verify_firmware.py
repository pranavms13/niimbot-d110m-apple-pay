"""Execute a small, explicit Thumb subset against the actual firmware bytes.
For the pure decompressor/TEA/CRC functions only; no peripherals or NFC device.
"""
import sys, struct, random, zlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM
from niimbot_tag import encrypt, decrypt, counter_block, KEY
from decompress import decompress_initializer

BASE=0x1010000
ROOT=Path(__file__).resolve().parent.parent
FW=(ROOT/'firmware/D110_M_V4.31_original.bin').read_bytes()[28:]
class Thumb:
    def __init__(self, firmware=None):
        self.firmware = FW if firmware is None else firmware
        self.mem={};self.r={};self.z=False;self.n=False;self.c=False
        self.md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);self.md.detail=True
        self.cache={};self.hooks={}
    def read(self,a,n):
        if BASE <= a < BASE+len(self.firmware):
            data=self.firmware[a-BASE:a-BASE+n]
            return data+bytes(self.mem.get(a+i,0) for i in range(len(data),n))
        return bytes(self.mem.get(a+i,0) for i in range(n))
    def write(self,a,b):self.mem.update({a+i:v for i,v in enumerate(b)})
    def reg(self,name):return self.r.get(name,0)
    def put(self,name,v):self.r[name]=v&0xffffffff
    def val(self,o):
        if o.type==ARM_OP_IMM:return o.imm
        assert o.type==ARM_OP_REG
        name=self.md.reg_name(o.reg)
        return ((self.pc+4)&~3) if name=='pc' else self.reg(name)
    def addr(self,o):
        base=self.md.reg_name(o.mem.base)
        a=((self.pc+4)&~3) if base=='pc' else self.reg(base)
        return a+o.mem.disp+(self.reg(self.md.reg_name(o.mem.index)) if o.mem.index else 0)
    def call(self,off,*args):
        self.put('sp',0x6f000);self.put('lr',0x100001)
        for n,v in enumerate(args):self.put('r'+str(n),v)
        self.pc=BASE+off
        for step in range(200000):
            if self.pc==0x100000:return self.reg('r0')
            if self.pc not in self.cache:self.cache[self.pc]=next(self.md.disasm(self.read(self.pc,4),self.pc,count=1))
            i=self.cache[self.pc];ops=i.operands;m=i.mnemonic;nextpc=self.pc+i.size
            names=[self.md.reg_name(o.reg) if o.type==ARM_OP_REG else None for o in ops]
            if m=='push':
                sp=self.reg('sp')-4*len(ops)
                for n,name in enumerate(names):self.write(sp+4*n,struct.pack('<I',self.reg(name)))
                self.put('sp',sp)
            elif m=='pop':
                sp=self.reg('sp')
                for n,name in enumerate(names):
                    v=int.from_bytes(self.read(sp+4*n,4),'little')
                    if name=='pc':nextpc=v&~1
                    else:self.put(name,v)
                self.put('sp',sp+4*len(ops))
            elif m in ['ldr','ldrb','ldrh']:
                self.put(names[0],int.from_bytes(self.read(self.addr(ops[1]),{'ldr':4,'ldrb':1,'ldrh':2}[m]),'little'))
            elif m in ['str','strb','strh']:
                n={'str':4,'strb':1,'strh':2}[m]
                self.write(self.addr(ops[1]),self.val(ops[0]).to_bytes(4,'little')[:n])
            elif m=='bl':
                target=self.val(ops[0])
                if target in self.hooks:self.hooks[target](self)
                else:
                    self.put('lr',nextpc|1);nextpc=target
            elif m in ['b','bne','beq','bpl','bmi','blo','bhs','bls','bhi','bx']:
                condition={'b':True,'bne':not self.z,'beq':self.z,'bpl':not self.n,'bmi':self.n,'blo':not self.c,'bhs':self.c,'bls':not self.c or self.z,'bhi':self.c and not self.z,'bx':True}[m]
                if condition:nextpc=self.val(ops[0])&~1
            else:
                a=self.val(ops[0 if len(ops)==2 else 1]);b=self.val(ops[-1]);v=None
                if m in ['mov','movs']:v=b
                elif m=='cmp':
                    self.c=a>=b;v=a-b
                elif m in ['adds','add']:v=a+b;self.c=v>0xffffffff
                elif m in ['subs','sub']:v=a-b;self.c=a>=b
                elif m=='eors':v=a^b
                elif m=='orrs':v=a|b
                elif m=='bics':v=a&~b
                elif m=='muls':v=a*b
                elif m=='uxtb':v=b&255
                elif m=='uxth':v=b&65535
                elif m=='mvns':v=(~b)
                elif m in ['lsls','lsrs','asrs']:
                    if m=='lsls':v=a<<b
                    elif m=='lsrs':v=a>>b
                    else:v=(a if a<0x80000000 else a-0x100000000)>>b
                else:raise NotImplementedError(f'{i.address:x}: {m} {i.op_str}')
                v &= 0xffffffff
                if m=='cmp' or m.endswith('s'):self.z=v==0;self.n=bool(v&0x80000000)
                if m!='cmp':self.put(names[0],v)
            self.pc=nextpc
        raise RuntimeError('instruction limit')

def verify_original():
    vm=Thumb()
    vm.call(0x139e,BASE+0x1c43c,0x20004,0x7a8)
    assert vm.read(0x20004,0x7a8)==decompress_initializer(FW)
    assert struct.unpack('<4I',vm.read(0x20788,16))==KEY
    rng=random.Random(110)
    for n in range(100):
        plain=bytes(rng.randrange(256) for _ in range(8))
        vm.write(0x60000,plain)
        vm.call(0x7f18,0x60000,0x60100)
        cipher=vm.read(0x60100,8)
        assert cipher==encrypt(plain)
        vm.call(0x7eb8,0x60100,0x60200)
        assert vm.read(0x60200,8)==plain==decrypt(cipher)
        crc=vm.call(0xb76c,0x60000,4)
        assert crc==zlib.crc32(plain[:4])
    print('PASS: decompressed RAM/key independently match firmware instructions.')
    print('PASS: 100 deterministic blocks match firmware TEA encryption/decryption and CRC32.')
    print('Zero-used, zero-reserved ciphertext:', counter_block(0,0).hex(' '))

    # Run the firmware history lookup on a synthetic previously seen exhausted roll.
    vm.hooks[BASE+0x204]=lambda t:t.put('r0', int(t.read(t.reg('r0'),t.reg('r2'))!=t.read(t.reg('r1'),t.reg('r2'))))
    vm.hooks[BASE+0xe13c]=lambda t:None  # hardware-independent error logger stub
    vm.write(0x482fc+0x14,bytes.fromhex('8804112233445566'))
    vm.write(0x20928+4,bytes.fromhex('8804112233445566'))
    vm.write(0x20928+14,struct.pack('<H',200))
    vm.write(0x482fc+14,struct.pack('<H',0))
    vm.write(0x482fc+0x4e,struct.pack('<H',150))
    vm.call(0x14d74,0)
    assert int.from_bytes(vm.read(0x482fc+14,2),'little')==200
    assert int.from_bytes(vm.read(0x207d0+0x14,4),'little') & (1<<19)
    print('PASS: firmware history lookup restores reset count 0 to cached 200 and flags exhausted at limit 150.')
    # Exercise the actual 0x28 handler; stub flash save and transport, inspect cache.
    cache=vm.read(0x20928,0xf4)
    vm.hooks[BASE+0x12e20]=lambda t:None
    vm.hooks[BASE+0x4e18]=lambda t:None
    vm.call(0x7374,0,0,0)
    assert vm.read(0x20928,0xf4)==cache
    print('PASS: firmware command 0x28 leaves the 244-byte roll history region unchanged.')

    # Exhaust every one-byte history selector; neither valid pages nor invalid
    # selectors constitute a hidden clear command. Transport/memcpy are stubbed.
    vm.hooks[BASE+0x150]=lambda t:t.write(t.reg('r0'),t.read(t.reg('r1'),t.reg('r2')))
    vm.write(0x20928,struct.pack('<I',20))
    cache=vm.read(0x20928,0xf4)
    for selector in range(256):
        vm.write(0x60005,bytes([selector]))
        vm.write(0x204c5,b'\x00')
        vm.call(0x3ca0,0x60000,0,0)
        assert vm.read(0x20928,0xf4)==cache, selector
    print('PASS: all 256 selectors of command 0x52 leave roll history unchanged.')

    # Settings-load recovery: use a synthetic flash record with a valid CRC, then
    # corrupt only that CRC. Execute the actual recovery and byte-zero routines.
    record=bytearray((i*17+9)&255 for i in range(0x13c))
    struct.pack_into('<I',record,0,zlib.crc32(record[4:]))
    vm.write(0x010ff000,record)
    vm.hooks[BASE+0xc664]=lambda t:t.write(t.reg('r1'),t.read(t.reg('r0'),t.reg('r2')))
    vm.call(0xd128,0x20900)
    assert vm.read(0x20928,0xf4)==record[0x28:0x11c]
    vm.write(0x010ff000,bytes([record[0]^1]))
    vm.call(0xd128,0x20900)
    assert vm.read(0x20928,0xf4)==bytes(0xf4)
    print('PASS: startup preserves history with valid settings CRC, clears it with invalid CRC.')

    # Confirm eviction after 20 different, accepted identities. This models the
    # history routine only, not tag authentication or availability of such tags.
    def divide(t):
        quotient,remainder=divmod(t.reg('r0'),t.reg('r1'))
        t.put('r0',quotient);t.put('r1',remainder)
    vm.hooks[BASE+0xfc]=divide
    vm.write(0x20928,bytes(0xf4))
    for identity in range(1,22):
        vm.write(0x48310,identity.to_bytes(8,'little'))
        vm.write(0x4830a,struct.pack('<H',0))
        vm.call(0x14d74,0)
    assert int.from_bytes(vm.read(0x20928,4),'little')==21
    assert all(vm.read(0x2092c+12*i,8)!=(1).to_bytes(8,'little') for i in range(20))
    print('PASS: 20 further distinct accepted identities evict the oldest of 20 history entries.')

    # Reproduce the reported six-count example independently of the synthetic exhausted
    # case: zero on tag, six in history, metadata limit 186 -> effective count six.
    vm.write(0x20928,bytes(0xf4))
    identity=bytes.fromhex('8804112233445566')
    vm.write(0x2092c,identity)
    vm.write(0x20936,struct.pack('<H',6))
    vm.write(0x48310,identity)
    vm.write(0x4830a,struct.pack('<H',0))
    vm.write(0x4834a,struct.pack('<H',186))
    vm.write(0x207e4,bytes(4))
    vm.call(0x14d74,0)
    assert vm.read(0x4830a,2)==struct.pack('<H',6)
    assert int.from_bytes(vm.read(0x207e4,4),'little')&(1<<19)==0
    print('PASS: synthetic identity with zero tag count and cached six produces effective count six.')


if __name__ == '__main__':
    verify_original()
