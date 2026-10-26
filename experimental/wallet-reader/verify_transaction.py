"""Offline compiled-ARM transaction tests and host no-retry tests."""
import asyncio
from datetime import datetime
from verify import Device,select
from wallet_transaction import request,execute,decode_transaction

PARAMS=bytes.fromhex('26102611223344')
REQUEST=b'TXN\x01\xa5'+PARAMS
SELECT=bytes.fromhex('00a4040007a000000004101000')
GPO=bytes.fromhex('80a800000c830a0480a00000000000035600')
READ=bytes.fromhex('00b2011400')
CDOL=bytes.fromhex('9f02069f03069f1a0295055f2a029a039c019f37049f35019f3403')
CDOL_DATA=bytes.fromhex('0000000001000000000000000356800080800003562610260011223344223f0000')
GENERATE=b'\x80\xae\x80\x00'+bytes([len(CDOL_DATA)])+CDOL_DATA+b'\0'

def tlv(tag,value):
    tag=bytes.fromhex(tag)
    n=len(value);length=bytes([n]) if n<128 else b'\x81'+bytes([n]) if n<256 else b'\x82'+n.to_bytes(2,'big')
    return tag+length+value

FCI=tlv('6f',tlv('84',bytes.fromhex('a0000000041010'))+tlv('a5',tlv('9f38',bytes.fromhex('9f1d089f1a02'))))+b'\x90\0'
GPO_RESPONSE=tlv('77',tlv('82',b'\x19\x80')+tlv('94',b'\x10\x01\x01\0'))+b'\x90\0'
# Synthetic PAN sentinel must never be exported by transaction responses.
SENTINEL=bytes.fromhex('1234567890123456')
RECORD=tlv('70',tlv('5a',SENTINEL)+tlv('8c',CDOL)+tlv('9f46',b'\xab'*200))+b'\x90\0'
AC=bytes.fromhex('0102030405060708')
def ac_response(cid=0x80,template=0x77):
    if template==0x80:body=tlv('80',bytes([cid])+b'\x12\x34'+AC+b'\x01\x02')
    else:body=tlv('77',tlv('9f27',bytes([cid]))+tlv('9f36',b'\x12\x34')+tlv('9f26',AC)+tlv('9f10',b'\x01\x02'))
    return body+b'\x90\0'

def dialogue(pairs,fsc=64):
    frames=select(ats=bytes([2,{16:0,64:5}[fsc]]));bn=0
    for command,response in pairs:
        chunks=[command[i:i+fsc-3] for i in range(0,len(command),fsc-3)]
        for chunk in chunks[:-1]:
            frames.append((bytes([0x12|bn])+chunk,bytes([0xa2|bn])));bn^=1
        tx=bytes([2|bn])+chunks[-1]
        if response is None:frames.append((tx,None));break
        replies=[response[i:i+61] for i in range(0,len(response),61)]
        for chunk in replies[:-1]:
            frames.append((tx,bytes([0x12|bn])+chunk));bn^=1;tx=bytes([0xa2|bn])
        frames.append((tx,bytes([2|bn])+replies[-1]));bn^=1
    return frames

BASE=[(SELECT,FCI),(GPO,GPO_RESPONSE),(READ,RECORD)]
d=Device();assert d.command(b'\1')['status']==17 and not d.field
for payload in (b'TXN\1\xa5'+b'\xff'*7,b'TXN\1\xa5'+bytes.fromhex('26132611223344')):
    d=Device();assert d.command(payload)['status']==1 and not d.field
d=Device();d.u.mem_write(0x21cec,b'\1');assert d.command(REQUEST)['status']==2 and not d.field
for cid in (0,0x40,0x80):
    for template in (0x77,0x80):
        d=Device(dialogue(BASE+[(GENERATE,ac_response(cid,template))]))
        result=d.command(REQUEST)
        assert result['status']==0 and result['cryptogram_received']
        assert result['generate_ac_sent'] and result['apdu_count']==4 and result['records_read']==1
        assert result['cryptogram']==AC.hex() and result['application_transaction_counter']==0x1234
        assert result['cid']==f'{cid:02x}' and not result['payment_submitted']
        assert SENTINEL not in d.sent[-1]
        assert result['pdol']=='9f1d089f1a02' and result['cdol1']==CDOL.hex()
        assert result['zero_filled_unknown_dol_fields']==0
print('PASS: full single-session SELECT/GPO/READ/GENERATE AC; AAC, TC and ARQC; templates 77/80; no PAN export')
d=Device(dialogue(BASE+[(GENERATE,ac_response())],fsc=16));assert d.command(REQUEST)['status']==0
print('PASS: multi-APDU block numbering, 16-byte FSC transmit chaining, large record receive chaining')
for response,status in ((None,3),(b'\x69\x85',9),(tlv('77',tlv('9f26',AC))+b'\x90\0',6)):
    d=Device(dialogue(BASE+[(GENERATE,response)]));result=d.command(REQUEST)
    assert result['status']==status and result['generate_ac_sent'] and not result['cryptogram_received']
    assert result['status_word'] is None if response is None else True
print('PASS: lost/declined/malformed cryptogram response stops after exactly one GENERATE AC')
for response in (tlv('77',tlv('82',b'\0\0')+tlv('94',b'\x11\1\1\0'))+b'\x90\0',
                 tlv('77',tlv('82',b'\0\0')+tlv('94',b'\x10\1\x20\0'))+b'\x90\0',b'\x69\x85'):
    d=Device(dialogue([(SELECT,FCI),(GPO,response)]));r=d.command(REQUEST)
    assert r['status']!=0 and r['gpo_sent'] and not r['generate_ac_sent']
d=Device(dialogue([(SELECT,FCI),(GPO,GPO_RESPONSE),(READ,tlv('70',tlv('50',b'TEST'))+b'\x90\0')]))
assert d.command(REQUEST)['status']==10
print('PASS: invalid/oversized AFL, GPO refusal and missing CDOL stop before GENERATE AC')
# A card producing its cryptogram during GPO must not receive GENERATE AC.
d=Device(dialogue([(SELECT,FCI),(GPO,ac_response())]));r=d.command(REQUEST)
assert r['cryptogram_received'] and not r['generate_ac_sent']
# Format-1 GPO and DOL unknown-field zero filling.
gpo1=tlv('80',b'\x19\x80\x10\1\1\0')+b'\x90\0'
cdol2=CDOL+bytes.fromhex('df0102')
gen2=b'\x80\xae\x80\0'+bytes([len(CDOL_DATA)+2])+CDOL_DATA+b'\0\0\0'
d=Device(dialogue([(SELECT,FCI),(GPO,gpo1),(READ,tlv('70',tlv('8c',cdol2))+b'\x90\0'),(gen2,ac_response())]))
r=d.command(REQUEST);assert r['status']==0 and r['zero_filled_unknown_dol_fields']==1
print('PASS: GPO cryptogram early stop, GPO template 80, unknown DOL fields reported')

# Exact PDOL/CDOL1 and six-record AFL observed on the user's card, with
# synthetic record bodies and cryptogram. GAC is longer than one FIFO frame.
actual_cdol=bytes.fromhex('9f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f1d089f15029f4e14')
actual_data=CDOL_DATA[:-3]+bytes(10)+bytes.fromhex('3f00000480a00000000000')+bytes(22)
actual_gen=b'\x80\xae\x80\0'+bytes([len(actual_data)])+actual_data+b'\0'
afl=bytes.fromhex('0801010010010501')
actual_pairs=[(SELECT,FCI),(GPO,tlv('77',tlv('82',b'\x1b\x80')+tlv('94',afl))+b'\x90\0')]
for sfi,rec in [(1,1),(2,1),(2,2),(2,3),(2,4),(2,5)]:
    body=tlv('8c',actual_cdol) if (sfi,rec)==(2,1) else tlv('50',b'TEST')
    actual_pairs.append((bytes([0,0xb2,rec,(sfi<<3)|4,0]),tlv('70',body)+b'\x90\0'))
actual_pairs.append((actual_gen,ac_response()))
d=Device(dialogue(actual_pairs));r=d.command(REQUEST)
assert r['status']==0 and r['apdu_count']==9 and r['records_read']==6
assert r['zero_filled_unknown_dol_fields']==4 and r['frame_diagnostics']['reason']==0
# Regression: the previous wrong-number ACK must not be accepted.
frames=dialogue(actual_pairs)
for i,(tx,rx) in enumerate(frames):
    if tx[0]&0xfe==0x12 and len(tx)>40:
        frames=frames[:i]+[(tx,bytes([rx[0]^1]))];break
d=Device(frames);r=d.command(REQUEST)
assert r['status']==6 and r['frame_diagnostics']['reason']==2 and r['generate_ac_sent']
print('PASS: observed six-record/73-byte CDOL transaction, correct PICC ACK numbering and wrong-ACK diagnostic')

def wire(status=0,stage=8,flags=7):
    b=bytearray(190);b[:3]=b'WT\1';b[3:7]=bytes([status,stage,0,flags]);return bytes(b)
class FakeConnection:
    def __init__(self,replies):self.replies=list(replies);self.calls=0
    async def command(self,*a,**kw):
        self.calls+=1;r=self.replies.pop(0)
        if isinstance(r,BaseException):raise r
        return r
async def client_tests():
    for reply in (wire(),wire(9,6,1),wire(3,8,3),wire(6,5,0)):
        c=FakeConnection([reply]);log=[];await execute(c,REQUEST,2,log.append);assert c.calls==1
    c=FakeConnection([TimeoutError('lost reply')]);log=[]
    try:await execute(c,REQUEST,2,log.append)
    except TimeoutError:pass
    else:raise AssertionError('Timeout not propagated')
    assert c.calls==1 and 'unknown' in log[-1]['outcome']
    c=FakeConnection([wire(3,1,0),wire()]);log=[];await execute(c,REQUEST,2,log.append);assert c.calls==2
asyncio.run(client_tests())
assert request(datetime(2026,10,26),bytes.fromhex('11223344'))==REQUEST
print('PASS: host never retries GPO/GENERATE AC or ambiguous transport failures; only pre-application discovery is retried')
print('LIMIT: cryptograms are parsed, not cryptographically verified; peripheral and Wallet behavior require hardware testing.')
