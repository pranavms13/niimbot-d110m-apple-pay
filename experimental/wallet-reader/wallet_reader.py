#!/usr/bin/env python3
"""Read SELECT metadata from a personally presented contactless card. Never flashes."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'refill-reset'))
from bluetooth_refill import Connection

MAGIC=b'WALLET\x01\xa5'
STATUS={0:'SELECT response received',1:'Malformed request',2:'Printer busy',
        3:'No response / timeout',4:'Selected tag does not support ISO-DEP',
        5:'NFC hardware error / collision',6:'Malformed or unsupported frame',
        7:'Response exceeds 180-byte PoC limit',8:'Timing / frame budget unsupported',
        16:'Wallet reader protocol v1 installed'}
STAGE={0:'idle',1:'WUPA',2:'anticollision',3:'card selection',4:'RATS / ATS',5:'SELECT APDU'}
LABELS={0x4f:'application_id',0x50:'application_label',0x84:'df_name',
        0x87:'application_priority',0x9f12:'application_preferred_name',0x9f38:'PDOL'}

def tlvs(data,depth=0):
    if depth>10: raise ValueError('TLV nesting exceeds limit')
    out=[]; i=0
    while i<len(data):
        first=data[i];tag=first;i+=1
        if first in (0,255): continue
        if first&31==31:
            for count in range(3):
                if i>=len(data): raise ValueError('Truncated TLV tag')
                b=data[i];i+=1;tag=(tag<<8)|b
                if not b&128: break
            else: raise ValueError('TLV tag too long')
        if i>=len(data): raise ValueError('Missing TLV length')
        n=data[i];i+=1
        if n&128:
            k=n&127
            if not 1<=k<=2 or i+k>len(data): raise ValueError('Unsupported TLV length')
            n=int.from_bytes(data[i:i+k],'big');i+=k
        if i+n>len(data): raise ValueError('Truncated TLV value')
        value=data[i:i+n];i+=n
        item={'tag':f'{tag:X}','hex':value.hex()}
        if tag in LABELS: item['name']=LABELS[tag]
        if tag in (0x50,0x9f12): item['text']=value.decode('ascii',errors='replace')
        if first&32: item['children']=tlvs(value,depth+1)
        out.append(item)
    return out

def flatten(items):
    for item in items:
        yield item
        yield from flatten(item.get('children',[]))

def decode(data):
    if len(data)<54 or data[:3]!=b'WA\x01': raise ValueError('Not a Wallet protocol v1 reply')
    status,stage,error=data[3:6]; uidn=data[9];atsn=data[20];apdun=data[53]
    if uidn>10 or atsn>32 or apdun>180 or len(data)!=54+apdun:
        raise ValueError('Invalid response lengths')
    result={'status':status,'message':STATUS.get(status,'Unknown status'),
            'stage':STAGE.get(stage,str(stage)),'hardware_error':f'{error:02x}',
            'atqa':data[6:8].hex(),'sak':f'{data[8]:02x}',
            'uid':data[10:10+uidn].hex(),'ats':data[21:21+atsn].hex(),
            'response_hex':data[54:].hex(),'select_succeeded':False}
    if status==0:
        if apdun<2: raise ValueError('Missing APDU status word')
        response=data[54:]; result['status_word']=response[-2:].hex()
        result['select_succeeded']=response[-2:]==b'\x90\x00'
        if response[:-2]:
            try:
                result['tlv']=tlvs(response[:-2])
                result['applications']=[i['hex'] for i in flatten(result['tlv']) if i['tag']=='4F']
                result['labels']=[i['text'] for i in flatten(result['tlv']) if 'text' in i]
            except ValueError as exc: result['parse_error']=str(exc)
    return result

def aid_value(s):
    try: value=bytes.fromhex(s)
    except ValueError as exc: raise argparse.ArgumentTypeError('AID must be hex') from exc
    if not 5<=len(value)<=16: raise argparse.ArgumentTypeError('AID must be 5–16 bytes')
    return value

async def run(args):
    from bleak import BleakScanner
    if args.mode=='scan':
        for d in await BleakScanner.discover(timeout=10):
            if (d.name or '').startswith('D110_M'): print(d.address,d.name)
        return
    if not args.address: raise ValueError('--address is required')
    device=await BleakScanner.find_device_by_address(args.address,timeout=10)
    if device is None: raise RuntimeError('Printer not advertising; disconnect NIIMBOT app')
    async with Connection(device) as c:
        for selector,expected in [(8,b'\x09\x10'),(9,b'\x04\x1f'),(12,b'\x04\x01')]:
            if await c.command(0x40,bytes([selector]),0x40+selector)!=expected:
                raise RuntimeError('Requires D110_M 4.31 / hardware 4.01')
        cap=decode(await c.command(0xf2,b'\x00',0xf3,timeout=5))
        if cap['status']!=16: raise RuntimeError('Wallet reader firmware not installed')
        if args.mode=='probe': print(json.dumps(cap,indent=2));return
        print('Select your own payment card in Wallet, authenticate normally, then hold the top of the iPhone at the printer’s roll antenna.',flush=True)
        deadline=time.monotonic()+args.seconds
        records=[];last=None;success=False
        while time.monotonic()<deadline:
            result=decode(await c.command(0xf2,MAGIC+(args.aid or b''),0xf3,timeout=15))
            result['time']=datetime.now(timezone.utc).isoformat()
            records.append(result)
            key=(result['status'],result['stage'],result.get('response_hex'))
            if key!=last: print(json.dumps(result,indent=2),flush=True);last=key
            if result['select_succeeded']:
                success=True;break
            if result['status'] in (1,2,7,8): break
            await asyncio.sleep(0.35)
        if args.output:
            with args.output.open('x') as f:
                json.dump({'select_succeeded':success,'aid':(args.aid or b'').hex(),'attempts':records},f,indent=2)
                f.write('\n')
            print(f'Saved {args.output}')
        if not success: raise RuntimeError('No successful SELECT; see the last stage and status above')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['scan','probe','read'],nargs='?',default='probe')
    p.add_argument('--address')
    p.add_argument('--aid',type=aid_value,help='SELECT this AID instead of the PPSE directory')
    p.add_argument('--seconds',type=int,default=30)
    p.add_argument('--output',type=Path,help='New local JSON capture file; never overwrites')
    a=p.parse_args()
    if not 1<=a.seconds<=120: p.error('--seconds must be 1–120')
    try: asyncio.run(run(a))
    except (ValueError,RuntimeError,asyncio.TimeoutError) as e: p.exit(1,f'{e}\n')
