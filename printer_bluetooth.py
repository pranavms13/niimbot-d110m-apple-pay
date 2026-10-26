#!/usr/bin/env python3
"""D110_M 4.31 / hardware 4.01 Bluetooth inspection and guarded firmware update.

Wire protocol follows MultiMote/niimbluelib packet.ts and protocol.ts.
Flashing requires the explicit flash subcommand and an explicit printer address.
"""
import argparse
import asyncio
import hashlib
import json
import math
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from zlib import crc32

from bleak import BleakClient, BleakScanner
from patch_firmware import validate_container

ROOT = Path(__file__).resolve().parent
IMAGE = ROOT/'firmware/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin'
IMAGE_SHA256 = '31d2819cdca1aad3d8abb840c55144ae02ef05e2b7f9702459ae87bb5d7bdb57'
CRC_COMMANDS = {0x90, 0x91, 0x92, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e}


def packet(command, data=b'\x01', sequence=None):
    if len(data)>255:
        raise ValueError('Packet payload too large')
    if sequence is None:
        body=bytes([command,len(data)])+data
        checksum=0
        for byte in body:checksum^=byte
        return b'\x55\x55'+body+bytes([checksum])+b'\xaa\xaa'
    body=struct.pack('>BHB',command,sequence,len(data))+data
    return b'\x55\x55'+body+struct.pack('>I',crc32(body))+b'\xaa\xaa'


def parse_frame(raw):
    if not raw.startswith(b'\x55\x55') or not raw.endswith(b'\xaa\xaa'):
        raise ValueError('Invalid frame delimiters')
    command=raw[2]
    if command in CRC_COMMANDS:
        sequence=int.from_bytes(raw[3:5],'big');length=raw[5]
        if len(raw)!=length+12 or crc32(raw[2:-6])!=int.from_bytes(raw[-6:-2],'big'):
            raise ValueError('Firmware packet size/CRC mismatch')
        data=raw[6:-6]
    else:
        sequence=None;length=raw[3];checksum=0
        for byte in raw[2:-3]:checksum^=byte
        if len(raw)!=length+7 or checksum!=raw[-3]:
            raise ValueError('Normal packet size/checksum mismatch')
        data=raw[4:-3]
    return {'command':command,'sequence':sequence,'data':data,'raw':raw}


class Printer:
    def __init__(self, log_path, address, name=None, image=IMAGE, expected_hash=IMAGE_SHA256):
        self.address=address;self.name=name;self.image=image;self.expected_hash=expected_hash
        self.client=None;self.char=None;self.buffer=bytearray();self.pending=[]
        self.changed=asyncio.Event();self.failure=None
        self.log_file=log_path.open('x');self.started=time.monotonic()
        self.record('session',target=self.name,address=self.address)

    def record(self,event,**fields):
        record={'time':datetime.now(timezone.utc).isoformat(),'elapsed':round(time.monotonic()-self.started,3),'event':event,**fields}
        self.log_file.write(json.dumps(record)+'\n');self.log_file.flush()

    async def connect(self):
        devices=await BleakScanner.discover(timeout=10)
        matches=[d for d in devices if d.address.upper()==self.address.upper()]
        if len(matches)!=1 or (self.name is not None and matches[0].name!=self.name):
            raise RuntimeError('The specifically identified D110_M is not advertising; no other device will be used')
        self.name=matches[0].name
        self.client=BleakClient(matches[0],disconnected_callback=lambda _:self.record('disconnected'))
        await self.client.connect()
        choices=[c for s in self.client.services for c in s.characteristics
                 if 'notify' in c.properties and 'write-without-response' in c.properties]
        if len(choices)!=1:
            raise RuntimeError('Expected exactly one printer communication characteristic')
        self.char=choices[0]
        self.record('connected',characteristic=self.char.uuid,max_write=self.char.max_write_without_response_size)
        print('Connected',self.name,'write size',self.char.max_write_without_response_size,flush=True)
        await self.client.start_notify(self.char,self.notify)

    def notify(self,_,data):
        self.record('notification',hex=bytes(data).hex())
        self.buffer.extend(data)
        try:
            while len(self.buffer)>=4:
                start=self.buffer.find(b'\x55\x55')
                if start<0:
                    self.buffer[:]=b'\x55' if self.buffer[-1]==0x55 else b''
                    break
                if start:del self.buffer[:start]
                if len(self.buffer)<4:break
                is_crc=self.buffer[2] in CRC_COMMANDS
                if is_crc and len(self.buffer)<6:break
                size=(self.buffer[5]+12) if is_crc else (self.buffer[3]+7)
                if len(self.buffer)<size:break
                frame=parse_frame(bytes(self.buffer[:size]));del self.buffer[:size]
                self.pending.append(frame)
                self.record('received',command=hex(frame['command']),sequence=frame['sequence'],data=frame['data'].hex())
                if frame['command']==0x9e and frame['data']==b'\x00':
                    self.failure=RuntimeError('Printer rejected the firmware update (0x9e 00)')
        except Exception as exc:
            self.failure=exc
        self.changed.set()

    async def send(self,command,data=b'\x01',sequence=None):
        if self.failure:raise self.failure
        raw=packet(command,data,sequence)
        self.record('sending',command=hex(command),sequence=sequence,data=data.hex(),frame=raw.hex())
        size=self.char.max_write_without_response_size
        for offset in range(0,len(raw),size):
            if self.failure:raise self.failure
            await self.client.write_gatt_char(self.char,raw[offset:offset+size],response=False)
            if offset+size<len(raw):await asyncio.sleep(0.01)

    async def wait(self,commands,timeout=15):
        deadline=time.monotonic()+timeout
        while True:
            if self.failure:raise self.failure
            for i,frame in enumerate(self.pending):
                if frame['command'] in commands:return self.pending.pop(i)
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError(f'Waiting for {[hex(c) for c in commands]}')
            self.changed.clear()
            await asyncio.wait_for(self.changed.wait(),left)

    async def command(self,command,data,responses,timeout=15):
        await self.send(command,data)
        return await self.wait(responses,timeout)

    async def inspect(self):
        result={'name':self.name}
        for key,name in [(8,'model'),(9,'firmware'),(12,'hardware'),(10,'battery')]:
            frame=await self.command(0x40,bytes([key]),{0x40+key})
            result[name+'_hex']=frame['data'].hex()
        if result['model_hex']!='0910' or result['firmware_hex']!='041f' or result['hardware_hex']!='0401':
            raise RuntimeError(f'Unexpected model or version: {result}')
        frame=await self.command(0x1a,b'\x01',{0x1b})
        result['rfid_hex']=frame['data'].hex()
        result['history']=await self.history()
        self.record('inspection',result=result)
        print(json.dumps(result,indent=2),flush=True)
        return result

    async def history(self):
        # Selector 5 returns the count and clears only the pagination flag.
        frame=await self.command(0x52,b'\x05',{0x63})
        if len(frame['data'])!=1 or frame['data'][0]>20:raise RuntimeError('Invalid history count')
        count=frame['data'][0];records=[];pages=[]
        for page in range(1,math.ceil(count/5)+1):
            response=await self.command(0x52,bytes([page]),{0x62,0x63})
            raw=response['data'];pages.append({'page':page,'response':hex(response['command']),'hex':raw.hex()})
            if response['command']!=0x62 or len(raw)%12:
                raise RuntimeError('Unexpected history page response')
            for offset in range(0,len(raw),12):
                records.append({'identity':raw[offset:offset+8].hex(),
                                'limit':int.from_bytes(raw[offset+8:offset+10],'big'),
                                'used':int.from_bytes(raw[offset+10:offset+12],'big')})
        if len(records)!=count:raise RuntimeError('History record count mismatch')
        return {'count':count,'records':records,'pages':pages}

    async def flash(self):
        image=validated_image(self.image,self.expected_hash)
        before=await self.inspect()
        if before['battery_hex']!='04':raise RuntimeError('Expected full 4/4 battery for this update')
        if not before['rfid_hex'].startswith('00'):raise RuntimeError('Remove the roll before flashing')
        self.record('update_begin',sha256=self.expected_hash,bytes=len(image),file=str(self.image))
        print('Starting the authorized firmware update',flush=True)
        start=await self.command(0xf5,bytes([4,31]),{0xf6})
        if start['data']!=b'\x01':raise RuntimeError('Printer refused update mode')
        await self.wait({0x90})
        await self.send(0x91,struct.pack('>I',crc32(image)),sequence=0)
        total=math.ceil(len(image)/200);sent=set();requests=0
        while True:
            request=await self.wait({0x9a,0x9e},timeout=20)
            if request['command']!=0x9a:raise RuntimeError('Unexpected early update result')
            sequence=request['sequence'];requests+=1
            if sequence is None or sequence>total or requests>total*3:
                raise RuntimeError('Invalid or excessive chunk requests')
            if sequence==total:
                if len(sent)!=total:raise RuntimeError('Printer skipped untransmitted chunks')
                break
            if sequence>len(sent):raise RuntimeError('Out-of-order chunk request')
            await self.send(0x9b,image[sequence*200:(sequence+1)*200],sequence)
            sent.add(sequence)
            if len(sent)%25==0 or len(sent)==total:
                print(f'Uploaded {len(sent)}/{total} chunks',flush=True)
        print('Upload complete; requesting printer checksum verification',flush=True)
        await self.send(0x9c,b'\x01',sequence=0)
        checked=await self.wait({0x9d,0x9e},timeout=30)
        if checked['command']!=0x9d or checked['data']!=b'\x01':
            raise RuntimeError('Printer checksum check failed; commit not sent')
        self.record('device_checksum_verified')
        print('Printer checksum check passed; committing update',flush=True)
        await self.send(0x92,b'\x01',sequence=0)
        result=await self.wait({0x9e},timeout=30)
        if result['data']!=b'\x01':raise RuntimeError('Printer did not confirm commit')
        self.record('device_update_success',sha256=self.expected_hash)
        print('Printer confirmed update success. Waiting 10 seconds for restart.',flush=True)
        await asyncio.sleep(10)
        return {'update_success':True,'sha256':self.expected_hash,'before':before}

    async def close(self):
        if self.client and self.client.is_connected:await self.client.disconnect()
        self.log_file.close()


def validated_image(path, expected_hash):
    image=path.read_bytes()
    if hashlib.sha256(image).hexdigest()!=expected_hash.lower():
        raise RuntimeError('Update file differs from the selected SHA-256')
    if validate_container(image)!=(431,2320):
        raise RuntimeError('Expected a D110_M 4.31 firmware container')
    return image


async def run(args):
    # Validate the file before opening Bluetooth or creating an update session.
    if args.mode=='flash':validated_image(args.image,args.sha256)
    logs=ROOT/'logs';logs.mkdir(exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    p=Printer(logs/f'{stamp}-{args.mode}.jsonl',args.address,args.name,args.image,args.sha256)
    try:
        await p.connect()
        result=await p.flash() if args.mode=='flash' else await p.inspect()
        (logs/f'{stamp}-{args.mode}-result.json').write_text(json.dumps(result,indent=2)+'\n')
    except Exception as exc:
        p.record('error',type=type(exc).__name__,message=str(exc))
        raise
    finally:await p.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['inspect','flash'])
    parser.add_argument('--address',required=True,help='Explicit BLE address (CoreBluetooth UUID on macOS)')
    parser.add_argument('--name',help='Optional additional exact advertised-name check')
    parser.add_argument('--image',type=Path,help='Alternative image; requires --sha256')
    parser.add_argument('--sha256',help='Expected image digest; requires --image')
    args=parser.parse_args()
    if (args.image is None)!=(args.sha256 is None):
        parser.error('--image and --sha256 must be provided together')
    if args.sha256 is not None and (len(args.sha256)!=64 or any(c not in '0123456789abcdefABCDEF' for c in args.sha256)):
        parser.error('--sha256 must contain exactly 64 hexadecimal characters')
    if args.image is None:args.image,args.sha256=IMAGE,IMAGE_SHA256
    asyncio.run(run(args))
