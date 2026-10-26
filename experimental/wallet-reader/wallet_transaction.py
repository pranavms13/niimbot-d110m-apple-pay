#!/usr/bin/env python3
"""One local INR 1.00 Mastercard or physical Visa experiment; no processor submission.

The card can update its transaction counter. The firmware never sends a second
GENERATE AC, issuer authentication or issuer scripts. No PAN/track data is returned.
"""
import argparse
import asyncio
from datetime import datetime
import json
from pathlib import Path
import secrets
import time
from zoneinfo import ZoneInfo
from wallet_reader import Connection,STATUS

MAGIC=b'TXN\x01\xa5'
NETWORKS={'mastercard':(0,'a0000000041010'),'visa':(1,'a0000000031010')}
STAGES={0:'idle',1:'WUPA',2:'anticollision',3:'card selection',4:'RATS / ATS',
        5:'SELECT application',6:'GET PROCESSING OPTIONS',7:'READ RECORD',8:'GENERATE AC'}

def decode_transaction(data):
    if len(data) not in (190,198) or data[:2]!=b'WT' or data[2] not in (1,2):
        raise ValueError('Not a supported transaction protocol reply')
    version=data[2]
    if version==2 and len(data)!=198:raise ValueError('Truncated protocol v2 reply')
    status,stage,error,flags=data[3:7]
    if flags&~(15 if version==2 else 7) or data[25]>32 or data[58]>32 or data[91]>64 or data[156]>32:
        raise ValueError('Invalid transaction response fields')
    present=bool(flags&4)
    if flags&8 and (not present or data[197]!=1):raise ValueError('Invalid missing-CID flag')
    if version==2 and status!=17 and data[197] not in (0,1):raise ValueError('Invalid network')
    if status==0 and not present: raise ValueError('Success without a cryptogram')
    cid=data[14]
    kind={0:'AAC (card declined)',0x40:'TC (card-generated offline approval)',
          0x80:'ARQC (online authorization request)'}.get(cid&0xc0,'Invalid cryptogram type') if present else None
    if flags&8:kind='Unknown (card omitted CID)'
    supported=['mastercard'] if version==1 else [name for name,(bit,_) in NETWORKS.items() if data[197]&(1<<bit)]
    return {'protocol_version':version,'network':None if status==17 else ('visa' if version==2 and data[197]==1 else 'mastercard'),
            'supported_networks':supported if status==17 else None,
            'status':status,'message':{0:'Cryptogram received; no payment submitted',
            9:'Card returned an unsuccessful APDU status',10:'Card did not provide CDOL1',
            11:'Visa GPO did not return a supported qVSDC response',
            12:'Visa PDOL missing or mis-sizing required transaction fields',
            17:f'Local transaction protocol v{version} installed'}.get(status,STATUS.get(status,'Unknown status')),
            'stage':STAGES.get(stage,str(stage)),'hardware_error':f'{error:02x}',
            'gpo_sent':bool(flags&1),'generate_ac_sent':bool(flags&2),
            'cryptogram_received':present,'cryptogram_type':kind,
            'status_word':data[7:9].hex() if data[7:9]!=b'\0\0' else None,
            'apdu_count':data[9],'records_read':data[10],'zero_filled_unknown_dol_fields':data[11],
            'aip':data[12:14].hex(),'cid':f'{cid:02x}' if present and not flags&8 else None,
            'application_transaction_counter':int.from_bytes(data[15:17],'big') if present else None,
            'cryptogram':data[17:25].hex() if present else None,
            'issuer_application_data':data[26:26+data[25]].hex(),
            'afl':data[59:59+data[58]].hex(),'cdol1':data[92:92+data[91]].hex(),
            'pdol':data[157:157+data[156]].hex(),
            'frame_diagnostics':dict(zip(['reason','tx_pcb','rx_pcb','tx_length','rx_length',
                'block_number','phase','frame_index'],data[189:197])) if len(data)==198 else None,
            'payment_submitted':False,'issuer_authorization_obtained':False}

def request(now,unpredictable,network='mastercard'):
    if len(unpredictable)!=4: raise ValueError('Challenge must be four bytes')
    network_id,_=NETWORKS[network]
    params=bytes.fromhex(now.strftime('%y%m%d'))+unpredictable
    return MAGIC+params if network=='mastercard' else b'TXN\x02\xa5'+params+bytes([network_id])

def require_network(cap,network):
    if cap['status']!=17:raise RuntimeError('Transaction firmware not installed')
    if network not in cap['supported_networks']:
        raise RuntimeError(f'{network.title()} requires the new transaction firmware; no test command sent')

async def execute(c,payload,seconds,record):
    """Retry ONLY explicit pre-application no-response observations. A lost
    Bluetooth response is ambiguous and is never retried, even before GPO."""
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            result=decode_transaction(await c.command(0xf2,payload,0xf3,timeout=45))
        except BaseException:
            record({'outcome':'unknown; command sent but no valid response; do not automatically repeat',
                    'payment_submitted':False})
            raise
        record(result)
        if result['gpo_sent'] or result['generate_ac_sent'] or result['stage'] not in (
                'WUPA','anticollision','card selection','RATS / ATS') or result['status'] not in (3,5):
            return result
        await asyncio.sleep(0.4)
    return result

async def run(args):
    from bleak import BleakScanner
    device=await BleakScanner.find_device_by_address(args.address,timeout=10)
    if device is None: raise RuntimeError('Printer not advertising; disconnect NIIMBOT app')
    async with Connection(device) as c:
        for selector,expected in [(8,b'\x09\x10'),(9,b'\x04\x1f'),(12,b'\x04\x01')]:
            if await c.command(0x40,bytes([selector]),0x40+selector)!=expected:
                raise RuntimeError('Requires D110_M 4.31 / hardware 4.01')
        cap=decode_transaction(await c.command(0xf2,b'\x01',0xf3,timeout=5))
        require_network(cap,args.network)
        if args.mode=='probe':print(json.dumps(cap,indent=2));return
        now=datetime.now(ZoneInfo('Asia/Kolkata'));un=secrets.token_bytes(4)
        payload=request(now,un,args.network)
        # Reserve and record the run BEFORE any transaction command can be sent.
        with args.output.open('x') as log:
            def record(value):
                value={'time':datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(),**value}
                log.write(json.dumps(value)+'\n');log.flush()
            record({'event':'local_test_start','amount':'1.00','currency':'INR',
                    'currency_code':'0356','terminal_country':'0356','date':now.strftime('%Y-%m-%d'),
                    'unpredictable_number':un.hex(),'network':args.network,'aid':NETWORKS[args.network][1],
                    'payment_submitted':False,'issuer_authorization_obtained':False,
                    'trmd':'0480a00000000000' if args.network=='mastercard' else None,
                    'ttq':'20800000' if args.network=='visa' else None,
                    'tvr':'8000808000','cvm_results':'3f0000'})
            instruction=('Hold your own physical Visa card at the roll antenna.' if args.network=='visa' else
                         'Authenticate your own Mastercard in Wallet and hold the iPhone at the roll antenna.')
            print(f'LOCAL INR 1.00 {args.network.upper()} TEST — no payment will be submitted. {instruction} One GPO/cryptogram attempt maximum.',flush=True)
            result=await execute(c,payload,args.seconds,record)
            print(json.dumps(result,indent=2),flush=True)
            print(f'Capture: {args.output}',flush=True)
            if result['status']!=0 or not result['cryptogram_received']:
                raise RuntimeError('No completed cryptogram exchange. This run stopped; it will not retry the transaction.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['probe','run'],nargs='?',default='probe')
    p.add_argument('--address',required=True)
    p.add_argument('--network',choices=NETWORKS,default='mastercard',help='Explicit application selection; never falls back to another network')
    p.add_argument('--seconds',type=int,default=60,help='Maximum wait for card presence, 1–120 seconds')
    p.add_argument('--output',type=Path,help='New local JSONL capture path (required for run)')
    a=p.parse_args()
    if not 1<=a.seconds<=120:p.error('--seconds must be 1–120')
    if a.mode=='run' and not a.output:p.error('--output is required before a transaction can be sent')
    try:asyncio.run(run(a))
    except (ValueError,RuntimeError,asyncio.TimeoutError) as e:p.exit(1,f'{e}\n')
