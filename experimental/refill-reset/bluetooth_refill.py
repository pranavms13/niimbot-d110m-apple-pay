#!/usr/bin/env python3
"""Bluetooth client for the EXPERIMENTAL combined reset patch. Never flashes.

scan/probe/verify are read-only protocol operations. reset writes the loaded
sticker, clears all saved roll history, restores defaults, and requests reboot.
The reset command is sent once, never automatically retried.
"""
import argparse
import asyncio
import json
import time

MAGIC = b'REFILL\x01\xa5'
ERRORS = {
    1: 'Malformed request', 2: 'Printer busy: finish printing/updating first',
    3: 'NFC authentication/read failed', 4: 'Counter or metadata CRC invalid',
    5: 'Loaded sticker identity differs or has an unsupported UID layout',
    6: 'NFC write failed; original counter restored and verified',
    7: 'NFC readback failed; original counter restored and verified',
    8: 'Settings flash save failed; sticker is zero but flash state is uncertain. No reboot requested',
    9: 'NFC write/readback failed and rollback could not be verified. Inspect the sticker before printing',
    10: 'Reel/settings reset succeeded, but the restart marker could not be verified. No reboot requested',
}


def packet(command, data):
    if not 0 <= command <= 255 or len(data) > 255: raise ValueError('Invalid packet')
    body = bytes([command, len(data)]) + data
    checksum = 0
    for b in body: checksum ^= b
    return b'\x55\x55' + body + bytes([checksum]) + b'\xaa\xaa'


def refill_payload(uid):
    if len(uid) != 8: raise ValueError('Use the 8-byte roll ID from the printer, not the 7-byte phone UID')
    return MAGIC + uid


def decode_roll(data):
    if len(data) < 8: raise RuntimeError('No readable reel loaded')
    offset = 8
    for _ in range(2):
        if offset >= len(data): raise ValueError('Truncated RFID information')
        offset += 1 + data[offset]
    if offset + 5 != len(data): raise ValueError('Unexpected RFID information format')
    return {'identity': data[:8].hex(), 'limit': int.from_bytes(data[offset:offset+2], 'big'),
            'used': int.from_bytes(data[offset+2:offset+4], 'big'), 'type': data[offset+4]}


class Connection:
    def __init__(self, device):
        self.device = device
        self.buffer = bytearray()
        self.queue = asyncio.Queue()
        self.disconnected = asyncio.Event()

    async def __aenter__(self):
        from bleak import BleakClient
        self.client = BleakClient(self.device, disconnected_callback=lambda _: self.disconnected.set())
        await self.client.connect()
        try:
            choices = [c for s in self.client.services for c in s.characteristics
                       if 'notify' in c.properties and 'write-without-response' in c.properties]
            if len(choices) != 1: raise RuntimeError('Expected one printer protocol characteristic')
            self.char = choices[0]
            await self.client.start_notify(self.char, self.notify)
            return self
        except BaseException:
            await self.client.disconnect()
            raise

    async def __aexit__(self, *_):
        if self.client.is_connected: await self.client.disconnect()

    def notify(self, _, data):
        self.buffer.extend(data)
        if len(self.buffer) > 8192:
            self.buffer.clear(); self.queue.put_nowait(ValueError('Unexpected notification size')); return
        while len(self.buffer) >= 4:
            start = self.buffer.find(b'\x55\x55')
            if start < 0:
                self.buffer[:] = b'\x55' if self.buffer[-1:] == b'\x55' else b''
                return
            if start: del self.buffer[:start]
            if len(self.buffer) < 4: return
            size = self.buffer[3] + 7
            if len(self.buffer) < size: return
            raw = bytes(self.buffer[:size]); del self.buffer[:size]
            checksum = 0
            for b in raw[2:-3]: checksum ^= b
            if raw[-2:] != b'\xaa\xaa' or checksum != raw[-3]:
                self.queue.put_nowait(ValueError('Invalid printer reply')); continue
            self.queue.put_nowait((raw[2], raw[4:-3]))

    async def command(self, command, data, response, timeout=20):
        raw = packet(command, data)
        size = self.char.max_write_without_response_size
        for offset in range(0, len(raw), size):
            await self.client.write_gatt_char(self.char, raw[offset:offset+size], response=False)
        deadline = time.monotonic()+timeout
        while True:
            item = await asyncio.wait_for(self.queue.get(), max(0.01, deadline-time.monotonic()))
            if isinstance(item, Exception): raise item
            if item[0] == response: return item[1]
            if time.monotonic() >= deadline: raise TimeoutError('No expected printer reply')

    async def identify(self):
        for selector, expected in [(8,b'\x09\x10'),(9,b'\x04\x1f'),(12,b'\x04\x01')]:
            data = await self.command(0x40, bytes([selector]), 0x40+selector)
            if data != expected: raise RuntimeError('Expected D110_M, firmware 4.31, hardware 4.01')
        reply = await self.command(0xf0, b'\x00', 0xf1, timeout=5)
        if reply != b'RF\x01\x10': raise RuntimeError('Experimental refill protocol v1 is not installed')

    async def roll(self):
        return decode_roll(await self.command(0x1a, b'\x01', 0x1b))

    async def verify(self, expected_uid=None):
        roll = await self.roll()
        if expected_uid and roll['identity'] != expected_uid: raise RuntimeError('Different reel after reboot')
        if roll['used'] != 0: raise RuntimeError('Printer does not report zero used labels')
        count = await self.command(0x52, b'\x05', 0x63)
        if count not in (b'\x00', b'\x01'): raise RuntimeError('Old roll history remains')
        if count == b'\x01':
            record = await self.command(0x52, b'\x01', 0x62)
            if len(record) != 12 or record[:8].hex() != roll['identity'] or record[10:] != b'\x00\x00':
                raise RuntimeError('Saved history does not match the zero-count reel')
        return {'roll': roll, 'saved_records': count[0], 'printer_reports_reset': True}


async def run(args):
    from bleak import BleakScanner
    from bleak.exc import BleakError
    if args.mode == 'scan':
        devices = await BleakScanner.discover(timeout=10)
        for d in devices:
            if (d.name or '').startswith('D110_M'): print(d.address, d.name)
        return
    if not args.address: raise ValueError('--address is required; use scan to find it')
    device = await BleakScanner.find_device_by_address(args.address, timeout=10)
    if device is None: raise RuntimeError('Selected printer is not advertising; disconnect the phone app')
    uid = None
    async with Connection(device) as c:
        await c.identify()
        if args.mode == 'probe':
            print(json.dumps({'refill_protocol': 1, 'supported': True}, indent=2)); return
        if args.mode == 'verify':
            print(json.dumps(await c.verify(), indent=2)); return
        roll = await c.roll(); uid = roll['identity']
        print(f'Resetting loaded reel {uid}; currently {roll["used"]} used. Sending once.', flush=True)
        try:
            reply = await c.command(0xf0, refill_payload(bytes.fromhex(uid)), 0xf1)
        except Exception as exc:
            raise RuntimeError('Reset outcome unknown; do not resend automatically. Reconnect using verify.') from exc
        if len(reply) != 4 or reply[:3] != b'RF\x01': raise RuntimeError('Unexpected reset response')
        if reply[3] != 0: raise RuntimeError(ERRORS.get(reply[3], f'Unknown status {reply[3]}'))
        print('NFC and settings writes acknowledged; waiting for reset disconnect. '
              'Leave the power button untouched until the reconnection check finishes.', flush=True)
        try: await asyncio.wait_for(c.disconnected.wait(), 15)
        except asyncio.TimeoutError as exc:
            raise RuntimeError('Reset acknowledged but no reboot disconnect observed. Do not repeat automatically.') from exc
    # Read-only retries after reboot; never retry the mutating command.
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        await asyncio.sleep(2)
        device = await BleakScanner.find_device_by_address(args.address, timeout=5)
        if device is None: continue
        try:
            async with Connection(device) as c:
                await c.identify()
                result = await c.verify(uid)
                result['reset_disconnect_observed'] = True
                result['automatic_restart_verified'] = False
                print(json.dumps(result, indent=2)); return
        except (BleakError, OSError, asyncio.TimeoutError): continue
    raise RuntimeError('Printer did not reconnect. If powered off, turn it on and run verify; automatic reboot is unverified.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['scan','probe','verify','reset'], nargs='?', default='probe')
    p.add_argument('--address', help='Exact Bluetooth address/UUID printed by scan')
    args = p.parse_args()
    try: asyncio.run(run(args))
    except (RuntimeError, ValueError, asyncio.TimeoutError) as exc:
        p.exit(1, f'{exc}\n')
