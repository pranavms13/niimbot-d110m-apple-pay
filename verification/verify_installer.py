"""Offline installer gates; no Bluetooth connection or physical update."""
import asyncio
import hashlib
from pathlib import Path
import sys
import tempfile
from unittest.mock import AsyncMock, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from printer_bluetooth import IMAGE, IMAGE_SHA256, Printer, packet, parse_frame, validated_image


def rejects(call):
    try:
        call()
    except (ValueError, RuntimeError):
        return
    raise AssertionError('Expected rejection')


image = validated_image(IMAGE, IMAGE_SHA256)
rejects(lambda: validated_image(IMAGE, '0' * 64))
with tempfile.TemporaryDirectory() as directory:
    damaged = Path(directory) / 'damaged.bin'
    data = bytearray(image)
    data[-1] ^= 1
    damaged.write_bytes(data)
    # Even a caller-provided matching digest cannot bypass container CRC checks.
    rejects(lambda: validated_image(damaged, hashlib.sha256(data).hexdigest()))

for command, payload, sequence in [(0x40, b'\x08', None), (0x9b, bytes(range(200)), 12)]:
    frame = packet(command, payload, sequence)
    parsed = parse_frame(frame)
    assert (parsed['command'], parsed['data'], parsed['sequence']) == (command, payload, sequence)
    corrupted = bytearray(frame)
    corrupted[-4] ^= 1
    rejects(lambda: parse_frame(bytes(corrupted)))
print('PASS: image hash/container and transport checksum gates.')


async def checks():
    p = Printer.__new__(Printer)
    p.name = 'test printer'
    p.record = Mock()
    p.history = AsyncMock()
    p.command = AsyncMock(side_effect=[{'data': bytes.fromhex(v)} for v in ['0910', '041f', '0402', '04']])
    try:
        await p.inspect()
    except RuntimeError:
        pass
    else:
        raise AssertionError('Wrong hardware version accepted')
    p.history.assert_not_awaited()
    p.image, p.expected_hash = IMAGE, IMAGE_SHA256
    for battery, rfid in [('03', '00'), ('04', '01')]:
        p.inspect = AsyncMock(return_value={'battery_hex': battery, 'rfid_hex': rfid})
        p.command = AsyncMock()
        try:
            await p.flash()
        except RuntimeError:
            pass
        else:
            raise AssertionError('Unsafe preflight accepted')
        p.command.assert_not_awaited()
    print('PASS: wrong hardware, low battery and present-roll gates stop before update mode.')

    p.inspect = AsyncMock(return_value={'battery_hex': '04', 'rfid_hex': '00'})
    p.command = AsyncMock(return_value={'data': b'\x01'})
    p.send = AsyncMock()
    total = (len(image) + 199) // 200
    replies = [{'command': 0x90}]
    replies += [{'command': 0x9a, 'sequence': i} for i in range(total + 1)]
    replies += [{'command': 0x9d, 'data': b'\x00'}]
    p.wait = AsyncMock(side_effect=replies)
    try:
        await p.flash()
    except RuntimeError as exc:
        assert 'checksum check failed' in str(exc)
    else:
        raise AssertionError('Failed checksum accepted')
    assert not any(call.args[0] == 0x92 for call in p.send.await_args_list)
    chunks = [call.args[1] for call in p.send.await_args_list if call.args[0] == 0x9b]
    assert b''.join(chunks) == image
    print('PASS: complete upload preserves bytes; failed device checksum prevents commit.')


asyncio.run(checks())
