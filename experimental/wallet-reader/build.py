#!/usr/bin/env python3
"""Build SELECT and a local transaction experiment on the refill extension, offline."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
from zlib import crc32

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patch_firmware import BASE, encode_bl, validate_container
spec = importlib.util.spec_from_file_location('refill_build', ROOT/'experimental/refill-reset/build.py')
refill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refill)

def build(output, clang='clang'):
    output.mkdir(parents=True, exist_ok=True)
    image, previous = refill.build(output/'refill-base', clang)
    app = bytearray(image[28:])
    old = BASE+previous['extension_offset']+previous['symbols']['refill_dispatch']['offset']
    flags = previous['compiler_flags'] + [f'-DPREV_DISPATCH={old}u']
    source = Path(__file__).with_name('wallet.c')
    obj = output/'wallet.o'
    subprocess.run([clang, *flags, '-c', str(source), '-o', str(obj)], check=True)
    extension, symbols = refill.extract_object(obj.read_bytes())
    offset = (len(app)+3)&~3
    app.extend(bytes(offset-len(app)))
    app.extend(extension)
    assert app[0x4eee:0x4ef2] == encode_bl(BASE+0x4eee, old)
    target = BASE+offset+symbols['wallet_dispatch']['offset']
    app[0x4eee:0x4ef2] = encode_bl(BASE+0x4eee, target)
    if len(app)+28 >= 0x20000: raise ValueError('Image exceeds audited staging capacity')
    header = bytearray(image[:28])
    struct.pack_into('<II', header, 4, len(app), crc32(app))
    norm = bytearray(header[:24]); norm[1:4] = bytes(3)
    struct.pack_into('<I', header, 24, crc32(norm))
    candidate = bytes(header+app)
    assert validate_container(candidate) == (431,2320)
    name = 'D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin'
    digest = hashlib.sha256(candidate).hexdigest()
    manifest = dict(image=name, sha256=digest, image_bytes=len(candidate),
                    extension_offset=offset, extension_bytes=len(extension), symbols=symbols,
                    previous_dispatch=old, dispatch=target,
                    source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                    refill_base_sha256=previous['sha256'], compiler=previous['compiler'],
                    compiler_flags=flags, hardware_verified=False)
    (output/name).write_bytes(candidate)
    (output/'wallet-extension.bin').write_bytes(extension)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'SHA256SUMS.txt').write_text(f'{digest}  {name}\n')
    return manifest

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir',type=Path,default=ROOT/'build/wallet-transaction')
    p.add_argument('--clang',default='clang')
    a=p.parse_args()
    print(json.dumps(build(a.output_dir,a.clang),indent=2))
