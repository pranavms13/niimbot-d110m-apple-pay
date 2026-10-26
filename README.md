# Apple Pay NFC experiment on a NIIMBOT D110_M

A label printer talking to an iPhone's Apple Wallet over NFC. This repository contains the firmware patch, Bluetooth clients, guarded installer, and offline verification tools for that experiment.

**Hardware-tested on 26 October 2026:** an owner-presented Apple Wallet Mastercard completed SELECT → GET PROCESSING OPTIONS → six READ RECORD commands → one GENERATE AC. It returned `9000` and an ARQC, and the owner observed Wallet's checkmark or payment sound.

The amount was **₹1.00**, used only in the local card-side exchange. **No payment was submitted, no issuer authorization was obtained, and no money transfer was initiated through a payment processor.** An ARQC requests online authorization; Wallet feedback does not establish bank approval. There is no processor integration in this repository.

## What it does

| Mode | Result |
| --- | --- |
| SELECT reader | Payment directory and selected application metadata: AIDs, labels, NFC activation information, FCI and status words. |
| Local transaction | One fixed INR 1.00 Mastercard exchange; reports stage, status word, cryptogram type, counter and related diagnostic fields. |

This is an experimental reader, not a certified EMV terminal. It does not bypass Wallet authentication, enumerate all Wallet cards, or export PAN/track data from transaction records. Cryptograms are parsed, not cryptographically verified. A test may increment the card's transaction counter even if its response is lost.

## Supported hardware

- **NIIMBOT D110_M**, firmware **4.31**, hardware **4.01** only. D110 and other similarly named models are not validated.
- An iPhone presenting the owner's Apple Wallet Mastercard. The transaction AID is fixed to `A0000000041010`; other networks are not implemented.
- A computer with Bluetooth LE and Python **3.10+**. The physical test used macOS; other host platforms have not been hardware-tested.
- For source builds: Clang with the ARM target. The bundled image was built with Apple Clang 21.0.0.

The firmware uses the printer's existing NFC hardware and recovered stock routines. It is built on the earlier history-reset and refill/restart extensions, so those behaviors remain present. The Wallet paths do not write label tags or settings. A post-install label-printing regression was not performed for this exact transaction image.

## Setup

```sh
git clone git@github.com:pranavms13/niimbot-d110m-apple-pay.git
cd niimbot-d110m-apple-pay
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p captures
python experimental/wallet-reader/wallet_reader.py scan
```

Use the printer address returned by the scan in place of `ADDRESS` below. On macOS this is a CoreBluetooth UUID. Give the terminal Bluetooth permission when macOS asks. Disconnect the NIIMBOT phone app before using the clients.

## Install the tested image

Flashing changes the printer firmware. Keep USB power connected, charge the battery fully, and remove the label roll. The installer checks the exact model, firmware and hardware versions, full-battery indication, roll absence, and image hash before entering update mode. It verifies the printer's upload checksum before committing.

```sh
(cd firmware && shasum -a 256 -c SHA256SUMS.txt)
python printer_bluetooth.py inspect --address ADDRESS
python printer_bluetooth.py flash --address ADDRESS
```

The default is the bundled, hardware-tested image:

```text
firmware/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin
SHA-256: 31d2819cdca1aad3d8abb840c55144ae02ef05e2b7f9702459ae87bb5d7bdb57
Size: 122,972 bytes
```

If the printer remains powered off after the update, press its power button once. Then check the extension:

```sh
python experimental/wallet-reader/wallet_transaction.py probe --address ADDRESS
```

An optional `--name NAME` adds an exact advertised-name check to the installer. A different image requires both `--image PATH` and `--sha256 DIGEST`; a locally computed hash is not evidence that an image has been hardware-tested. The original firmware is bundled as a build input and reference; recovery from a failed boot is not automated here.

## Read the payment directory

Remove the roll, select your own payment card in Wallet, authenticate normally, and hold the top of the iPhone near the roll antenna.

```sh
python experimental/wallet-reader/wallet_reader.py read \
  --address ADDRESS --seconds 60 --output captures/wallet-directory.json
```

To SELECT an application, use an AID actually returned by the directory:

```sh
python experimental/wallet-reader/wallet_reader.py read \
  --address ADDRESS --aid A0000000041010 --seconds 60 \
  --output captures/wallet-application.json
```

SELECT mode reads application metadata. It sends no GPO or GENERATE AC. See the [SELECT protocol and limits](experimental/wallet-reader/README.md).

## Run one local ₹1.00 experiment

Present and authenticate your own Mastercard as above, then run:

```sh
python experimental/wallet-reader/wallet_transaction.py run \
  --address ADDRESS --seconds 60 --output captures/transaction-01.jsonl
```

The client waits for card presence and makes one application-level attempt. It retries only explicit timeout/collision observations before application selection. It does not automatically retry after a SELECT failure, GPO, GENERATE AC, or an ambiguous transport result. Choose a new output filename for every deliberate new test; transaction logs are never overwritten.

The amount, currency and country are fixed to INR 1.00 / India. The date and random challenge are supplied by the host. There is no second GENERATE AC, issuer authentication, or payment submission. AAC, ARQC and TC are reported distinctly; none is treated as proof of issuer authorization.

Captures contain card-supplied metadata or transaction material, including cryptograms and issuer application data. Keep them private. `captures/`, installer `logs/`, and JSONL files are ignored by Git. **No real card captures are included in this repository.** See [transaction behavior and wire protocol](experimental/wallet-reader/TRANSACTION.md) and [hardware validation](experimental/wallet-reader/TRANSACTION-VALIDATION.md).

## Build and verify offline

```sh
python -m pip install -r requirements-dev.txt
python experimental/wallet-reader/build.py
python experimental/wallet-reader/verify_transaction.py
python verification/verify_upload.py \
  --image build/wallet-transaction/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin
python verification/verify_installer.py
cmp firmware/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin \
  build/wallet-transaction/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin
```

The transaction verifier also runs SELECT regressions. It executes compiled ARM code with a simulated NFC peripheral, including frame chaining, malformed replies, timeouts, DOL bounds, no-retry behavior, output bounds and stack checks. The upload verifier executes the stock update receiver against virtual staging flash. These tests do not simulate a bank, establish cryptogram validity, or replace physical hardware testing.

Build output goes to ignored `build/`. Matching the bundled bytes requires a compatible compiler; a different compiler can produce a different hash. New build manifests deliberately start with `hardware_verified: false`; the bundled manifest records the separately observed hardware result. Some macOS execution sandboxes prevent Unicorn from running; use a normal local terminal in that case.

## Repository layout and provenance

- `firmware/`: original build input, tested transaction image, hashes and hardware-result manifest.
- `experimental/wallet-reader/`: NFC implementation, Bluetooth clients, protocol documentation and ARM tests.
- `experimental/refill-reset/`: inherited firmware base builder and Bluetooth transport.
- `verification/`: stock firmware emulator, upload checks and installer checks.
- `printer_bluetooth.py`: explicit-address installer and inspection client; local logs stay ignored.

Extracted from [niimbot-d110m-patched-firmware](https://github.com/pranavms13/niimbot-d110m-patched-firmware), whose base was commit `a63b72fe6de9ac645d966fe1adeba269dbe175d6`, plus the locally developed Wallet experiment. The inherited code is included so this repository builds without a sibling checkout. The installer was adapted to remove machine-specific addresses and paths. The firmware source is unchanged from the successful test.

The stock NIIMBOT firmware is third-party material; its inclusion does not grant a new license to it. No blanket license is asserted for this collection. Bluetooth packet framing follows the work in [MultiMote/niimbluelib](https://github.com/MultiMote/niimbluelib). Protocol references and the observed chaining fix are documented alongside the experiment.
