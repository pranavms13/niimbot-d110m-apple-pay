# Experimental Apple Wallet SELECT reader

The current build also includes a separate, explicit [local INR 1.00 transaction experiment](TRANSACTION.md). The `wallet_reader.py` client and SELECT mode documented here retain their metadata-only behavior. Transaction operations require `wallet_transaction.py run` and a different command payload.

**Hardware result, 2026-10-26:** installed and tested on the owner's D110_M and iPhone. Both the payment directory and its advertised Mastercard application returned successful SELECT responses (`9000`). See [VALIDATION.md](VALIDATION.md) for the exact tested image and scope.

This D110_M 4.31 / hardware 4.01 SELECT mode reads **contactless application metadata** from a card you present yourself: ATQA, UID, SAK, ATS, payment application identifiers, labels, SELECT response data and status words. It does not read the original bank-card number, enumerate every Wallet item, bypass authentication, or initiate a payment. SELECT mode sends no GPO, GENERATE AC, tag-memory writes or settings writes. Apple Pay uses device-specific payment credentials; a selected application's FCI is not a payment-card dump.

The first milestone is a successful `SELECT 2PAY.SYS.DDF01` (the contactless payment directory). Hardware success must be established separately from offline emulator tests. Wallet appearing alone is not success. An iPhone must present a supported payment card; normal authentication may be needed before a SELECT succeeds. UID values may change and must not be used as identity credentials.

## Build and verify

From the repository root:

```sh
python3 experimental/wallet-reader/build.py
python3 experimental/wallet-reader/verify.py
python3 experimental/wallet-reader/verify_transaction.py
python3 verification/verify_upload.py --image build/wallet-transaction/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin
```

Verification requires `capstone` and `unicorn`; the Bluetooth client requires `bleak`. Use the existing project Python environment or install dependencies into a virtual environment. On this Mac Unicorn needs to run outside the execution sandbox.

The build regenerates the existing refill extension in `build/wallet-transaction/refill-base/`, appends the Wallet extension, and replaces only the dispatch hook. All other commands delegate to the existing refill dispatcher. The candidate retains the existing r1 history-reset and experimental refill/restart behavior. The complete base image is hash-pinned by the existing builder. The historical SELECT-only image is documented in VALIDATION.md but is not bundled here.

## Install and read

Installation uses `printer_bluetooth.py flash --address ADDRESS` from the repository root; it defaults to the bundled, hash-pinned transaction image. Connect USB power, charge the battery, remove the label roll, and disconnect the NIIMBOT phone app before updating. The client below does **not** install firmware.

```sh
python3 experimental/wallet-reader/wallet_reader.py scan
python3 experimental/wallet-reader/wallet_reader.py probe --address ADDRESS
python3 experimental/wallet-reader/wallet_reader.py read --address ADDRESS --seconds 60 --output captures/wallet-directory.json
```

Select your own payment card in Apple Wallet, authenticate normally, and hold the top of the iPhone close to the label-roll antenna. Remove the roll to avoid selecting its sticker instead. Each attempt cycles the field and finishes with the field off. If repeated field resets disrupt presentation, position/authenticate the phone first and run another scan.

On success, `applications` lists advertised AIDs and `labels` lists advertised names. To read one application's FCI, repeat with an AID actually returned by the directory:

```sh
python3 experimental/wallet-reader/wallet_reader.py read --address ADDRESS --aid AID_HEX --seconds 60 --output captures/wallet-application.json
```

`select_succeeded: true` requires an actual APDU response ending in `9000`. A `6a82` response means that DF/application was not found, not a successful read. The tool exits nonzero if no SELECT succeeds. JSON captures stay local and are never uploaded; choose a new output filename for each run.

## Limits and diagnostics

- ISO14443-A at the reader's stock 106-kbit/s configuration; no Type B, FeliCa or Apple VAS.
- One SELECT per fresh RF session. AIDs must be 5–16 bytes. Empty AID selects PPSE.
- Advertised receive frame size 64 bytes; commands/responses support ISO-DEP chaining, no CID/NAD. Corrupt/unexpected frames abort the attempt; there is no RF retransmission recovery.
- Responses are limited to 180 APDU bytes, including status words. Overflow is reported explicitly; partial data is not labeled successful.
- ATS is limited to 32 bytes. Frame waits are limited to 1000 ms, with a 64-frame and approximately eight-second APDU budget. Unsupported timing/WTX is reported explicitly.
- No raw APDU endpoint is exposed. NFC controller registers are accessed through recovered stock routines. Their register layout matches the RC522-style operations used in the stock firmware; this is not proof of the exact reader-chip model.
- Printer activity/update guards are checked before enabling RF. Polling services the watchdog and has both software and hardware timeouts. Settings flash and the label tag are not written by probe operations.

Stages distinguish WUPA, anticollision, card selection, RATS/ATS and SELECT. Status 3 is timeout, 4 is a tag without ISO-DEP, 5 is reader error/collision, 6 is malformed/unsupported framing, 7 is response overflow, 8 is unsupported timing or frame budget. `hardware_error` contains the reader ErrorReg when available.

The emulator executes the compiled extension and stock command wrapper while simulating reader registers/FIFO. It checks timeout/error paths, 4/7-byte UID selection, ATS parsing, SELECT, transmit/receive chaining, WTX, wrong block numbers, response limits, prior refill capability, framing, memory writes and stack bounds. It does not establish physical RF, chip CRC behavior, Bluetooth reliability or successful boot. The upload verifier separately executes the stock staging receiver.

## Protocol v1

NIIMBOT framing is `55 55 CMD LEN DATA XOR AA AA`.

| Request | Payload | Response |
| --- | --- | --- |
| `F2` capability | `00` | `F3`, `WA 01`, status `10` |
| `F2` SELECT | ASCII `WALLET`, `01 A5`, optional AID bytes | `F3`, observation payload |

The fixed observation header is 54 bytes: `WA`, version, status, stage, hardware error, ATQA[2], SAK, UID length, UID[10], ATS length, ATS[32], APDU length. APDU bytes follow. All unused bytes are zero; total response frame length is at most 241 bytes. Capability has the same header with zero observation fields. The magic is a format guard, not authentication.

References: [Apple Pay security](https://support.apple.com/en-ie/101554), [NXP reference POS application](https://www.nxp.com/docs/en/user-guide/UM10951.pdf), [RC522 register/FIFO documentation](https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf).
