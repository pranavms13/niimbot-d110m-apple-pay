# Local INR 1.00 Mastercard transaction experiment

**Hardware-tested successfully on 2026-10-26:** the owner's iPhone returned an ARQC and `9000` after nine APDUs, and the owner confirmed Wallet's checkmark/payment feedback. No payment was submitted. See [exact image, tests and hardware results](TRANSACTION-VALIDATION.md).

This explicitly requested experiment performs the **card-side NFC exchange only** using the owner's presented Apple Wallet Mastercard. It sends no transaction to an acquirer, processor, payment network or issuer. There is no network-submission implementation. The fixed test amount is **INR 1.00**; currency and terminal country are `0356` (India). The card can increment its internal transaction counter. This is a diagnostic experiment, not a certified payment terminal or a complete EMV kernel.

## Behavior

One RF session selects the previously observed Mastercard AID `A0000000041010`, reads its PDOL, sends GET PROCESSING OPTIONS, validates the returned AFL, reads up to 16 indicated records, obtains CDOL1 and sends **one GENERATE AC requesting ARQC**. It requests no CDA. A card returning a cryptogram at GPO causes an immediate stop, without GENERATE AC. There is no second GENERATE AC, issuer authentication, issuer script, or payment submission.

The report distinguishes AAC (card decline), ARQC (request for online authorization), and TC (card-generated offline approval). None proves issuer approval or money movement. Cryptograms are parsed, not cryptographically verified. A Wallet checkmark/sound, if observed, is a device-side observation rather than a bank result.

The test requests ordinary device verification. TRMD is `0480A00000000000`: CDCVM support, CVM required, EMV-only, CDCVM without CDA supported. Bypass, transit and deferred-authorization flags are clear. TVR `8000808000` conservatively reports offline authentication not performed, cardholder verification not established by this experiment, and a floor-limit condition. CVM results `3F0000` do not claim successful PIN or other verification. Terminal type is `22`. This deliberately incomplete terminal processing can cause a card decline; the experiment reports that honestly.

## Build and verify

```sh
python3 experimental/wallet-reader/build.py
python3 experimental/wallet-reader/verify_transaction.py
python3 verification/verify_upload.py --image build/wallet-transaction/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin
```

`verify_transaction.py` also runs the SELECT regression checks. It executes the compiled ARM code with a simulated NFC register/FIFO peripheral, including multi-APDU block numbering, small-frame transmit chaining, long-record receive chaining, both cryptogram templates, AAC/TC/ARQC results, malformed AFL/TLV, unknown DOL values, missing CDOL, timeouts and one-GENERATE-AC enforcement. Host tests verify that an ambiguous response is never retried. Some macOS execution sandboxes do not support Unicorn; use a normal local terminal if it fails there. Physical NFC and boot are separate tests.

Install the bundled, hash-pinned candidate using `printer_bluetooth.py flash --address ADDRESS` with USB power, a full battery and no label roll. See the [root README](../../README.md). The transaction image retains SELECT, refill and history-reset functionality.

## Run

Install the root `requirements.txt` into a virtual environment. After installation:

```sh
python3 experimental/wallet-reader/wallet_transaction.py probe --address ADDRESS
python3 experimental/wallet-reader/wallet_transaction.py run --address ADDRESS --seconds 60 --output captures/transaction-01.jsonl
```

Select your own Mastercard in Wallet, authenticate normally, and hold the top of the iPhone at the roll antenna. The program waits for card presence, then makes one application-level attempt. It retries only an explicit timeout/collision before the application stage. It stops on SELECT failure, any GPO attempt, any GENERATE AC attempt, or an ambiguous Bluetooth response. Run again only as a deliberate new test; absence of a response does not prove that the card did nothing.

The client reserves a new local log before sending the transaction command, records each observation immediately, and never overwrites an existing log. It logs the test parameters, random challenge, processing stages, counter, cryptogram type/value and issuer application data. **PAN and track data from records are not exported by firmware.** No capture is uploaded. Logs explicitly record `payment_submitted: false` and `issuer_authorization_obtained: false`.

## Bounds and protocol

- Reader frame size remains 64 bytes. APDU replies can be assembled up to 512 bytes in local stack memory; only the bounded summary is returned over Bluetooth.
- PDOL maximum 32 bytes, CDOL1 maximum 64 bytes, filled DOL maximum 96 bytes, AFL maximum 32 bytes/eight entries and 16 total records. Unknown DOL fields are filled with zero and counted. Responses outside these limits stop before further commands.
- Hardware/software timeouts, watchdog servicing, 64-frame per-APDU limit, and a 30-second transaction-loop deadline are enforced. The current APDU may take up to eight additional seconds. The host waits up to 45 seconds for its reply. RF is disabled on exit.
- Commands use the existing `F2`/`F3` NIIMBOT framing. `F2 01` queries transaction capability. `F2` payload `TXN 01 A5` followed by three BCD date bytes (`YYMMDD`) and four random challenge bytes starts the fixed test. This is a format guard, not access control.
- Reply is 198 bytes beginning `WT 01`: status, stage, hardware error, flags; last status word; APDU/record/unknown-field counts; AIP, CID, ATC, cryptogram; length-prefixed fixed-capacity IAD, AFL, CDOL1 and PDOL fields. An eight-byte diagnostic tail starting at offset 189 records reason, TX/RX PCB, TX/RX length, block number, transfer phase and frame index; the last byte is reserved. The client also accepts the initial 190-byte format. Flags record GPO sent, GENERATE AC sent and a parsed cryptogram received. Capability status is `11`; normal completion is status zero. Status `09` means unsuccessful APDU status, `0A` missing CDOL1; other error codes retain SELECT meanings.

References: [Apple payment cryptograms and counters](https://support.apple.com/en-al/guide/security/secc1f57e189/web), [NXP reference Mastercard flow](https://www.nxp.com/docs/en/user-guide/UM10951.pdf), [EMVCo TRMD bulletin](https://www.emvco.com/specifications/sb-n319-new-trmd-bits/).
