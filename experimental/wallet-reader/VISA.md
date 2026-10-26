# Physical Visa ₹1 local experiment

Implemented and offline-tested on 2026-10-26. **Hardware-tested successfully with the owner’s physical Visa card.** The candidate retains the existing Mastercard and SELECT/refill paths. No payment is submitted, no issuer authorization is obtained, and no processor integration is present.

## Behavior and scope

Use `--network visa` for an owner-presented physical Visa credit/debit card. The firmware selects `A0000000031010`, parses its PDOL and sends one GET PROCESSING OPTIONS (GPO) with the fixed INR 1.00 amount. It then stops, whether GPO succeeds, declines, times out or returns an unsupported format. There is no Visa READ RECORD, GENERATE AC, second GPO, fallback to another AID, PIN collection or issuer script. A card may increment its transaction counter even when the response is lost.

Visa TTQ (`9F66`) is `20800000`: qVSDC supported and an online cryptogram requested. It does not claim support for magnetic-stripe mode, offline authentication, contact chip, PIN, signature or consumer-device CVM. It does not claim that cardholder verification succeeded. This physical-card, low-value experiment does not implement Visa Wallet CDCVM, Visa Electron, alternate Visa AIDs, or a certified terminal's risk management. Cards requiring those features can refuse the exchange.

Before sending GPO, the Visa PDOL must request exactly one correctly sized TTQ, amount (`9F02`, six bytes), currency (`5F2A`, two bytes) and unpredictable number (`9F37`, four bytes). Missing, duplicate or wrong-length required fields stop at SELECT. Other requested fields use the bounded filler; unknown fields are zero-filled and counted. Country and currency are `0356`; the amount is `000000000100`; the date and fresh random challenge come from the host. TVR remains `8000808000`, and CVM results remain `3F0000`. All pre-existing buffer and RF limits remain in force.

The supported GPO response is template `77` with AIP, ATC, an eight-byte application cryptogram and issuer application data. If CID (`9F27`) is present, AAC, TC and ARQC are reported distinctly. If it is absent, the result is **Unknown (card omitted CID)**; the requested online cryptogram does not establish the returned cryptogram's type. Neither outcome proves bank approval. Cryptograms are not cryptographically verified. PAN and track data received inside GPO stay in transient firmware buffers and are not exported in the summary or capture.

## Install and run

Candidate: `firmware/D110_M_V4.31_wallet-transaction-visa_EXPERIMENTAL.bin`

SHA-256: `1dfdcafc28ef9da34313867fe7716a9775e74a48a60e53876a3496315b5cdf57`

Size: 123,368 bytes; Wallet extension: 5,392 bytes. The candidate's separate `firmware/manifest-visa.json` records the successful physical Visa test with `hardware_verified: true`. The original hardware-tested Mastercard image and default installer selection are unchanged.

With USB power connected, a full battery and the label roll removed, run from the repository root:

```sh
python printer_bluetooth.py flash --address ADDRESS \
  --image firmware/D110_M_V4.31_wallet-transaction-visa_EXPERIMENTAL.bin \
  --sha256 1dfdcafc28ef9da34313867fe7716a9775e74a48a60e53876a3496315b5cdf57
# Turn the printer back on if it stays powered off after the update.
python experimental/wallet-reader/wallet_transaction.py probe --address ADDRESS --network visa
mkdir -p captures
python experimental/wallet-reader/wallet_transaction.py run --address ADDRESS \
  --network visa --seconds 120 --output captures/visa-01.jsonl
```

Hold the physical card at the printer's roll antenna. Use a new capture filename for each deliberate test. The host checks firmware capability before any transaction command; old firmware is rejected for Visa. It retries only explicit pre-application discovery timeouts/collisions, never an application selection failure, any GPO attempt or an ambiguous Bluetooth response.

## Protocol additions

- The capability request remains `F2 01`. New firmware returns a 198-byte `WT 02` summary, status `11`, and a supported-network bit mask at offset 197 (`03`: Mastercard and Visa). Legacy `WT 01` capabilities imply Mastercard only.
- The legacy 12-byte `TXN 01 A5` + date (three BCD bytes) + challenge (four bytes) request remains Mastercard and returns `WT 01`.
- A v2 request is 13 bytes: `TXN 02 A5` + date + challenge + network (`00` Mastercard, `01` Visa). It returns `WT 02`, with the selected network at offset 197. Other network values are rejected before RF activation.
- V2 flag `08` means a parsed Visa cryptogram omitted CID. It accompanies flag `04` (cryptogram received). Other flags and summary offsets are unchanged. Diagnostic bytes remain 189–196.
- Status `0B` means an unsupported Visa GPO template; `0C` means missing/invalid required PDOL fields. Existing malformed-data, card-status, timeout and bounds errors retain their meanings.

## Offline verification

The compiled ARM emulator passes the existing Mastercard/SELECT/refill regressions plus Visa fixtures that independently assert the exact SELECT and GPO command bytes. Visa cases cover both FIFO sizes, long chained responses, optional CID, explicit AAC/TC/ARQC, no PAN/track export, malformed and duplicate TLVs, missing fields, bad PDOL lengths, GPO refusal/timeouts, and stopping without fallback or GENERATE AC. Host tests check legacy-firmware rejection and no retry following Visa GPO. Memory-write guards, output canaries, RF cleanup and the two-KiB stack limit apply to every emulator case.

The upload-receiver simulation passed all 617 chunks, and the installer gate checks passed. The exact candidate was then installed on the D110_M on 2026-10-26: the printer acknowledged checksum verification and commit, rebooted, and reported protocol v2 with Mastercard and Visa capabilities over Bluetooth. The subsequent owner-presented physical Visa test completed SELECT → GPO in two APDUs with status `9000`, CID `80` and an ARQC. All requested PDOL fields were supplied without unknown-field zero filling. The chained GPO response completed without a frame error. No READ RECORD or GENERATE AC was sent, no payment was submitted, and no issuer authorization was obtained. The cryptogram was parsed, not cryptographically verified. The private local capture remains outside the repository. This confirms the tested card and image; other Visa cards and post-install printing remain untested. Installation and transaction evidence are recorded separately in the manifest.

## References

Visa's [minimum online-only terminal configuration](https://usa.visa.com/dam/VCOM/regional/na/us/run-your-business/documents/visa-minimum-us-online-only-terminal-configuration.pdf) documents the Visa credit/debit AID and qVSDC/TTQ configuration. Visa's [acquirer implementation guide, section 3.5](https://usa.visa.com/content/dam/VCOM/regional/na/us/partner-with-us/documents/visa-smart-debit-credit-vsdc-visa-paywave-vpw-us-acquirer-implementation-guide.pdf) describes the qVSDC card exchange and separates it from online issuer processing. These public U.S. guides provide protocol context; this INR experiment does not claim regional acceptance compliance or certification.
