# Wallet reader validation — 2026-10-26

Historical SELECT-only candidate (not bundled; the current image also includes transactions): `D110_M_V4.31_wallet-reader_EXPERIMENTAL.bin`

SHA-256: `1177502d6cacfe2c2ed6641e61e5e71e563ed7ae8e96bfa9782a869e70061964`

Size: 121,664 bytes. Appended Wallet code: 3,688 bytes. Base refill candidate: `c320111084d1199d6947e704212a7d8b98d14171cd4352931b0ada90e7a40635`.

## Offline checks passed

- Clang Cortex-M0 build with warnings treated as errors, no unresolved code relocations or external data allocation.
- Header/application CRCs, model/version, staging capacity, and exact prior-image preservation except the dispatch hook.
- Compiled ARM execution through the stock wrapper: capability, malformed and busy requests, previous refill capability, reply bounds and stack below 1 KiB.
- Simulated NFC register/FIFO exchange: 4/7-byte UID selection, ISO-DEP detection, ATS, PPSE and explicit-AID SELECT, command/response chaining and WTX.
- Hardware/software timeouts, collision, non-ISO-DEP tag, malformed ATS, wrong block number, APDU overflow, excessive WTX and malformed BER-TLV rejection. RF field cleanup on all exercised exits.
- Memory-write guard and forbidden-call checks: no label password authentication, tag reads/writes or settings/flash writes during the new probe operations.
- Stock update receiver accepted all 609 chunks, reconstructed the complete payload and returned checksum success. Older-version and corrupted-header rejection checks also passed.
- Python source compilation.

The NFC peripheral, clocks and transport are simulated in the emulator. These checks do not establish successful NFC communication with Apple Wallet or physical boot.

## Hardware preflight

Connected to the existing D110_M target. Model `0910`, firmware `041f`, hardware `0401`, battery `04`, roll response `00`. Hardware install and Wallet observations are recorded separately below when available.

## Hardware results: success

- The guarded updater uploaded 609 chunks. The printer acknowledged its checksum check and successful commit, rebooted, and reconnected.
- Capability command `F2 00` returned Wallet protocol v1 status `10` from the installed image.
- The owner's presented iPhone returned a valid contactless payment directory after nine polling attempts. Label `MASTERCARD`, AID `A0000000041010`, application priority `01`, SELECT status `9000`.
- A second session directly selected that advertised AID and returned the application's FCI and `9000`. It included label `MASTERCARD`, language preference `en`, PDOL bytes `9F1D089F1A02`, and additional card-supplied FCI fields.
- Both sessions reported ATQA `0400`, SAK `20`, ATS `0578807002`. The four-byte UID differed between the two sessions; it is not a stable identity credential.
- Captures remain private and are not included in this repository. They include timestamps, unsuccessful attempts, raw SELECT responses and decoded TLVs. They have not been published.

This proves two-way ISO14443-A/ISO-DEP application-metadata reading from the presented Wallet card with this printer. It does not establish access to a PAN/Device Account Number, cardholder name, transaction history, other Wallet cards, or Apple VAS passes. No GPO, GENERATE AC or payment authorization was sent. No label-print regression was performed after this installation.
