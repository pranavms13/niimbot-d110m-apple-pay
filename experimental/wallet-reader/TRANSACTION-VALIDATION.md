# Local transaction experiment validation — 2026-10-26

Image: `build/wallet-transaction/D110_M_V4.31_wallet-transaction_EXPERIMENTAL.bin`

SHA-256: `31d2819cdca1aad3d8abb840c55144ae02ef05e2b7f9702459ae87bb5d7bdb57`

Complete size: 122,972 bytes. Wallet extension: 4,996 bytes. Hash-pinned refill base remains `c320111084d1199d6947e704212a7d8b98d14171cd4352931b0ada90e7a40635`.

## Offline verification passed

- Warning-free Cortex-M0 compilation; no unresolved code relocations or separate data allocation; container CRC/model/version and staging capacity checks.
- Prior image bytes unchanged except the dispatch hook. Prior refill capability and SELECT regression tests passed.
- Compiled ARM executes SELECT → GPO → READ RECORD → one GENERATE AC in one simulated RF session, with persistent block numbering. Exact amount, currency, date, challenge, DOL contents and requested ARQC are checked against independent expected byte strings.
- Both response formats and AAC, TC and ARQC outcomes are decoded without claiming issuer authorization.
- 16-byte FSC command chaining and long-record response chaining; no synthetic PAN sentinel exported in the response.
- Lost, declined and malformed cryptogram replies stop after one GENERATE AC. GPO-returned cryptograms stop without GENERATE AC. Invalid/oversized AFL, missing CDOL, unknown DOL fields, timeouts and parser errors are exercised.
- Host tests prove no retry following GPO, GENERATE AC, SELECT failure, malformed/ambiguous response, or a transport timeout. Only explicit pre-application no-response observations are retried.
- Memory-write guards, forbidden persistence/tag-write calls, output canaries and a two-KiB stack bound pass.
- Stock update receiver simulation accepted all 615 chunks, reconstructed the exact image and acknowledged checksum success; old-version/corrupted-header rejection checks passed.
- Python compilation passed.

These are emulator and software results. Cryptograms are not cryptographically verified. NFC peripherals, timing and transport are simulated; physical results are recorded separately.

## Hardware preflight

The specific D110_M responded with model `0910`, firmware `041f`, hardware `0401`, battery `04`, and no roll (`00`). The user confirmed USB power and readiness to present their own Wallet Mastercard for a fixed INR 1.00 local experiment.

## First hardware run and correction

The initial transaction image (`8c2b6455a24e943dad7b8ca2883c62ca0a50d210a83aed77084867f8ce340c9a`) installed successfully. The first run selected Mastercard, completed GPO and read all six AFL records. It reached GENERATE AC, then stopped with a frame-validation error and no cryptogram. It did not retry. The owner reported that Wallet stayed on the card screen. No transaction was submitted. Raw captures remain private.

The returned AFL was `0801010010010501`; CDOL1 requested 73 data bytes. This made GENERATE AC the first long outgoing APDU in the physical test. Investigation found a mistaken assumption in the reader and original mock: a PICC R(ACK) for a chained outgoing I-block echoes that block's current number; the reader must accept that number and then toggle. The original code incorrectly expected the toggled number. The current candidate repairs that check. A new regression uses the observed CDOL/AFL and six synthetic records, verifies the full 79-byte GENERATE AC exchange, and rejects the previously expected wrong ACK.

The current response adds eight non-payload frame-diagnostic bytes (reason, last TX/RX PCB, TX/RX length, expected block number, transfer phase, frame index). These do not expose record contents. They allow future RF failures to be distinguished without repeating a transaction merely to guess at its cause.

## Corrected hardware run: success

The exact corrected image identified at the top installed successfully, with the printer acknowledging checksum and commit. It was powered off after the update; the owner turned it back on. An initial Bluetooth connection attempt while it was off sent no transaction command and created no transaction capture.

The subsequent run completed a single local INR 1.00 attempt:

- Nine APDUs: Mastercard SELECT, GPO, six AFL record reads, one GENERATE AC requesting ARQC.
- The long GENERATE AC was sent in two I-blocks. The final frame diagnostic showed 19 transmitted bytes, 46 received bytes, matching block numbers and no frame error.
- Reply status `9000`, CID `80`, parsed **ARQC (online authorization request)**, an application transaction counter, eight-byte cryptogram and issuer application data.
- Four DOL fields (`9F45`, `9F4C`, `9F15`, `9F4E`) were zero-filled as documented; the amount, currency, country, date and unpredictable number were supplied explicitly.
- The owner confirmed that Wallet showed a checkmark or played the payment sound during this successful second test. This UI observation is separate from the captured protocol evidence.
- No transaction was submitted to a processor/issuer, no issuer authorization was obtained, and no second GENERATE AC was sent. The returned ARQC was not cryptographically verified.

The private local capture includes the exact request parameters, timestamps, waiting observations and final response. It has not been uploaded or published. Post-install label printing was not exercised; prior SELECT/refill dispatch behavior passed offline regression tests.
