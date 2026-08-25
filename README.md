# SCEPMutator

A scriptable SCEP message forge and cross-implementation differential harness.

SCEPMutator builds SCEP messages from the PKCS#10 up through the CMS `EnvelopedData` and `SignedData` with the SCEP authenticated attributes, giving full control over every layer a normal client hides. It is meant for testing SCEP server implementations against each other: mismatched signer keys, broken proof-of-possession, hand-crafted PKCS#1 v1.5 padding, malformed ASN.1, and so on. It auto-adapts transport (POST vs GET+base64) and algorithms from each server's advertised `GetCACaps`.

It was written for the research in [Five SCEP Servers, One Harness](https://cbev0x.github.io), a differential characterization across NDES, EJBCA, Dogtag, OpenXPKI, and micromdm/scep.

## Install

Requires Python 3.9+ and three packages:

```bash
pip install requests cryptography asn1crypto
```

Two files, kept together: `scepmutator.py` (CLI) and `scep_core.py` (the SCEP/CMS protocol library). No install step; run it in place.

```bash
git clone https://github.com/cbev0x/SCEPMutator
cd SCEPMutator
python3 scepmutator.py --help
```

## Usage

Global flags (`-debug`, `-ts`, `-no-color`) go before the subcommand. Every subcommand takes `-u <url>` for the SCEP endpoint and `-name <label>` for readable output.

```bash
python3 scepmutator.py [-debug] <subcommand> -u <url> [options]
```

### Subcommands

| Command | Purpose |
|---|---|
| `getcaps` | `GetCACaps` capability advertisement |
| `getca` | `GetCACert` CA/RA certificate bundle |
| `baseline` | read-only sweep across all targets into one grid |
| `enroll` | `PKCSReq` enrollment, conformant or with mutation flags |
| `renew` | renewal via `PKCSReq` signed by an existing cert (cross-CA confusion probe) |
| `poll` | `GetCertInitial` polling authorization (poll as a non-originator) |
| `getcert` | `GetCert` retrieval by issuer+serial (enumeration probe) |
| `fuzz` | malformation corpus against the CMS/DER body (`-deep` for the heavy cases) |
| `router` | fuzz the request router: operations and parameters, not the CMS body |
| `downgrade` | send algorithms the server advertises as absent |
| `headers` | proxy-trust header injection (does the origin honor attacker-set headers) |
| `admin` | probe the NDES `mscep_admin` challenge-generation endpoint |
| `race` | concurrency race on the enrollment state machine |
| `oracle` | PKCS#1 v1.5 padding-oracle differential (Bleichenbacher/ROBOT) |
| `selftrust` | CA-cert-as-signer confusion and self-subject (CA-DN) issuance |

### Examples

Conformant enrollment, saving the issued cert and key:

```bash
python3 scepmutator.py enroll \
  -u http://ndes.example.com/certsrv/mscep/mscep.dll \
  -cn device01.example.com -challenge <OTP> \
  -o issued.pem -save-key issued.key
```

Break the inner proof-of-possession (submit a CSR for a key you do not hold):

```bash
python3 scepmutator.py enroll -u <url> -cn probe01 -challenge <c> \
  -mutate csr-nopop
```

Padding-oracle differential, twelve reps per variant for a clean timing median:

```bash
python3 scepmutator.py oracle -u <url> -cn probe01 -challenge <c> -reps 12
```

Malformation fuzzing with the deep corpus (extreme nesting, integer-overflow lengths, intra-CMS corruption):

```bash
python3 scepmutator.py fuzz -deep -u <url> -cn probe01 -challenge <c>
```

Cross-CA renewal confusion (renew server A using a credential server B issued):

```bash
python3 scepmutator.py renew -u <server-A-url> \
  -cert cred-from-B.pem -key cred-from-B.key -cn probe01
```

### enroll mutation flags

The `enroll` subcommand's `-mutate` option applies a single-stage mutation so a differential isolates what each server checks:

- `signer-key-mismatch`: sign the outer CMS with a key that does not match the enclosed signer certificate (outer-signature check)
- `csr-nopop`: inner CSR carries a public key you do not control, with an invalid self-signature (inner proof-of-possession check)
- `full-nopop`: both the outer signature and the inner self-signature are broken

## Notes

- Output uses an impacket-style logger (`[*]`, `[+]`, `[-]`, `[!]`). Add `-json` to most subcommands for machine-readable output.
- Single-use challenge servers (NDES OTP, Dogtag flatfile PIN) consume the challenge per request; refresh it between runs.
- This is a testing tool for systems you are authorized to test. It forges authentication material and sends malformed input on purpose.

## License

MIT. See `LICENSE`.
