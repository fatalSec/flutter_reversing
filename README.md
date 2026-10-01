# flutter_reversing

Sample apps and Frida scripts used in the **FatalSec** series on reverse engineering Flutter applications.

The repo pairs each target binary with the script used against it in the corresponding video. Flutter compiles Dart to native code in `libapp.so`, so these scripts work at the native (ARM64) level — hooking functions by offset, walking the Dart heap to dump tagged objects, and patching TLS verification inside `libflutter.so`.

> **Note on offsets:** the hook addresses in the scripts (`fn_addr`, the `session_verify_cert_chain` offset) are specific to the exact binaries in this repo. For your own targets you'll need to recompute them.
> 

---

## Videos & files

| Video | Script(s) | Target app(s) | What it covers |
| --- | --- | --- | --- |
| https://youtu.be/lQSBpEJbJaY | `authpass_cert_bypass.js` | `authpass-pinned-unsigned.ipa` | Bypassing SSL/TLS pinning in an iOS Flutter app by analyzing `App.framework` directly using `r2flutter` plugin inside `radare`. |
| https://youtu.be/0uUSwMg2suk | `funnybones_frida.js` | `funnybones.apk`, `funnybones_obf.apk` | Dealing with an obfuscated Flutter app by resolving Dart Object Pool indirections. Covers DartVM internals — Snapshots and Isolates — and how the Dart Object Pool works, the key component for making sense of an obfuscated app and for dumping Dart objects from `libapp.so`. |
| https://youtu.be/Pw4_lepwVEs | `flutter_obf_frida.js`, `AES_decrypt.py` | `news.apk`, `news_enc_obf.apk` | **I**ntercepting & decrypting encrypted traffic from an obfuscated Flutter app. Reverse engineering the Flutter app, bypassing certificate pinning, analyzing encrypted API requests/responses, and dumping the AES key (via the Dart object dumper) to decrypt the data with `AES_decrypt.py`. |
|  |  |  |  |

---

## Files

**Sample apps**

- `funnybones.apk` — baseline (non-obfuscated) Flutter app.
- `funnybones_obf.apk` — obfuscated build of the same app.
- `news.apk` — baseline Flutter news app.
- `news_enc_obf.apk` — encrypted + obfuscated build.
- `authpass-pinned-unsigned.ipa` — iOS build with SSL pinning (unsigned), for the pinning-bypass demo using r2flutter.

---

## Tools

- Blutter
    - https://github.com/worawit/blutter
- **r2flutter**
    - https://github.com/radareorg/r2flutter

---

## ⚠️ Disclaimer

These materials are for **educational and authorized security research only**. The sample apps are included as targets for the FatalSec reversing videos. Only analyze applications you own or are explicitly permitted to test.

---
