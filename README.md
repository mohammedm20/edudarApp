# 🎓 Edudar Web Installer (Bootstrapper)

Official lightweight open-source web installer and bootstrapper for the **Edudar** suite.

## 🚀 Features
- **Ultra-lightweight:** Compact native Windows executable (~1.5 MB).
- **Cryptographically Secure:** Verifies SHA-256 and Ed25519 digital signatures before execution.
- **Fast & Resilient:** Automatic failover, streaming progress, and native Win32 UI.
- **Dual-Language:** Clean Arabic and English interface.

## 🛠️ Building
To build locally:
```bash
cargo build --release
```
The compiled output will be available at `target/release/edudar-installer.exe` (or `EdudarSetup.exe`).

## 📄 License
MIT License. Copyright (c) 2026 Edudar.
