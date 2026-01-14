
# QuantumAuth Client
![Powered by QuantumAuth](https://img.shields.io/badge/Powered%20By-QuantumAuth-1a1a1a?style=for-the-badge&logo=dependabot)

[![Release](https://img.shields.io/github/v/release/quantumauth-io/quantum-auth-client)](https://github.com/quantumauth-io/quantum-auth-client/releases)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

The **QuantumAuth Client** is a lightweight, open-source system agent that provides **device-bound authentication** using secure hardware such as **TPM** (with Secure Enclave support coming soon).  
It runs locally on the user’s device and manages a unique cryptographic identity used to sign requests and authenticate with QuantumAuth-enabled applications.

The client handles:

- Device registration
- Hardware-backed key generation
- Local signing of authentication requests
- Secure communication with the QuantumAuth backend



### TPM / Secure Hardware Support

- Linux + Windows use TPM 2.0 for hardware-backed keys
- macOS Secure Enclave support is in development
- If no secure hardware is available, the client automatically falls back to software keys

### Development

You will need an Infura api key in your environment

```
QA_ENV=local   // for local development
QA_ENV=develop // for the development environment

QA_ENV=        // if not set it will default to prod
```



## 📦 Installation

### Linux

Creates the standard directory where APT stores trusted repository signing keys.
```bash
sudo install -d -m 0755 /etc/apt/keyrings
```
Downloads the QuantumAuth APT repository public signing key and installs it for package verification.
```bash
curl -fsSL https://apt.quantumauth.io/keyrings/quantumauth.gpg \
| sudo tee /etc/apt/keyrings/quantumauth.gpg > /dev/null
```
Registers the QuantumAuth APT repository as a trusted package source for amd64 and arm64 systems.
```bash
echo "deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/quantumauth.gpg] https://apt.quantumauth.io stable main" \
| sudo tee /etc/apt/sources.list.d/quantumauth.list > /dev/null
```
Refreshes the package index and installs the QuantumAuth client from the signed repository.
```bash
sudo apt update
sudo apt install quantum-auth-client
```
Verifies the installation and prints the installed client version, commit, and build date.
```bash
quantumauth --version
```


## 🛡 Security

Please report vulnerabilities to:

**security@quantumauth.io**

---

## 📄 License

**Apache 2.0**

```bash
go run ./cmd/quantum-auth-client
```


## 💖 Sponsors

QuantumAuth is an independent, open-source project focused on building modern, hardware-rooted authentication for developers and users everywhere.  
Your sponsorship helps fund ongoing development, security research, cross-platform clients, and long-term maintenance.

### 🙌 Thank you to our supporters

We are deeply grateful to everyone who helps sustain this project.  
If you rely on QuantumAuth or believe in our mission, please consider becoming a sponsor.

👉 **Become a sponsor:** https://github.com/sponsors/quantumauth-io

---

### 🏆 Project Sponsors

<!-- YOUR SPONSORS WILL APPEAR AUTOMATICALLY HERE -->

This section will list the names or logos of organizations and individuals who sponsor QuantumAuth at the *Project Sponsor* tier and above.

If you'd like to be featured here, please visit our Sponsor page!



🏛 Attribution

This project uses QuantumAuth — Post-Quantum Authentication System
Created by Ian Dorion (Madeindreams)

Please retain the following attribution in any public product, documentation, or service:

