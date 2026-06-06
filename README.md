# ZWC Steganography — Run Instructions

This repository contains baseline and enhanced Zero-Width Character (ZWC) text steganography tools and an attack toolkit.

**Prerequisites:**
- Python 3.8+ (3.10 recommended)
- Git (if cloning from remote)

**Files of interest:** [enhanced_zwc_stego.py](enhanced_zwc_stego.py), [original_zwc_stego.py](original_zwc_stego.py), [zwc_attack_toolkit.py](zwc_attack_toolkit.py), [requirements.txt](requirements.txt)

**Quick Start — From scratch (clone + run)**

1. Clone the repository:

```bash
git clone <repo-url> zwc-project
cd zwc-project
```

2. Create and activate a virtual environment:

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```bash
pip install -r requirements.txt
# Optional: for AES support (recommended)
pip install pycryptodome
```

**Quick Start — Already cloned**

If you already have the repository locally, start at step 2 above (create/activate venv and install dependencies).

**Run the tools (examples)**

- Baseline embed:

```bash
python3 original_zwc_stego.py embed --cover cover.txt --secret "Hello world" --output stego.txt
```

- Baseline extract:

```bash
python3 original_zwc_stego.py extract --stego stego.txt
```

- Enhanced embed (encryption + permutation):

```bash
python3 enhanced_zwc_stego.py embed --cover cover.txt --secret "Secret msg" --passkey "MyKey123!" --output stego_enhanced.txt
```

- Enhanced extract:

```bash
python3 enhanced_zwc_stego.py extract --stego stego_enhanced.txt --passkey "MyKey123!"
```

- Attack toolkit (examples):

```bash
# Scan for ZWC characters
python3 zwc_attack_toolkit.py scan --file stego.txt

# Statistical analysis
python3 zwc_attack_toolkit.py stats --file stego.txt

# Strip (remove ZWC characters)
python3 zwc_attack_toolkit.py strip --file stego.txt --output clean.txt

# Inject noise
python3 zwc_attack_toolkit.py noise --file stego.txt --output noisy.txt --density 0.5

# Brute-force passkey (uses wordlist or built-in list)
python3 zwc_attack_toolkit.py brute --file stego_enhanced.txt --wordlist wordlist.txt
```

**Notes & Troubleshooting**

- AES support: the enhanced tool uses PyCryptodome when available. If it's not installed the code falls back to a weaker XOR method and prints a warning. Install `pycryptodome` for full AES-256-CBC support.
- Encoding: all scripts read/write UTF-8. If you see garbled output, ensure files are UTF-8 encoded.
- Permissions: ensure you have write permission for output paths.
- Short cover text: both embed tools will warn if the cover text is too short to contain the full payload — use a longer `--cover` file.

**Developer tips**

- Run a single example and inspect the output files in a text editor that can show invisible characters (or use the attack toolkit `scan` command).
- To reproduce results in CI, use the same Python version and install `requirements.txt` into the environment.

If you want, I can:
- Add a small example script that runs a complete embed→extract roundtrip, or
- Add a `Makefile` or `invoke` tasks for common flows.
