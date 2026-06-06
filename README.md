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

**Plan of Attack:**

| Action                                  | Short Workflow                                                                                         |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **1. ZWC Scanner (Passive)**            | Input stego text → Scan for invisible characters → Count ZWC → Detect hidden message                   |
| **2. Statistical Analysis (Passive)**   | Extract ZWC characters → Calculate frequency → Analyze pattern → Identify encoding type                |
| **3. Raw Bit Extraction (Passive)**     | Read ZWC symbols → Convert to bits (0/1) → Group into bytes → Recover hidden text                      |
| **4. Known-Key Decoder (Passive)**      | Input passkey → Verify HMAC → Decrypt payload → Reveal secret message                                  |
| **5. Strip Attack (Active)**            | Read stego text → Remove all ZWC characters → Save clean text → Hidden message destroyed               |
| **6. Noise Injection Attack (Active)**  | Read stego text → Insert random ZWC characters → Corrupt bit sequence → Extraction fails               |
| **7. Substitution Attack (Active)**     | Replace original ZWC symbols with different ZWC → Change bit values → Message becomes unreadable       |
| **8. HMAC Brute-Force (Active)**        | Load wordlist → Try passkeys one by one → Check HMAC → Find correct key if weak                        |
| **9. Permutation Brute-Force (Active)** | Test passkey candidates → Reverse symbol permutation → Attempt decoding → Recover message if key found |

**Run the tools (examples)**

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

**Streamlit Web UI**

This repository includes a Streamlit-based UI (`streamlit_app.py`) that provides a friendly interface for scanning, analyzing, and attacking ZWC stego text.

1. Run the web app:

```bash
streamlit run streamlit_app.py
```

2. Open the URL printed by Streamlit (usually http://localhost:8501) in your browser.

**Quick tips**

- Upload a `stego.txt` file or paste text into the sidebar to begin.
- Use the centered "Run" button to execute the selected action.
- For brute-force runs, uploading a `wordlist.txt` is recommended to avoid using the built-in test list.

**Notes & Troubleshooting**

- AES support: the enhanced tool uses PyCryptodome when available. If it's not installed the code falls back to a weaker XOR method and prints a warning. Install `pycryptodome` for full AES-256-CBC support.
- Encoding: all scripts read/write UTF-8. If you see garbled output, ensure files are UTF-8 encoded.
- Permissions: ensure you have write permission for output paths.
- Short cover text: both embed tools will warn if the cover text is too short to contain the full payload — use a longer `--cover` file.
