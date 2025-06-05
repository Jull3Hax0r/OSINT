
# 🕵️ OSINT Intelligence Tool

![OSINT](https://img.shields.io/badge/Category-OSINT-blue.svg)
![Whitehat](https://img.shields.io/badge/Use-Whitehat-green.svg)
![Python](https://img.shields.io/badge/Made%20with-Python-FFD43B.svg)

A powerful multi-source OSINT (Open Source Intelligence) tool designed to gather public information based on **email address**, **username**, or **real name**. Useful for cybersecurity research, red teaming, or CTFs.

> © 2025 - https://jull3.se
<img src="https://jull3.se/demo.png">

---

## 📦 Installation

First, clone the repo and install the required Python dependencies:

```bash
pip install -r requirements.txt
```

<details>
<summary>requirements.txt</summary>

```text
requests
beautifulsoup4
colorama
```

</details>


---

## 🧪 Recommended: Run in a Virtual Environment

To keep your Python dependencies isolated, i  recommend using a `venv`:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate it (Linux/macOS)
source venv/bin/activate

# On Windows (CMD)
venv\Scripts\activate.bat

# Then install dependencies
pip install -r requirements.txt
```

To deactivate the environment when you're done:

```bash
deactivate
```


## 🚀 Usage

```bash
# Basic search
python osint_tool.py -q "john.doe@example.com"

# Social media only
python osint_tool.py -q "johndoe" -t social

# Full search with export
python osint_tool.py -q "John Doe" -t all -o results.json

# No banner
python osint_tool.py -q "target" --no-banner
```

---

## 🎯 Search Strategies

### 🔐 For email:
- Domain analysis and validation
- Common vendor detection
- Breach lookup reference (manual via HIBP)

### 👤 For username:
- Profile discovery (Twitter, Facebook, Instagram, LinkedIn)
- GitHub repositories & follower count
- Pastebin and public web exposure

### 🧑‍💼 For name:
- LinkedIn name-based search
- GitHub activity correlation
- General web visibility using DuckDuckGo

---

## ⚠️ Ethics Guidelines

This tool is intended for **legitimate cybersecurity use** only.

By using it, you agree to:
- Respect privacy of individuals
- Validate all data manually
- Use the tool **responsibly** and **legally**

---

## 💬 License

MIT License  
Maintained by [Jull3Hax0r](https://jull3.se)
