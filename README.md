# FTP Client Desktop

A two-panel FTP client with a graphical interface built with Python + PySide6. The FTP protocol is implemented over raw TCP sockets, without third-party FTP libraries.

## Features

- Two-panel interface: local and remote file systems, sortable columns
- LIST, RETR, STOR, DELE, MKD/RMD, CWD/CDUP, PWD, RNFR/RNTO, SIZE, TYPE I/A
- Passive mode (PASV), transfer progress, drag & drop from the file explorer
- Connection profiles with encrypted passwords (Fernet)
- Collapsible log of FTP commands

## Usage

```bash
pip install -r requirements.txt
python main.py
```

Or use the script: `run.bat` (Windows) / `./run.sh` (Linux/macOS) — it creates a venv and installs dependencies automatically.

## Tests

```bash
python -m pytest test_ftp_protocol.py -v
```

## Project structure

| File | Description |
|------|-------------|
| `main.py` | GUI application (PySide6) |
| `ftp_protocol.py` | FTP protocol client (sockets) |
| `test_ftp_protocol.py` | Protocol unit tests |

## License

[MIT](LICENSE)
