"""
FTP Protocol Module - Low-level FTP implementation using TCP sockets.
Supports commands: LIST, GET, PUT, DELETE, MKDIR, CWD, PWD, CDUP
"""

import socket
import os
import re
import ssl
from typing import Optional, Callable, List, Tuple
from dataclasses import dataclass
from enum import Enum


class TransferMode(Enum):
    ACTIVE = "active"
    PASSIVE = "passive"


@dataclass
class FTPFile:
    """Represents a file or directory on the FTP server."""
    name: str
    is_dir: bool
    size: int
    modified: str
    permissions: str

    def __lt__(self, other):
        # Directories first, then alphabetically
        if self.is_dir != other.is_dir:
            return self.is_dir > other.is_dir
        return self.name.lower() < other.name.lower()


class FTPError(Exception):
    """Custom FTP exception."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"FTP Error {code}: {message}")


class FTPClient:
    """
    FTP Client implementation using raw TCP sockets.
    Supports both active and passive mode for data transfers.
    """

    # FTP Response Codes
    CODE_SERVICE_READY = 220
    CODE_PASSWORD_REQUIRED = 331
    CODE_LOGIN_SUCCESS = 230
    CODE_FILE_STATUS_OK = 150
    CODE_TRANSFER_COMPLETE = 226
    CODE_PASSIVE_MODE = 227
    CODE_PATHNAME_CREATED = 257
    CODE_FILE_ACTION_OK = 250
    CODE_PWD = 257
    CODE_CWD_OK = 250
    CODE_DELETE_OK = 250
    CODE_MKDIR_OK = 257

    def __init__(self,
                 host: str,
                 port: int = 21,
                 timeout: float = 30.0,
                 encoding: str = 'utf-8',
                 use_ssl: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.encoding = encoding
        self.use_ssl = use_ssl

        # Control connection
        self.control_socket: Optional[socket.socket] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.welcome_message: str = ""

        # Transfer mode
        self.transfer_mode = TransferMode.PASSIVE

        # Callbacks for progress reporting
        self.on_progress: Optional[Callable[[int, int], None]] = None
        self.on_log: Optional[Callable[[str], None]] = None

        # Connection state
        self._connected = False
        self._authenticated = False

    @property
    def is_connected(self) -> bool:
        return self._connected and self.control_socket is not None

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def _log(self, message: str):
        if self.on_log:
            self.on_log(message)

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def _send_command(self, command: str) -> Tuple[int, str]:
        if not self.control_socket:
            raise FTPError(0, "Not connected to server")

        self._log(f">>> {command}")
        try:
            self.control_socket.sendall((command + "\r\n").encode(self.encoding))
        except ssl.SSLError as e:
            raise FTPError(0, f"SSL/Connection error during send: {e}")

        response = self._receive_response()
        self._log(f"<<< {response}")

        code_match = re.match(r'^(\d{3})[-\s]?', response)
        if not code_match:
            raise FTPError(0, f"Invalid response format: {response}")

        code = int(code_match.group(1))
        message = response[3:].lstrip('- ').strip()

        return code, message

    def _receive_response(self) -> str:
        """
        Safely receive a complete FTP response, correctly handling
        multi-line FileZilla Server welcome banners.
        """
        response = b""
        while True:
            try:
                chunk = self.control_socket.recv(4096)
            except ssl.SSLError as e:
                raise FTPError(0, f"SSL Error receiving response: {e}")

            if not chunk:
                break
            response += chunk

            decoded = response.decode(self.encoding, errors='ignore')

            # Process only if we hit a newline (end of response part)
            if '\n' in decoded:
                lines =[line.replace('\r', '') for line in decoded.split('\n')]
                # Remove empty trailing strings after final \n
                if lines and not lines[-1]:
                    lines.pop()

                if not lines:
                    continue

                first_line = lines[0]
                code_match = re.match(r'^(\d{3})', first_line)

                if code_match:
                    code = code_match.group(1)

                    # FileZilla Multi-line checking
                    if first_line.startswith(code + '-'):
                        # Multi-line string ends with "CODE Space"
                        if len(lines) > 1 and lines[-1].startswith(code + ' '):
                            return decoded.strip()
                    else:
                        # Single line ends immediately
                        return decoded.strip()

        return response.decode(self.encoding, errors='ignore').strip()

    def _parse_passive_response(self, response: str) -> Tuple[str, int]:
        match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response)
        if not match:
            raise FTPError(0, "Invalid PASV response")

        groups = match.groups()
        ip = f"{groups[0]}.{groups[1]}.{groups[2]}.{groups[3]}"
        port = int(groups[4]) * 256 + int(groups[5])

        # FileZilla NAT IP workaround
        def is_private(ip_str):
            try:
                parts = [int(p) for p in ip_str.split('.')]
                if len(parts) != 4: return False
                if parts[0] == 10: return True
                if parts[0] == 172 and 16 <= parts[1] <= 31: return True
                if parts[0] == 192 and parts[1] == 168: return True
                if parts[0] == 127: return True
                if ip_str == "0.0.0.0": return True
                return False
            except ValueError:
                return False

        if is_private(ip):
            self._log(f"Server returned private IP {ip}, using actual host {self.host} instead.")
            ip = self.host

        return ip, port

    def _open_data_connection(self) -> socket.socket:
        """
        Open a raw TCP data connection. SSL wrapping will happen LATER,
        after the FTP server responds with 150 (FileZilla requirement).
        """
        if self.transfer_mode == TransferMode.PASSIVE:
            code, response = self._send_command("PASV")
            if code != self.CODE_PASSIVE_MODE:
                raise FTPError(code, response)

            ip, port = self._parse_passive_response(response)
            data_socket = self._create_socket()
            data_socket.connect((ip, port))
            return data_socket
        else:
            raise FTPError(0, "Active mode not implemented")

    def _wrap_data_socket(self, data_socket: socket.socket) -> socket.socket:
        """
        Wrap data connection with SSL/TLS and reuse Session.
        Must be called ONLY after receiving 150 response to prevent deadlocks.
        """
        if self.use_ssl and self.ssl_context:
            # FileZilla Server strictly demands session resumption for data channel
            session = getattr(self.control_socket, 'session', None)
            try:
                data_socket = self.ssl_context.wrap_socket(
                    data_socket,
                    server_hostname=self.host,
                    session=session
                )
            except ssl.SSLError as e:
                data_socket.close()
                raise FTPError(0, f"SSL Data channel error: {e}")
        return data_socket

    def connect(self) -> str:
        self._log(f"Connecting to {self.host}:{self.port}...")

        self.control_socket = self._create_socket()
        self.control_socket.connect((self.host, self.port))

        response = self._receive_response()
        self._log(f"<<< {response}")

        code_match = re.match(r'^(\d{3})', response)
        if not code_match:
            self.control_socket.close()
            self.control_socket = None
            raise FTPError(0, f"Invalid response format: {response}")

        code = int(code_match.group(1))
        if code != self.CODE_SERVICE_READY:
            self.control_socket.close()
            self.control_socket = None
            raise FTPError(code, response)

        self.welcome_message = response
        self._connected = True

        if self.use_ssl:
            self._upgrade_to_ssl()

        return self.welcome_message

    def _upgrade_to_ssl(self):
        self._log(">>> AUTH TLS")
        self.control_socket.sendall(b"AUTH TLS\r\n")

        response = self._receive_response()
        self._log(f"<<< {response}")

        code_match = re.match(r'^(\d{3})', response)
        if not code_match:
            raise FTPError(0, f"Invalid AUTH response: {response}")

        code = int(code_match.group(1))
        if code != 234:
            self._log(">>> AUTH SSL")
            self.control_socket.sendall(b"AUTH SSL\r\n")
            response = self._receive_response()
            self._log(f"<<< {response}")
            code_match = re.match(r'^(\d{3})', response)
            if code_match and int(code_match.group(1)) != 234:
                raise FTPError(code, f"SSL/TLS negotiation failed: {response}")

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self.control_socket = self.ssl_context.wrap_socket(
            self.control_socket,
            server_hostname=self.host
        )

        self._log("Control channel SSL/TLS established")

        self._log(">>> PBSZ 0")
        self.control_socket.sendall(b"PBSZ 0\r\n")
        response = self._receive_response()
        self._log(f"<<< {response}")

        self._log(">>> PROT P")
        self.control_socket.sendall(b"PROT P\r\n")
        response = self._receive_response()
        self._log(f"<<< {response}")

        self._log("Data channel protection enabled")

    def login(self, username: str = "anonymous", password: str = "") -> str:
        if not self.is_connected:
            raise FTPError(0, "Not connected")

        code, response = self._send_command(f"USER {username}")

        if code == self.CODE_LOGIN_SUCCESS:
            self._authenticated = True
            return response

        if code == self.CODE_PASSWORD_REQUIRED:
            code, response = self._send_command(f"PASS {password}")
            if code != self.CODE_LOGIN_SUCCESS:
                raise FTPError(code, response)

            self._authenticated = True
            return response

        raise FTPError(code, response)

    def disconnect(self):
        if self.control_socket:
            try:
                self._send_command("QUIT")
            except:
                pass
            finally:
                self.control_socket.close()
                self.control_socket = None

        self._connected = False
        self._authenticated = False
        self._log("Disconnected")

    def pwd(self) -> str:
        code, response = self._send_command("PWD")
        if code != self.CODE_PWD:
            raise FTPError(code, response)
        match = re.search(r'"([^"]+)"', response)
        if match:
            return match.group(1)
        return response

    def cwd(self, directory: str) -> str:
        code, response = self._send_command(f"CWD {directory}")
        if code != self.CODE_CWD_OK:
            raise FTPError(code, response)
        return response

    def cdup(self) -> str:
        code, response = self._send_command("CDUP")
        if code != self.CODE_CWD_OK:
            raise FTPError(code, response)
        return response

    def list(self, directory: str = "") -> List[FTPFile]:
        data_socket = self._open_data_connection()
        try:
            cmd = f"LIST {directory}" if directory else "LIST"
            code, response = self._send_command(cmd)

            if code not in (self.CODE_FILE_STATUS_OK, 125, 150):
                raise FTPError(code, response)

            # FileZilla requirement: Data SSL Handshake AFTER 150 response is triggered
            data_socket = self._wrap_data_socket(data_socket)

            data = b""
            while True:
                try:
                    chunk = data_socket.recv(8192)
                except ssl.SSLZeroReturnError:
                    break
                if not chunk:
                    break
                data += chunk

            data_socket.close()
            response = self._receive_response()
            self._log(f"<<< {response}")

            return self._parse_list_response(data.decode(self.encoding, errors='ignore'))

        except FTPError:
            if data_socket:
                try: data_socket.close()
                except: pass
            raise
        except Exception as e:
            if data_socket:
                try: data_socket.close()
                except: pass
            raise FTPError(0, str(e))

    def _parse_list_response(self, listing: str) -> List[FTPFile]:
        """
        Advanced Regex parser for handling irregular ProFTPd and FileZilla directory output.
        """
        files =[]
        for line in listing.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Windows/IIS Server output: 01-01-24  12:00PM  <DIR>  dirname
            win_match = re.search(
                r'^(\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}(?:AM|PM))\s+(<DIR>|\d+)\s+(.+)$',
                line, re.IGNORECASE
            )
            if win_match:
                modified, size_or_dir, name = win_match.groups()
                is_dir = size_or_dir.upper() == '<DIR>'
                size = 0 if is_dir else int(size_or_dir)
                if name.strip() not in ('.', '..'):
                    files.append(FTPFile(
                        name=name.strip(), is_dir=is_dir, size=size,
                        modified=modified, permissions=""
                    ))
                continue

            # UNIX/FileZilla Server output: drwxr-xr-x 1 ftp ftp 0 Feb 28 11:34 myfolder
            unix_match = re.search(
                r'^([dcb\-lps][rwxsStT\-]{9})\s+.*?\s+(\d+)\s+([a-zA-Z]{3}\s+\d+\s+[\d:]+)\s+(.+)$',
                line
            )
            if unix_match:
                perms, size_str, modified, name = unix_match.groups()
                is_dir = perms.startswith('d')
                size = int(size_str)
                if name.strip() not in ('.', '..'):
                    files.append(FTPFile(
                        name=name.strip(), is_dir=is_dir, size=size,
                        modified=modified, permissions=perms
                    ))
                continue

        return sorted(files)

    def download_file(self,
                      remote_path: str,
                      local_path: str,
                      progress_callback: Optional[Callable[[int, int], None]] = None) -> int:
        data_socket = self._open_data_connection()
        try:
            self._send_command("TYPE I")
            code, response = self._send_command(f"RETR {remote_path}")

            if code not in (self.CODE_FILE_STATUS_OK, 125, 150):
                raise FTPError(code, response)

            # Data SSL Handshake
            data_socket = self._wrap_data_socket(data_socket)

            downloaded = 0
            with open(local_path, 'wb') as f:
                while True:
                    try:
                        chunk = data_socket.recv(8192)
                    except ssl.SSLZeroReturnError:
                        break
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if progress_callback:
                        progress_callback(downloaded, -1)

            data_socket.close()
            response = self._receive_response()
            self._log(f"<<< {response}")

            return downloaded

        except FTPError:
            if data_socket:
                try: data_socket.close()
                except: pass
            if os.path.exists(local_path):
                os.remove(local_path)
            raise
        except Exception as e:
            if data_socket:
                try: data_socket.close()
                except: pass
            if os.path.exists(local_path):
                os.remove(local_path)
            raise FTPError(0, str(e))

    def upload_file(self,
                    local_path: str,
                    remote_path: str,
                    progress_callback: Optional[Callable[[int, int], None]] = None) -> int:
        data_socket = self._open_data_connection()
        try:
            self._send_command("TYPE I")
            code, response = self._send_command(f"STOR {remote_path}")

            if code not in (self.CODE_FILE_STATUS_OK, 125, 150):
                raise FTPError(code, response)

            # Data SSL Handshake
            data_socket = self._wrap_data_socket(data_socket)

            file_size = os.path.getsize(local_path)
            uploaded = 0

            with open(local_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    data_socket.sendall(chunk)
                    uploaded += len(chunk)

                    if progress_callback:
                        progress_callback(uploaded, file_size)

            data_socket.close()
            response = self._receive_response()
            self._log(f"<<< {response}")

            return uploaded

        except FTPError:
            if data_socket:
                try: data_socket.close()
                except: pass
            raise
        except Exception as e:
            if data_socket:
                try: data_socket.close()
                except: pass
            raise FTPError(0, str(e))

    def delete_file(self, path: str) -> str:
        code, response = self._send_command(f"DELE {path}")
        if code != self.CODE_DELETE_OK:
            raise FTPError(code, response)
        return response

    def delete_directory(self, path: str) -> str:
        code, response = self._send_command(f"RMD {path}")
        if code != self.CODE_DELETE_OK:
            raise FTPError(code, response)
        return response

    def mkdir(self, directory: str) -> str:
        code, response = self._send_command(f"MKD {directory}")
        if code != self.CODE_MKDIR_OK:
            raise FTPError(code, response)
        return response

    def rename(self, old_name: str, new_name: str) -> str:
        code, response = self._send_command(f"RNFR {old_name}")
        if code != 350:
            raise FTPError(code, response)

        code, response = self._send_command(f"RNTO {new_name}")
        if code != self.CODE_FILE_ACTION_OK:
            raise FTPError(code, response)

        return response

    def size(self, path: str) -> int:
        code, response = self._send_command(f"SIZE {path}")
        if code != 213:
            raise FTPError(code, response)
        return int(response.strip())