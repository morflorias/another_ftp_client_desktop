"""
FTP Client with Graphical User Interface
Two-panel interface for local and remote file system navigation.

Features:
- TCP socket based FTP protocol implementation
- Commands: LIST, GET, PUT, DELETE, MKDIR
- Drag and drop file transfer
- Progress indicators
- Connection profiles
- Manual path input
- Encrypted config storage
"""

import sys
import os
import json
import time
import platform
import subprocess
import base64
import hashlib
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeView, QTableView,
    QMenuBar, QMenu, QToolBar, QStatusBar, QMessageBox, QInputDialog,
    QProgressDialog, QDialog, QFormLayout, QLineEdit, QPushButton,
    QComboBox, QCheckBox, QGroupBox, QLabel, QTabWidget,
    QFileIconProvider, QFileDialog, QStyle, QAbstractItemView,
    QListWidget, QListWidgetItem, QHeaderView,
    QFileSystemModel, QToolButton
)
from PySide6.QtCore import (
    Qt, QDir, QModelIndex, QThread, Signal,
    QObject, QSize, QPoint, QMimeData, QUrl
)
from PySide6.QtGui import (
    QIcon, QAction, QKeySequence, QStandardItemModel, QStandardItem,
    QIntValidator, QDesktopServices, QDrag
)

from ftp_protocol import FTPClient, FTPFile, FTPError, TransferMode


# ============================================================================
# Config Encryption
# ============================================================================

class ConfigEncryption:
    """Encrypt/decrypt config file using a key derived from machine info."""
    
    # Salt for key derivation (can be changed for different installations)
    _SALT = b'FTP_Client_Salt_2024'
    
    @classmethod
    def _get_key(cls) -> bytes:
        """Derive encryption key from machine-specific info."""
        # Use machine name and user home as key source
        machine_info = f"{platform.node()}-{Path.home()}-ftp_client"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=cls._SALT,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(machine_info.encode()))
        return key
    
    @classmethod
    def encrypt(cls, data: str) -> bytes:
        """Encrypt string data."""
        key = cls._get_key()
        f = Fernet(key)
        return f.encrypt(data.encode())
    
    @classmethod
    def decrypt(cls, encrypted_data: bytes) -> str:
        """Decrypt encrypted data."""
        key = cls._get_key()
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()

    @dataclass
    class ConnectionProfile:
        """FTP connection profile."""
        name: str
        host: str
        port: int = 21
        username: str = "anonymous"
        password: str = ""
        use_passive: bool = True
        encoding: str = "utf-8"
        use_ssl: bool = False

# ============================================================================
# Data Classes for Configuration
# ============================================================================

@dataclass
class ConnectionProfile:
    """FTP connection profile."""
    name: str
    host: str
    port: int = 21
    username: str = "anonymous"
    password: str = ""
    use_passive: bool = True
    encoding: str = "utf-8"
    use_ssl: bool = False  # <-- ДОБАВЛЕНО ЭТО ПОЛЕ

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'ConnectionProfile':
        # Для обратной совместимости со старыми конфигами, где нет use_ssl
        if 'use_ssl' not in data:
            data['use_ssl'] = False
        return cls(**data)


# ============================================================================
# Worker Thread for FTP Operations
# ============================================================================

class FTPWorkerSignals(QObject):
    """Signals for FTP worker thread."""
    finished = Signal(object)
    log = Signal(str)
    connected = Signal(str)
    disconnected = Signal()
    error = Signal(str)
    list_result = Signal(list)
    transfer_progress = Signal(int, int)
    transfer_complete = Signal(int)


class FTPWorker(QThread):
    """Worker thread for FTP operations."""
    
    OP_CONNECT = "connect"
    OP_DISCONNECT = "disconnect"
    OP_LIST = "list"
    OP_DOWNLOAD = "download"
    OP_UPLOAD = "upload"
    OP_DELETE = "delete"
    OP_MKDIR = "mkdir"
    OP_CWD = "cwd"
    OP_CDUP = "cdup"
    OP_PWD = "pwd"
    OP_RENAME = "rename"
    
    def __init__(self, client: FTPClient, operation: str, **kwargs):
        super().__init__()
        self.client = client
        self.operation = operation
        self.kwargs = kwargs
        self.signals = FTPWorkerSignals()
        self.client.on_log = lambda msg: self.signals.log.emit(msg)
    
    def run(self):
        """Execute the FTP operation."""
        try:
            operations = {
                self.OP_CONNECT: self._do_connect,
                self.OP_DISCONNECT: self._do_disconnect,
                self.OP_LIST: self._do_list,
                self.OP_DOWNLOAD: self._do_download,
                self.OP_UPLOAD: self._do_upload,
                self.OP_DELETE: self._do_delete,
                self.OP_MKDIR: self._do_mkdir,
                self.OP_CWD: self._do_cwd,
                self.OP_CDUP: self._do_cdup,
                self.OP_PWD: self._do_pwd,
                self.OP_RENAME: self._do_rename,
            }
            
            if self.operation in operations:
                result = operations[self.operation]()
                self.signals.finished.emit(result)
            else:
                raise ValueError(f"Unknown operation: {self.operation}")
                
        except Exception as e:
            self.signals.error.emit(str(e))
            self.signals.finished.emit(e)
    
    def _do_connect(self) -> str:
        welcome = self.client.connect()
        username = self.kwargs.get('username', 'anonymous')
        password = self.kwargs.get('password', '')
        login_result = self.client.login(username, password)
        # Испускаем сигнал ПОСЛЕ успешного login, когда is_authenticated = True
        self.signals.connected.emit(welcome)
        return login_result
    
    def _do_disconnect(self) -> str:
        self.client.disconnect()
        self.signals.disconnected.emit()
        return "Disconnected"
    
    def _do_list(self) -> List[FTPFile]:
        directory = self.kwargs.get('directory', '')
        files = self.client.list(directory)
        self.signals.list_result.emit(files)
        return files
    
    def _do_download(self) -> int:
        remote_path = self.kwargs['remote_path']
        local_path = self.kwargs['local_path']
        return self.client.download_file(
            remote_path, local_path,
            lambda c, t: self.signals.transfer_progress.emit(c, t)
        )
    
    def _do_upload(self) -> int:
        local_path = self.kwargs['local_path']
        remote_path = self.kwargs['remote_path']
        return self.client.upload_file(
            local_path, remote_path,
            lambda c, t: self.signals.transfer_progress.emit(c, t)
        )
    
    def _do_delete(self) -> str:
        path = self.kwargs['path']
        is_dir = self.kwargs.get('is_dir', False)
        if is_dir:
            return self.client.delete_directory(path)
        return self.client.delete_file(path)
    
    def _do_mkdir(self) -> str:
        return self.client.mkdir(self.kwargs['directory'])
    
    def _do_cwd(self) -> str:
        return self.client.cwd(self.kwargs['directory'])
    
    def _do_cdup(self) -> str:
        return self.client.cdup()
    
    def _do_pwd(self) -> str:
        return self.client.pwd()
    
    def _do_rename(self) -> str:
        return self.client.rename(self.kwargs['old_name'], self.kwargs['new_name'])


# ============================================================================
# Remote File System Model
# ============================================================================

class RemoteFileModel(QStandardItemModel):
    """Model for remote FTP file system with sorting support."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(['Имя', 'Размер', 'Изменён', 'Тип'])
        self._files: List[FTPFile] = []
        self.setSortRole(Qt.UserRole)
    
    def set_files(self, files: List[FTPFile]):
        """Set the file list."""
        self.clear()
        self.setHorizontalHeaderLabels(['Имя', 'Размер', 'Изменён', 'Тип'])
        self._files = files
        
        # Сначала добавляем папки, потом файлы
        dirs = [f for f in files if f.is_dir]
        regular_files = [f for f in files if not f.is_dir]
        
        for file in dirs + regular_files:
            name_item = QStandardItem(file.name)
            if file.is_dir:
                name_item.setIcon(QApplication.style().standardIcon(QStyle.SP_DirIcon))
            else:
                name_item.setIcon(QApplication.style().standardIcon(QStyle.SP_FileIcon))
            name_item.setData(file.name, Qt.UserRole)
            name_item.setData(file.is_dir, Qt.UserRole + 1)
            name_item.setData(0 if file.is_dir else 1, Qt.UserRole + 2)  # Для сортировки: папки первыми
            
            size_str = self._format_size(file.size) if not file.is_dir else "<Папка>"
            size_item = QStandardItem(size_str)
            size_item.setData(file.size, Qt.UserRole)
            
            modified_item = QStandardItem(file.modified)
            type_item = QStandardItem("Папка" if file.is_dir else "Файл")
            
            self.appendRow([name_item, size_item, modified_item, type_item])
    
    def _format_size(self, size: int) -> str:
        for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} ПБ"
    
    def get_file_at(self, index: QModelIndex) -> Optional[FTPFile]:
        if not index.isValid():
            return None
        row = index.row()
        if 0 <= row < len(self._files):
            return self._files[row]
        return None


# ============================================================================
# Local File System Model (with Russian headers)
# ============================================================================

class LocalFileSystemModel(QFileSystemModel):
    """File system model with Russian headers."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._headers = ['Имя', 'Размер', 'Тип', 'Изменён']
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if 0 <= section < len(self._headers):
                return self._headers[section]
        return super().headerData(section, orientation, role)


# ============================================================================
# Connection Dialog
# ============================================================================

class ConnectionDialog(QDialog):
    """Dialog for FTP connection settings."""
    
    def __init__(self, profiles: List[ConnectionProfile] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Подключение к FTP-серверу")
        self.setMinimumWidth(400)
        self.profiles = profiles or []
        self._profile = None
        self._setup_ui()
        self._load_profiles()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Profile selection
        profile_group = QGroupBox("Профиль подключения")
        profile_layout = QHBoxLayout(profile_group)
        
        self.profile_combo = QComboBox()
        self.profile_combo.currentIndexChanged.connect(self._on_profile_selected)
        profile_layout.addWidget(self.profile_combo, 1)
        
        self.btn_save_profile = QPushButton("Сохранить")
        self.btn_save_profile.clicked.connect(self._save_profile)
        profile_layout.addWidget(self.btn_save_profile)
        
        self.btn_delete_profile = QPushButton("Удалить")
        self.btn_delete_profile.clicked.connect(self._delete_profile)
        profile_layout.addWidget(self.btn_delete_profile)
        
        layout.addWidget(profile_group)
        
        # Connection settings
        conn_group = QGroupBox("Параметры подключения")
        conn_layout = QFormLayout(conn_group)
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Имя профиля")
        conn_layout.addRow("Имя:", self.name_edit)
        
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("ftp.example.com")
        conn_layout.addRow("Сервер:", self.host_edit)
        
        self.port_edit = QLineEdit("21")
        self.port_edit.setValidator(QIntValidator(1, 65535))
        conn_layout.addRow("Порт:", self.port_edit)
        
        self.username_edit = QLineEdit("anonymous")
        conn_layout.addRow("Пользователь:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        conn_layout.addRow("Пароль:", self.password_edit)
        
        self.passive_check = QCheckBox("Пассивный режим")
        self.passive_check.setChecked(True)
        conn_layout.addRow("", self.passive_check)

        self.ssl_check = QCheckBox("Использовать SSL/TLS (FTPS)")
        self.ssl_check.setChecked(False)
        conn_layout.addRow(" ", self.ssl_check)
        
        layout.addWidget(conn_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_connect = QPushButton("Подключиться")
        self.btn_connect.setDefault(True)
        self.btn_connect.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_connect)
        
        self.btn_cancel = QPushButton("Отмена")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)
        
        layout.addLayout(btn_layout)
    
    def _load_profiles(self):
        self.profile_combo.clear()
        self.profile_combo.addItem("-- Новый профиль --")
        for profile in self.profiles:
            self.profile_combo.addItem(profile.name)
    
    def _on_profile_selected(self, index: int):
        if index <= 0 or index > len(self.profiles):
            self.name_edit.clear()
            self.host_edit.clear()
            self.port_edit.setText("21")
            self.username_edit.setText("anonymous")
            self.password_edit.clear()
            self.passive_check.setChecked(True)
            self._profile = None
        else:
            profile = self.profiles[index - 1]
            self._profile = profile
            self.name_edit.setText(profile.name)
            self.host_edit.setText(profile.host)
            self.port_edit.setText(str(profile.port))
            self.username_edit.setText(profile.username)
            self.password_edit.setText(profile.password)
            self.passive_check.setChecked(profile.use_passive)
    
    def _save_profile(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Ошибка", "Введите имя профиля")
            return
        
        profile = self.get_profile()
        profile.name = name
        
        for i, p in enumerate(self.profiles):
            if p.name == name:
                self.profiles[i] = profile
                self._load_profiles()
                self.profile_combo.setCurrentIndex(i + 1)
                return
        
        self.profiles.append(profile)
        self._load_profiles()
        self.profile_combo.setCurrentIndex(len(self.profiles))
    
    def _delete_profile(self):
        index = self.profile_combo.currentIndex()
        if index > 0:
            del self.profiles[index - 1]
            self._load_profiles()
            self.profile_combo.setCurrentIndex(0)
    
    def get_profile(self) -> ConnectionProfile:
        return ConnectionProfile(
            name=self.name_edit.text().strip() or "Безымянный",
            host=self.host_edit.text().strip(),
            port=int(self.port_edit.text() or 21),
            username=self.username_edit.text().strip(),
            password=self.password_edit.text(),
            use_passive=self.passive_check.isChecked(),
            use_ssl=self.ssl_check.isChecked()
        )


# ============================================================================
# Local File Panel
# ============================================================================

class LocalFilePanel(QWidget):
    """Widget for local file system navigation with drag & drop support."""
    
    file_selected = Signal(str)
    upload_requested = Signal(str)
    path_changed = Signal(str)
    download_to_path = Signal(str, str)  # remote_name, local_path
    
    # MIME types for drag & drop
    MIME_TYPE = "application/x-ftp-local-file"
    REMOTE_MIME_TYPE = "application/x-ftp-remote-file"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_path = QDir.homePath()
        self._clipboard_path = None
        self.setAcceptDrops(True)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Локальная файловая система")
        title_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        self.btn_up = QPushButton("↑")
        self.btn_up.setFixedWidth(30)
        self.btn_up.setToolTip("На уровень выше")
        self.btn_up.clicked.connect(self._go_up)
        header_layout.addWidget(self.btn_up)
        
        btn_refresh = QPushButton("↻")
        btn_refresh.setFixedWidth(30)
        btn_refresh.setToolTip("Обновить")
        btn_refresh.clicked.connect(self._refresh)
        header_layout.addWidget(btn_refresh)
        
        layout.addLayout(header_layout)
        
        # Path input with validation
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit(self._current_path)
        self.path_edit.setToolTip("Введите путь и нажмите Enter")
        self.path_edit.returnPressed.connect(self._on_path_entered)
        path_layout.addWidget(self.path_edit)
        
        btn_browse = QPushButton("...")
        btn_browse.setFixedWidth(30)
        btn_browse.setToolTip("Выбрать папку")
        btn_browse.clicked.connect(self._browse_folder)
        path_layout.addWidget(btn_browse)
        
        layout.addLayout(path_layout)
        
        # Tree view with drag & drop
        self.tree_view = QTreeView()
        self.tree_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self._show_context_menu)
        self.tree_view.doubleClicked.connect(self._on_double_click)
        
        # Enable drag and sorting
        self.tree_view.setDragEnabled(True)
        self.tree_view.setDragDropMode(QAbstractItemView.DragOnly)
        self.tree_view.setSortingEnabled(True)
        
        # File system model with Russian headers
        self.model = LocalFileSystemModel()
        self.model.setRootPath("")
        self.model.setFilter(QDir.AllDirs | QDir.Files | QDir.NoDotAndDotDot)
        
        self.tree_view.setModel(self.model)
        self.tree_view.setRootIndex(self.model.index(self._current_path))
        
        # Hide unnecessary columns (keep: Name, Size, Type, Modified)
        # Show all 4 columns now with Russian headers
        self.tree_view.setColumnWidth(0, 250)
        self.tree_view.setColumnWidth(1, 80)
        self.tree_view.setColumnWidth(2, 80)
        self.tree_view.setColumnWidth(3, 120)
        
        layout.addWidget(self.tree_view)
    
    def dragEnterEvent(self, event):
        """Handle drag enter - accept drops from remote panel."""
        mime = event.mimeData()
        if mime.hasFormat(self.REMOTE_MIME_TYPE) or mime.hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def dragMoveEvent(self, event):
        """Handle drag move."""
        mime = event.mimeData()
        if mime.hasFormat(self.REMOTE_MIME_TYPE) or mime.hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def dropEvent(self, event):
        """Handle drop - download file from server to current folder."""
        mime = event.mimeData()
        
        # Drop from remote panel (FTP file)
        if mime.hasFormat(self.REMOTE_MIME_TYPE):
            data = mime.data(self.REMOTE_MIME_TYPE).data().decode('utf-8')
            # Format: "filename|is_dir"
            parts = data.split("|")
            if len(parts) >= 2:
                remote_name = parts[0]
                is_dir = parts[1] == "True"
                
                if not is_dir:
                    local_path = os.path.join(self._current_path, remote_name)
                    self.download_to_path.emit(remote_name, local_path)
            
            event.acceptProposedAction()
        
        # Drop from external file manager (upload)
        elif mime.hasUrls():
            urls = mime.urls()
            for url in urls:
                local_path = url.toLocalFile()
                if os.path.isfile(local_path):
                    self.upload_requested.emit(local_path)
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def _on_path_entered(self):
        """Handle manual path input."""
        path = self.path_edit.text().strip()
        if not path:
            return
        
        # Normalize path
        path = os.path.normpath(path)
        
        # Check if path exists
        if os.path.exists(path):
            if os.path.isdir(path):
                self.set_path(path)
            else:
                # It's a file - select it in parent directory
                parent_dir = os.path.dirname(path)
                if parent_dir and os.path.exists(parent_dir):
                    self.set_path(parent_dir)
                    # Select the file
                    index = self.model.index(path)
                    self.tree_view.setCurrentIndex(index)
        else:
            QMessageBox.warning(
                self, 
                "Путь не найден",
                f"Путь не существует:\n{path}"
            )
            self.path_edit.setText(self._current_path)
    
    def _browse_folder(self):
        """Open folder selection dialog."""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Выберите папку",
            self._current_path
        )
        if folder:
            self.set_path(folder)
    
    def _go_up(self):
        current_dir = QDir(self._current_path)
        parent = current_dir.absoluteFilePath("..")
        parent_dir = QDir(parent)
        parent_canonical = parent_dir.canonicalPath()
        current_canonical = current_dir.canonicalPath()
        
        if parent_canonical == current_canonical:
            return
        
        self.set_path(parent)
    
    def _refresh(self):
        self.set_path(self._current_path)
    
    def _on_double_click(self, index: QModelIndex):
        path = self.model.filePath(index)
        if self.model.isDir(index):
            self.set_path(path)
        else:
            # Open file with system default
            self._open_file(path)
    
    def _open_file(self, path: str):
        """Open file with system default application."""
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["open", path])
        else:  # Linux
            subprocess.run(["xdg-open", path])
    
    def _open_in_explorer(self, path: str):
        """Open file/folder in system file manager."""
        if platform.system() == "Windows":
            if os.path.isdir(path):
                subprocess.run(["explorer", path])
            else:
                subprocess.run(["explorer", "/select,", path])
        elif platform.system() == "Darwin":  # macOS
            if os.path.isdir(path):
                subprocess.run(["open", path])
            else:
                subprocess.run(["open", "-R", path])
        else:  # Linux
            subprocess.run(["xdg-open", os.path.dirname(path) if os.path.isfile(path) else path])
    
    def _show_context_menu(self, pos: QPoint):
        index = self.tree_view.indexAt(pos)
        
        menu = QMenu(self)
        
        if index.isValid():
            path = self.model.filePath(index)
            is_dir = self.model.isDir(index)
            
            if is_dir:
                # Open folder
                open_action = menu.addAction("📂 Открыть папку")
                open_action.triggered.connect(lambda: self.set_path(path))
                
                # Open in explorer
                explorer_action = menu.addAction("🔍 Открыть в проводнике")
                explorer_action.triggered.connect(lambda: self._open_in_explorer(path))
                
                menu.addSeparator()
                
                # Create subfolder
                create_action = menu.addAction("📁 Создать папку")
                create_action.triggered.connect(lambda: self._create_folder(path))
            else:
                # Open file
                open_action = menu.addAction("📄 Открыть файл")
                open_action.triggered.connect(lambda: self._open_file(path))
                
                # Open in explorer
                explorer_action = menu.addAction("🔍 Показать в проводнике")
                explorer_action.triggered.connect(lambda: self._open_in_explorer(path))
                
                menu.addSeparator()
                
                # Upload
                upload_action = menu.addAction("⬆ Загрузить на сервер")
                upload_action.triggered.connect(lambda: self.upload_requested.emit(path))
            
            menu.addSeparator()
            
            # Rename
            rename_action = menu.addAction("✏ Переименовать")
            rename_action.triggered.connect(lambda: self._rename_item(path))
            
            # Delete
            delete_action = menu.addAction("🗑 Удалить")
            delete_action.triggered.connect(lambda: self._delete_item(path))
            
            menu.addSeparator()
            
            # Copy path
            copy_action = menu.addAction("📋 Копировать путь")
            copy_action.triggered.connect(lambda: self._copy_path(path))
        else:
            # Empty area context menu
            refresh_action = menu.addAction("↻ Обновить")
            refresh_action.triggered.connect(self._refresh)
            
            create_action = menu.addAction("📁 Создать папку")
            create_action.triggered.connect(lambda: self._create_folder(self._current_path))
            
            menu.addSeparator()
            
            paste_action = menu.addAction("📋 Вставить")
            paste_action.triggered.connect(self._paste_item)
            paste_action.setEnabled(self._clipboard_path is not None)
        
        menu.exec(self.tree_view.viewport().mapToGlobal(pos))
    
    def _create_folder(self, parent_path: str):
        """Create a new folder."""
        name, ok = QInputDialog.getText(self, "Создать папку", "Имя папки:")
        if ok and name:
            new_path = os.path.join(parent_path, name)
            try:
                os.makedirs(new_path, exist_ok=False)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать папку:\n{e}")
    
    def _rename_item(self, path: str):
        """Rename a file or folder."""
        old_name = os.path.basename(path)
        new_name, ok = QInputDialog.getText(
            self, "Переименовать", "Новое имя:", 
            text=old_name
        )
        if ok and new_name and new_name != old_name:
            new_path = os.path.join(os.path.dirname(path), new_name)
            try:
                os.rename(path, new_path)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось переименовать:\n{e}")
    
    def _delete_item(self, path: str):
        """Delete a file or folder."""
        name = os.path.basename(path)
        is_dir = os.path.isdir(path)
        type_name = "папку" if is_dir else "файл"
        
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Удалить {type_name} '{name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if is_dir:
                    import shutil
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить:\n{e}")
    
    def _copy_path(self, path: str):
        """Copy path to clipboard."""
        self._clipboard_path = path
        clipboard = QApplication.clipboard()
        clipboard.setText(path)
    
    def _paste_item(self):
        """Paste (copy) item from clipboard."""
        if not self._clipboard_path:
            return
        
        src = self._clipboard_path
        dst = os.path.join(self._current_path, os.path.basename(src))
        
        if src == dst:
            # Same location - add copy suffix
            base, ext = os.path.splitext(src)
            dst = f"{base} - копия{ext}"
        
        try:
            import shutil
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            self._refresh()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось скопировать:\n{e}")
    
    def set_path(self, path: str):
        self._current_path = QDir(path).absolutePath()
        self.tree_view.setRootIndex(self.model.index(self._current_path))
        self.path_edit.setText(self._current_path)
        self.path_changed.emit(self._current_path)
    
    def get_selected_file(self) -> Optional[str]:
        indexes = self.tree_view.selectedIndexes()
        if indexes:
            return self.model.filePath(indexes[0])
        return None
    
    def get_current_path(self) -> str:
        return self._current_path


# ============================================================================
# Remote Table View (for drag support)
# ============================================================================

class RemoteTableView(QTableView):
    """Table view with drag support for remote files."""
    
    REMOTE_MIME_TYPE = "application/x-ftp-remote-file"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._remote_files: List[FTPFile] = []
    
    def set_remote_files(self, files: List[FTPFile]):
        """Store reference to remote files for drag operations."""
        self._remote_files = files
    
    def startDrag(self, supportedActions):
        """Override startDrag to provide custom MIME data."""
        selected = self.selectedIndexes()
        if not selected:
            return
        
        # Get the first selected row
        row = selected[0].row()
        if row < 0 or row >= len(self._remote_files):
            return
        
        file = self._remote_files[row]
        if file.is_dir:
            return  # Don't drag directories
        
        # Create MIME data
        mime_data = QMimeData()
        # Format: "filename|is_dir"
        data = f"{file.name}|{file.is_dir}"
        mime_data.setData(self.REMOTE_MIME_TYPE, data.encode('utf-8'))
        
        # Create drag object
        from PySide6.QtCore import Qt
        drag = QDrag(self)
        drag.setMimeData(mime_data)
        
        # Set drag icon
        if file.is_dir:
            icon = QApplication.style().standardIcon(QStyle.SP_DirIcon)
        else:
            icon = QApplication.style().standardIcon(QStyle.SP_FileIcon)
        drag.setPixmap(icon.pixmap(32, 32))
        
        drag.exec(Qt.CopyAction)


# ============================================================================
# Remote File Panel
# ============================================================================

class RemoteFilePanel(QWidget):
    """Widget for remote FTP file system navigation with drag & drop support."""
    
    directory_activated = Signal(object)
    download_requested = Signal(str)
    delete_requested = Signal(str, bool)
    mkdir_requested = Signal()
    refresh_requested = Signal()
    path_changed = Signal(str)
    rename_requested = Signal(str, str)
    
    REMOTE_MIME_TYPE = "application/x-ftp-remote-file"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_path = "/"
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Удалённая файловая система")
        title_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        self.btn_up = QPushButton("↑")
        self.btn_up.setFixedWidth(30)
        self.btn_up.setToolTip("На уровень выше")
        self.btn_up.clicked.connect(lambda: self.directory_activated.emit(None))
        header_layout.addWidget(self.btn_up)
        
        btn_refresh = QPushButton("↻")
        btn_refresh.setFixedWidth(30)
        btn_refresh.setToolTip("Обновить")
        btn_refresh.clicked.connect(self.refresh_requested.emit)
        header_layout.addWidget(btn_refresh)
        
        layout.addLayout(header_layout)
        
        # Path input
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit("/")
        self.path_edit.setToolTip("Введите путь и нажмите Enter")
        self.path_edit.returnPressed.connect(self._on_path_entered)
        path_layout.addWidget(self.path_edit)
        
        layout.addLayout(path_layout)
        
        # Table view with drag & drop support
        self.table_view = RemoteTableView()
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_view.setShowGrid(False)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.doubleClicked.connect(self._on_double_click)
        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self._show_context_menu)
        
        # Enable drag
        self.table_view.setDragEnabled(True)
        
        # Model
        self.model = RemoteFileModel()
        self.table_view.setModel(self.model)
        
        self.table_view.setColumnWidth(0, 250)
        self.table_view.setColumnWidth(1, 100)
        self.table_view.setColumnWidth(2, 150)
        
        layout.addWidget(self.table_view)
    
    def _on_path_entered(self):
        """Handle manual path input - request navigation from main window."""
        path = self.path_edit.text().strip()
        if not path:
            path = "/"
        
        # Normalize path
        if not path.startswith("/"):
            path = "/" + path
        
        # Remove trailing slash except for root
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        
        self.path_changed.emit(path)
    
    def _on_double_click(self, index: QModelIndex):
        file = self.model.get_file_at(index)
        if file and file.is_dir:
            self.directory_activated.emit(file)
    
    def _show_context_menu(self, pos: QPoint):
        index = self.table_view.indexAt(pos)
        
        menu = QMenu(self)
        
        if index.isValid():
            file = self.model.get_file_at(index)
            if file:
                if file.is_dir:
                    open_action = menu.addAction("📂 Открыть папку")
                    open_action.triggered.connect(lambda: self.directory_activated.emit(file))
                else:
                    download_action = menu.addAction("⬇ Скачать")
                    download_action.triggered.connect(
                        lambda: self.download_requested.emit(file.name)
                    )
                
                menu.addSeparator()
                
                rename_action = menu.addAction("✏ Переименовать")
                rename_action.triggered.connect(lambda: self._rename_item(file.name))
                
                delete_action = menu.addAction("🗑 Удалить")
                delete_action.triggered.connect(
                    lambda: self.delete_requested.emit(file.name, file.is_dir)
                )
                
                menu.addSeparator()
                
                copy_action = menu.addAction("📋 Копировать путь")
                copy_action.triggered.connect(
                    lambda: self._copy_path(f"{self._current_path}/{file.name}".replace("//", "/"))
                )
        
        menu.addSeparator()
        
        refresh_action = menu.addAction("↻ Обновить")
        refresh_action.triggered.connect(self.refresh_requested.emit)
        
        mkdir_action = menu.addAction("📁 Создать папку")
        mkdir_action.triggered.connect(self.mkdir_requested.emit)
        
        menu.exec(self.table_view.viewport().mapToGlobal(pos))
    
    def _rename_item(self, old_name: str):
        """Request rename operation."""
        new_name, ok = QInputDialog.getText(
            self, "Переименовать", "Новое имя:",
            text=old_name
        )
        if ok and new_name and new_name != old_name:
            self.rename_requested.emit(old_name, new_name)
    
    def _copy_path(self, path: str):
        """Copy path to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(path)
    
    def set_path(self, path: str):
        self._current_path = path
        self.path_label_text = path
        self.path_edit.setText(path)
    
    def set_files(self, files: List[FTPFile]):
        self.model.set_files(files)
    
    def get_selected_file(self) -> Optional[FTPFile]:
        indexes = self.table_view.selectedIndexes()
        if indexes:
            return self.model.get_file_at(indexes[0])
        return None
    
    def get_current_path(self) -> str:
        return self._current_path


# ============================================================================
# Log Widget
# ============================================================================

class LogWidget(QWidget):
    """Widget for displaying FTP command/response log with copy/save support."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.log_list = QListWidget()
        self.log_list.setStyleSheet("font-family: monospace; font-size: 10px;")
        self.log_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.log_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_list.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.log_list)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        btn_copy = QPushButton("📋 Копировать всё")
        btn_copy.clicked.connect(self._copy_all)
        btn_layout.addWidget(btn_copy)
        
        btn_save = QPushButton("💾 Сохранить...")
        btn_save.clicked.connect(self._save_log)
        btn_layout.addWidget(btn_save)
        
        btn_clear = QPushButton("🗑 Очистить")
        btn_clear.clicked.connect(self.log_list.clear)
        btn_layout.addWidget(btn_clear)
        
        layout.addLayout(btn_layout)
    
    def _show_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        
        # Copy selected
        copy_selected = menu.addAction("📋 Копировать выделенное")
        copy_selected.triggered.connect(self._copy_selected)
        copy_selected.setEnabled(len(self.log_list.selectedItems()) > 0)
        
        # Copy all
        copy_all = menu.addAction("📋 Копировать всё")
        copy_all.triggered.connect(self._copy_all)
        
        menu.addSeparator()
        
        # Save to file
        save_action = menu.addAction("💾 Сохранить в файл...")
        save_action.triggered.connect(self._save_log)
        
        menu.addSeparator()
        
        # Clear
        clear_action = menu.addAction("🗑 Очистить")
        clear_action.triggered.connect(self.log_list.clear)
        
        menu.exec(self.log_list.viewport().mapToGlobal(pos))
    
    def _copy_selected(self):
        """Copy selected items to clipboard."""
        selected = self.log_list.selectedItems()
        if selected:
            text = "\n".join(item.text() for item in selected)
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
    
    def _copy_all(self):
        """Copy all log entries to clipboard."""
        text = "\n".join(
            self.log_list.item(i).text() 
            for i in range(self.log_list.count())
        )
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def _save_log(self):
        """Save log to file."""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить лог",
            "ftp_log.txt",
            "Текстовые файлы (*.txt);;Все файлы (*.*)"
        )
        if filename:
            try:
                text = "\n".join(
                    self.log_list.item(i).text() 
                    for i in range(self.log_list.count())
                )
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{e}")
    
    def append(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        item = QListWidgetItem(f"[{timestamp}] {message}")
        
        if message.startswith(">>>"):
            item.setForeground(Qt.blue)
        elif message.startswith("<<<"):
            item.setForeground(Qt.darkGreen)
        elif "Error" in message or "error" in message.lower():
            item.setForeground(Qt.red)
        
        self.log_list.addItem(item)
        self.log_list.scrollToBottom()


# ============================================================================
# Main Window
# ============================================================================

class FTPClientWindow(QMainWindow):
    """Main FTP client window."""
    
    CONFIG_FILE = Path.home() / ".ftp_client_config.json"
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FTP Client")
        self.setMinimumSize(1000, 700)
        self.setAcceptDrops(True)
        
        self.ftp_client: Optional[FTPClient] = None
        self.ftp_worker: Optional[FTPWorker] = None
        self._remote_path = "/"
        self._local_path = QDir.homePath()
        self.profiles: List[ConnectionProfile] = []
        
        self._setup_ui()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()
        self._load_config()
        
        self.local_panel.set_path(self._local_path)
    
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Local panel
        self.local_panel = LocalFilePanel()
        self.local_panel.upload_requested.connect(self._upload_file)
        self.local_panel.path_changed.connect(self._on_local_path_changed)
        splitter.addWidget(self.local_panel)
        
        # Remote panel
        self.remote_panel = RemoteFilePanel()
        self.remote_panel.directory_activated.connect(self._on_remote_dir_activated)
        self.remote_panel.download_requested.connect(self._download_file)
        self.remote_panel.delete_requested.connect(self._delete_item)
        self.remote_panel.mkdir_requested.connect(self._create_directory)
        self.remote_panel.refresh_requested.connect(self._refresh_remote)
        self.remote_panel.path_changed.connect(self._on_remote_path_changed)
        self.remote_panel.rename_requested.connect(self._rename_remote_item)
        splitter.addWidget(self.remote_panel)
        
        splitter.setSizes([500, 500])
        layout.addWidget(splitter, 1)
        
        # Collapsible Log Panel
        self._log_collapsed = False
        self._log_height = 200
        
        log_header = QHBoxLayout()
        
        self.log_toggle_btn = QToolButton()
        self.log_toggle_btn.setArrowType(Qt.DownArrow)
        self.log_toggle_btn.setCheckable(True)
        self.log_toggle_btn.setChecked(True)
        self.log_toggle_btn.setToolTip("Свернуть/развернуть лог")
        self.log_toggle_btn.clicked.connect(self._toggle_log)
        log_header.addWidget(self.log_toggle_btn)
        
        log_title = QLabel("📋 Лог FTP")
        log_title.setStyleSheet("font-weight: bold;")
        log_header.addWidget(log_title)
        log_header.addStretch()
        
        layout.addLayout(log_header)
        
        # Log widget container
        self.log_container = QWidget()
        log_container_layout = QVBoxLayout(self.log_container)
        log_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.log_widget = LogWidget()
        log_container_layout.addWidget(self.log_widget)
        
        self.log_container.setMaximumHeight(self._log_height)
        layout.addWidget(self.log_container)
    
    def _toggle_log(self, checked: bool):
        """Toggle log visibility."""
        self._log_collapsed = not checked
        self.log_toggle_btn.setArrowType(Qt.DownArrow if checked else Qt.RightArrow)
        
        if self._log_collapsed:
            self.log_container.setMaximumHeight(0)
            self.log_container.setVisible(False)
        else:
            self.log_container.setMaximumHeight(self._log_height)
            self.log_container.setVisible(True)
    
    def _setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("Файл")
        
        connect_action = QAction("Подключиться...", self)
        connect_action.setShortcut(QKeySequence("Ctrl+N"))
        connect_action.triggered.connect(self._show_connect_dialog)
        file_menu.addAction(connect_action)
        
        disconnect_action = QAction("Отключиться", self)
        disconnect_action.setShortcut(QKeySequence("Ctrl+D"))
        disconnect_action.triggered.connect(self._disconnect)
        file_menu.addAction(disconnect_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Выход", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Transfer menu
        transfer_menu = menubar.addMenu("Передача")
        
        upload_action = QAction("Загрузить на сервер", self)
        upload_action.setShortcut(QKeySequence("Ctrl+U"))
        upload_action.triggered.connect(self._upload_selected)
        transfer_menu.addAction(upload_action)
        
        download_action = QAction("Скачать с сервера", self)
        download_action.setShortcut(QKeySequence("Ctrl+G"))
        download_action.triggered.connect(self._download_selected)
        transfer_menu.addAction(download_action)
        
        transfer_menu.addSeparator()
        
        delete_action = QAction("Удалить", self)
        delete_action.setShortcut(QKeySequence("Delete"))
        delete_action.triggered.connect(self._delete_selected)
        transfer_menu.addAction(delete_action)
        
        # View menu
        view_menu = menubar.addMenu("Вид")
        
        refresh_action = QAction("Обновить", self)
        refresh_action.setShortcut(QKeySequence("F5"))
        refresh_action.triggered.connect(self._refresh_all)
        view_menu.addAction(refresh_action)
        
        # Help menu
        help_menu = menubar.addMenu("Справка")
        
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_toolbar(self):
        toolbar = QToolBar("Главная")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        toolbar.addAction(QAction("Подключиться", self, triggered=self._show_connect_dialog))
        toolbar.addAction(QAction("Отключиться", self, triggered=self._disconnect))
        toolbar.addSeparator()
        toolbar.addAction(QAction("↑ Загрузить", self, triggered=self._upload_selected))
        toolbar.addAction(QAction("↓ Скачать", self, triggered=self._download_selected))
        toolbar.addSeparator()
        toolbar.addAction(QAction("↻ Обновить", self, triggered=self._refresh_all))
        toolbar.addAction(QAction("📁 Новая папка", self, triggered=self._create_directory))
    
    def _setup_statusbar(self):
        self.statusBar().showMessage("Не подключено")
    
    def _load_config(self):
        """Load and decrypt config file."""
        try:
            if not self.CONFIG_FILE.exists():
                return
            
            with open(self.CONFIG_FILE, 'rb') as f:
                data_bytes = f.read()
            
            # Try to decrypt first
            try:
                decrypted = ConfigEncryption.decrypt(data_bytes)
                data = json.loads(decrypted)
            except Exception:
                # If decryption fails, try plain text (for migration from old config)
                try:
                    data = json.loads(data_bytes.decode('utf-8'))
                except Exception:
                    data = {}
            
            self.profiles = [
                ConnectionProfile.from_dict(p) for p in data.get('profiles', [])
            ]
            self._local_path = data.get('local_path', QDir.homePath())
            
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def _save_config(self):
        """Encrypt and save config file."""
        try:
            data = {
                'profiles': [p.to_dict() for p in self.profiles],
                'local_path': self._local_path
            }
            json_data = json.dumps(data, indent=2, ensure_ascii=False)
            encrypted_data = ConfigEncryption.encrypt(json_data)
            with open(self.CONFIG_FILE, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def _log(self, message: str):
        self.log_widget.append(message)
    
    # Drag & Drop support
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        """Handle drop from external sources (file manager)."""
        urls = event.mimeData().urls()
        for url in urls:
            local_path = url.toLocalFile()
            if os.path.isfile(local_path):
                self._upload_file(local_path)
    
    def _on_local_path_changed(self, path: str):
        self._local_path = path
    
    def _on_remote_path_changed(self, path: str):
        """Navigate to specified remote path."""
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            QMessageBox.warning(self, "Предупреждение", "Сначала подключитесь к серверу")
            self.remote_panel.path_edit.setText(self._remote_path)
            return
        
        # Try to change to the specified directory
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_CWD, directory=path)
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(self._on_path_change_finished)
        self.ftp_worker.start()
    
    def _on_path_change_finished(self, result):
        if isinstance(result, Exception):
            QMessageBox.warning(self, "Ошибка", f"Не удалось перейти в указанный путь:\n{result}")
            self.remote_panel.path_edit.setText(self._remote_path)
        else:
            self._refresh_remote()
    
    def _show_connect_dialog(self):
        dialog = ConnectionDialog(self.profiles, self)
        if dialog.exec() == QDialog.Accepted:
            profile = dialog.get_profile()
            self.profiles = dialog.profiles
            self._save_config()
            self._connect(profile)

    def _connect(self, profile: ConnectionProfile):
        if self.ftp_client and self.ftp_client.is_connected:
            self._disconnect()

        self.ftp_client = FTPClient(
            host=profile.host,
            port=profile.port,
            encoding=profile.encoding,
            use_ssl=profile.use_ssl  # <-- Использовать значение из профиля
        )
        self.ftp_client.transfer_mode = (
            TransferMode.PASSIVE if profile.use_passive else TransferMode.ACTIVE
        )

        self.ftp_worker = FTPWorker(
            self.ftp_client,
            FTPWorker.OP_CONNECT,
            username=profile.username,
            password=profile.password
        )
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.connected.connect(self._on_connected)
        self.ftp_worker.signals.error.connect(self._on_error)
        self.ftp_worker.signals.finished.connect(self._on_connect_finished)

        self.statusBar().showMessage(f"Подключение к {profile.host}...")
        self.ftp_worker.start()
    
    def _disconnect(self):
        if self.ftp_client and self.ftp_client.is_connected:
            self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_DISCONNECT)
            self.ftp_worker.signals.log.connect(self._log)
            self.ftp_worker.signals.disconnected.connect(self._on_disconnected)
            self.ftp_worker.start()
    
    def _on_connected(self, welcome: str):
        self.statusBar().showMessage("Подключено")
        self._log(f"Подключено: {welcome}")
        # После подключения сразу делаем LIST /
        self._do_initial_list()
    
    def _do_initial_list(self):
        """Perform initial LIST / after connection."""
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        # Устанавливаем путь в корень
        self._remote_path = "/"
        self.remote_panel.set_path("/")
        
        # Делаем LIST /
        self._log(">>> LIST /")
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_LIST, directory="/")
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.list_result.connect(self._on_list_result)
        self.ftp_worker.start()
    
    def _on_disconnected(self):
        self.statusBar().showMessage("Отключено")
        self._log("Отключено от сервера")
        self.remote_panel.set_files([])
    
    def _on_connect_finished(self, result):
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", str(result))
    
    def _on_error(self, error: str):
        self._log(f"Ошибка: {error}")
    
    def _on_remote_dir_activated(self, file):
        if file is None:
            self._do_cdup()
        elif isinstance(file, FTPFile) and file.is_dir:
            self._do_cwd(file.name)
    
    def _do_cwd(self, directory: str):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_CWD, directory=directory)
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(self._on_navigation_finished)
        self.ftp_worker.start()
    
    def _do_cdup(self):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_CDUP)
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(self._on_navigation_finished)
        self.ftp_worker.start()
    
    def _on_navigation_finished(self, result):
        if not isinstance(result, Exception):
            self._refresh_remote()
    
    def _refresh_remote(self):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_PWD)
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(self._on_pwd_finished)
        self.ftp_worker.start()
    
    def _on_pwd_finished(self, result):
        if isinstance(result, str):
            self._remote_path = result
            self.remote_panel.set_path(result)
        
        self.ftp_worker = FTPWorker(self.ftp_client, FTPWorker.OP_LIST)
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.list_result.connect(self._on_list_result)
        self.ftp_worker.start()
    
    def _on_list_result(self, files: List[FTPFile]):
        self.remote_panel.set_files(files)
    
    def _refresh_all(self):
        self.local_panel.set_path(self._local_path)
        self._refresh_remote()
    
    def _upload_selected(self):
        path = self.local_panel.get_selected_file()
        if path:
            self._upload_file(path)
    
    def _upload_file(self, local_path: str):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            QMessageBox.warning(self, "Предупреждение", "Сначала подключитесь к серверу")
            return
        
        filename = os.path.basename(local_path)
        remote_path = f"{self._remote_path}/{filename}".replace("//", "/")
        
        progress = QProgressDialog("Загрузка файла...", "Отмена", 0, 100, self)
        progress.setWindowTitle("Загрузка")
        progress.setWindowModality(Qt.WindowModal)
        progress.setAutoClose(True)
        
        self.ftp_worker = FTPWorker(
            self.ftp_client,
            FTPWorker.OP_UPLOAD,
            local_path=local_path,
            remote_path=remote_path
        )
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.transfer_progress.connect(
            lambda c, t: progress.setValue(int(c * 100 / t) if t > 0 else 0)
        )
        self.ftp_worker.signals.finished.connect(
            lambda r: self._on_upload_finished(r, filename, progress)
        )
        
        progress.canceled.connect(self.ftp_worker.terminate)
        self.ftp_worker.start()
        progress.exec()
    
    def _on_upload_finished(self, result, filename: str, progress: QProgressDialog):
        progress.close()
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", f"Ошибка загрузки: {result}")
        else:
            self._log(f"Файл {filename} успешно загружен")
            self._refresh_remote()
    
    def _download_selected(self):
        file = self.remote_panel.get_selected_file()
        if file and isinstance(file, FTPFile) and not file.is_dir:
            self._download_file(file.name)
    
    def _download_file(self, remote_name: str):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            QMessageBox.warning(self, "Предупреждение", "Сначала подключитесь к серверу")
            return
        
        local_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить файл",
            os.path.join(self._local_path, remote_name)
        )
        
        if not local_path:
            return
        
        remote_path = f"{self._remote_path}/{remote_name}".replace("//", "/")
        
        progress = QProgressDialog("Скачивание файла...", "Отмена", 0, 100, self)
        progress.setWindowTitle("Скачивание")
        progress.setWindowModality(Qt.WindowModal)
        progress.setAutoClose(True)
        
        self.ftp_worker = FTPWorker(
            self.ftp_client,
            FTPWorker.OP_DOWNLOAD,
            remote_path=remote_path,
            local_path=local_path
        )
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.transfer_progress.connect(
            lambda c, t: progress.setValue(int(c * 100 / t) if t > 0 else 0)
        )
        self.ftp_worker.signals.finished.connect(
            lambda r: self._on_download_finished(r, remote_name, progress)
        )
        
        progress.canceled.connect(self.ftp_worker.terminate)
        self.ftp_worker.start()
        progress.exec()
    
    def _on_download_finished(self, result, filename: str, progress: QProgressDialog):
        progress.close()
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", f"Ошибка скачивания: {result}")
        else:
            self._log(f"Файл {filename} успешно скачан")
    
    def _delete_selected(self):
        file = self.remote_panel.get_selected_file()
        if file and isinstance(file, FTPFile):
            self._delete_item(file.name, file.is_dir)
    
    def _delete_item(self, name: str, is_dir: bool):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        type_name = "папку" if is_dir else "файл"
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить {type_name} '{name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        path = f"{self._remote_path}/{name}".replace("//", "/")
        
        self.ftp_worker = FTPWorker(
            self.ftp_client,
            FTPWorker.OP_DELETE,
            path=path,
            is_dir=is_dir
        )
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(
            lambda r: self._on_delete_finished(r, name)
        )
        self.ftp_worker.start()
    
    def _on_delete_finished(self, result, name: str):
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", f"Ошибка удаления: {result}")
        else:
            self._log(f"'{name}' успешно удалён")
            self._refresh_remote()
    
    def _rename_remote_item(self, old_name: str, new_name: str):
        """Rename a remote file or folder."""
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            return
        
        old_path = f"{self._remote_path}/{old_name}".replace("//", "/")
        new_path = f"{self._remote_path}/{new_name}".replace("//", "/")
        
        self.ftp_worker = FTPWorker(
            self.ftp_client,
            FTPWorker.OP_RENAME,
            old_name=old_path,
            new_name=new_path
        )
        self.ftp_worker.signals.log.connect(self._log)
        self.ftp_worker.signals.finished.connect(self._on_rename_finished)
        self.ftp_worker.start()
    
    def _on_rename_finished(self, result):
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", f"Ошибка переименования: {result}")
        else:
            self._log("Переименовано успешно")
            self._refresh_remote()
    
    def _create_directory(self):
        if not self.ftp_client or not self.ftp_client.is_authenticated:
            QMessageBox.warning(self, "Предупреждение", "Сначала подключитесь к серверу")
            return
        
        name, ok = QInputDialog.getText(self, "Создать папку", "Имя папки:")
        if ok and name:
            path = f"{self._remote_path}/{name}".replace("//", "/")
            
            self.ftp_worker = FTPWorker(
                self.ftp_client,
                FTPWorker.OP_MKDIR,
                directory=path
            )
            self.ftp_worker.signals.log.connect(self._log)
            self.ftp_worker.signals.finished.connect(
                lambda r: self._on_mkdir_finished(r, name)
            )
            self.ftp_worker.start()
    
    def _on_mkdir_finished(self, result, name: str):
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Ошибка", f"Ошибка создания папки: {result}")
        else:
            self._log(f"Папка '{name}' создана")
            self._refresh_remote()
    
    def _show_about(self):
        QMessageBox.about(
            self,
            "О программе",
            "<h3>FTP Client</h3>"
            "<p>FTP-клиент с графическим интерфейсом</p>"
            "<p>Поддерживаемые команды:</p>"
            "<ul>"
            "<li>LIST - просмотр файлов</li>"
            "<li>GET - скачивание файлов</li>"
            "<li>PUT - загрузка файлов</li>"
            "<li>DELETE - удаление файлов</li>"
            "<li>MKDIR - создание папок</li>"
            "<li>RENAME - переименование</li>"
            "</ul>"
            "<p><b>Drag & Drop:</b> перетаскивайте файлы из проводника для загрузки</p>"
            "<p>Технологии: Python, PySide6, TCP сокеты</p>"
        )
    
    def closeEvent(self, event):
        self._save_config()
        if self.ftp_client and self.ftp_client.is_connected:
            try:
                self.ftp_client.disconnect()
            except:
                pass
        event.accept()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("FTP Client")
    app.setOrganizationName("FTPClient")
    app.setStyle("Fusion")
    
    window = FTPClientWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
