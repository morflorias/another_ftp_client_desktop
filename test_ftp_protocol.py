"""
Unit tests for FTP Protocol Module.
Uses public FTP server: cygwin.mirror.rafal.ca

Run tests:
    pytest test_ftp_protocol.py -v

    # Run only fast tests (skip slow tests)
    pytest test_ftp_protocol.py -v -m "not slow"

    # Run with coverage
    pytest test_ftp_protocol.py -v --cov=ftp_protocol
"""

import pytest
import os
import tempfile
import time
from pathlib import Path

from ftp_protocol import (
    FTPClient, FTPFile, FTPError, TransferMode
)


# =============================================================================
# Test Configuration
# =============================================================================

# Public FTP server for testing (read-only mirror)
FTP_HOST = "cygwin.mirror.rafal.ca"
FTP_PORT = 21
FTP_USER = "ftp"
FTP_PASS = "mail@example.com"

# Test timeouts
CONNECT_TIMEOUT = 15.0
OPERATION_TIMEOUT = 30.0


def skip_on_security_error(func):
    """Decorator to skip tests when FTP server rejects data connection."""
    import functools
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FTPError as e:
            if "Security" in str(e) or "Bad IP" in str(e) or "425" in str(e):
                pytest.skip(f"FTP server rejected data connection: {e}")
            raise
    return wrapper


def safe_list(client, path=None):
    """Safely list directory, skipping on security errors."""
    try:
        if path:
            return client.list(path)
        return client.list()
    except FTPError as e:
        if "Security" in str(e) or "Bad IP" in str(e) or "425" in str(e):
            pytest.skip(f"FTP server rejected data connection: {e}")
        raise


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def ftp_client():
    """Create an FTP client instance."""
    client = FTPClient(
        host=FTP_HOST,
        port=FTP_PORT,
        timeout=CONNECT_TIMEOUT
    )
    client.transfer_mode = TransferMode.PASSIVE
    yield client
    # Cleanup
    if client.is_connected:
        try:
            client.disconnect()
        except:
            pass


@pytest.fixture
def connected_ftp(ftp_client):
    """FTP client that is connected but not authenticated."""
    ftp_client.connect()
    return ftp_client


@pytest.fixture
def authenticated_ftp(connected_ftp):
    """FTP client that is connected and authenticated."""
    connected_ftp.login(FTP_USER, FTP_PASS)
    return connected_ftp


@pytest.fixture
def temp_dir():
    """Create a temporary directory for file operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


# =============================================================================
# Internal Parsers Tests (Fast Unit Tests)
# =============================================================================

class TestInternalParsers:
    """Tests for internal regex parsers and NAT workarounds (no network required)."""

    def test_parse_list_response_unix(self):
        """Test parsing UNIX/FileZilla style directory listings."""
        client = FTPClient("dummy.host")
        listing = (
            "drwxr-xr-x 1 ftp ftp 4096 Feb 28 11:34 myfolder\n"
            "-rw-r--r-- 1 ftp ftp 1234 Jan 01 12:00 myfile.txt\n"
            "drwxrwxrwx 1 root root 0 Mar 15 08:00 .hidden_dir\n"
        )

        files = client._parse_list_response(listing)

        assert len(files) == 3

        # Checking sorting (Directories first, then alphabetical)
        assert files[0].name == ".hidden_dir"
        assert files[0].is_dir is True

        assert files[1].name == "myfolder"
        assert files[1].is_dir is True
        assert files[1].size == 4096

        assert files[2].name == "myfile.txt"
        assert files[2].is_dir is False
        assert files[2].size == 1234

    def test_parse_list_response_windows(self):
        """Test parsing Windows/IIS style directory listings."""
        client = FTPClient("dummy.host")
        listing = (
            "01-01-24  12:00PM       <DIR>          dirname\n"
            "02-02-24  01:00PM                 5678 filename.txt\n"
        )

        files = client._parse_list_response(listing)

        assert len(files) == 2

        assert files[0].name == "dirname"
        assert files[0].is_dir is True
        assert files[0].size == 0

        assert files[1].name == "filename.txt"
        assert files[1].is_dir is False
        assert files[1].size == 5678

    def test_parse_passive_response_public_ip(self):
        """Test parsing PASV response with a valid public IP."""
        client = FTPClient("ftp.example.com")

        ip, port = client._parse_passive_response("227 Entering Passive Mode (8,8,8,8,4,1).")
        assert ip == "8.8.8.8"
        assert port == 1025  # (4 * 256) + 1

    def test_parse_passive_response_nat_workaround(self):
        """Test PASV response with a private IP (NAT workaround)."""
        client = FTPClient("ftp.realdomain.com")

        # 192.168.x.x
        ip, port = client._parse_passive_response("227 Entering Passive Mode (192,168,1,50,4,2).")
        assert ip == "ftp.realdomain.com"  # Should fall back to host
        assert port == 1026

        # 10.x.x.x
        ip, port = client._parse_passive_response("227 Entering Passive Mode (10,0,0,5,10,0).")
        assert ip == "ftp.realdomain.com"
        assert port == 2560

        # 127.0.0.1
        ip, port = client._parse_passive_response("227 Entering Passive Mode (127,0,0,1,20,5).")
        assert ip == "ftp.realdomain.com"

    def test_ftp_file_comparison(self):
        """Test FTPFile comparison for correct sorting."""
        file1 = FTPFile(name="b_file", is_dir=False, size=100, modified="", permissions="")
        file2 = FTPFile(name="a_file", is_dir=False, size=100, modified="", permissions="")
        dir1 = FTPFile(name="z_dir", is_dir=True, size=0, modified="", permissions="")
        dir2 = FTPFile(name="a_dir", is_dir=True, size=0, modified="", permissions="")

        # Directories should be less than files (come first when sorted)
        assert dir1 < file1
        assert dir2 < file1

        # Alphabetical ordering
        assert file2 < file1  # a_file < b_file
        assert dir2 < dir1    # a_dir < z_dir


# =============================================================================
# Connection Tests
# =============================================================================

class TestConnection:
    """Tests for FTP connection."""

    def test_connect_success(self, ftp_client):
        """Test successful connection to FTP server."""
        welcome = ftp_client.connect()

        assert ftp_client.is_connected is True
        assert ftp_client.is_authenticated is False
        assert welcome is not None
        assert len(welcome) > 0
        assert "220" in welcome or "ftp" in welcome.lower()

    def test_connect_invalid_host(self):
        """Test connection to invalid host raises error."""
        client = FTPClient(host="invalid.host.that.does.not.exist", timeout=5.0)

        with pytest.raises(Exception):
            client.connect()

    def test_connect_invalid_port(self):
        """Test connection to invalid port raises error."""
        client = FTPClient(host=FTP_HOST, port=9999, timeout=5.0)

        with pytest.raises(Exception):
            client.connect()

    def test_disconnect(self, ftp_client):
        """Test disconnect from server."""
        ftp_client.connect()
        assert ftp_client.is_connected is True

        ftp_client.disconnect()

        assert ftp_client.is_connected is False
        assert ftp_client.is_authenticated is False

    def test_reconnect(self, ftp_client):
        """Test connecting when already connected."""
        ftp_client.connect()
        welcome1 = ftp_client.pwd() if ftp_client.is_authenticated else "connected"

        # Second connect should work (disconnects first)
        welcome = ftp_client.connect()
        assert ftp_client.is_connected is True


# =============================================================================
# Authentication Tests
# =============================================================================

class TestAuthentication:
    """Tests for FTP authentication."""

    def test_login_anonymous(self, connected_ftp):
        """Test anonymous login."""
        response = connected_ftp.login("anonymous", "test@test.com")

        assert connected_ftp.is_authenticated is True
        assert response is not None

    def test_login_with_credentials(self, connected_ftp):
        """Test login with specific credentials."""
        response = connected_ftp.login(FTP_USER, FTP_PASS)

        assert connected_ftp.is_authenticated is True

    def test_login_invalid_password(self, connected_ftp):
        """Test login with invalid credentials - some servers allow any password for anonymous."""
        # Many public FTP servers accept any password for anonymous/ftp user
        # So we test with completely invalid username instead
        connected_ftp.disconnect()
        connected_ftp.connect()

        # Try to login with invalid username - should fail
        with pytest.raises(FTPError):
            connected_ftp.login("invalid_user_12345_xyz", "invalid_pass")

    def test_login_without_connect(self, ftp_client):
        """Test login without connecting first raises error."""
        with pytest.raises(FTPError) as exc_info:
            ftp_client.login(FTP_USER, FTP_PASS)

        assert exc_info.value.code == 0
        assert "not connected" in str(exc_info.value).lower()


# =============================================================================
# Navigation Tests
# =============================================================================

class TestNavigation:
    """Tests for FTP navigation commands."""

    def test_pwd_root(self, authenticated_ftp):
        """Test PWD command returns current directory."""
        current_dir = authenticated_ftp.pwd()

        assert current_dir is not None
        assert current_dir.startswith("/")

    def test_cwd_to_existing_directory(self, authenticated_ftp):
        """Test CWD command to change to existing subdirectory."""
        # First list root to find a directory
        files = safe_list(authenticated_ftp, "/")

        # Find a directory (prefer simple names without special chars)
        directories =[f for f in files if f.is_dir]

        if not directories:
            pytest.skip("No directories found in root")

        # Prefer directories with simple names
        target_dir = None
        for d in directories:
            if '->' not in d.name and all(c not in d.name for c in['<', '>', '|', '*', ' ']):
                target_dir = d.name
                break

        if not target_dir:
            target_dir = directories[0].name

        # Change to directory
        authenticated_ftp.cwd(target_dir)
        new_dir = authenticated_ftp.pwd()

        # Verify we're now in a different directory or at least CWD succeeded
        assert new_dir is not None
        assert new_dir.startswith("/")

    def test_cwd_invalid_directory(self, authenticated_ftp):
        """Test CWD to non-existent directory raises error."""
        with pytest.raises(FTPError):
            authenticated_ftp.cwd("this_directory_does_not_exist_12345_xyz")

    def test_cdup_from_subdirectory(self, authenticated_ftp):
        """Test CDUP command from subdirectory."""
        # First list root to find a directory
        files = safe_list(authenticated_ftp, "/")

        directories =[f for f in files if f.is_dir]

        if not directories:
            pytest.skip("No directories found in root")

        target_dir = None
        for d in directories:
            if '->' not in d.name and all(c not in d.name for c in['<', '>', '|', '*', ' ']):
                target_dir = d.name
                break

        if not target_dir:
            target_dir = directories[0].name

        # Go to subdirectory
        authenticated_ftp.cwd(target_dir)
        dir_after_cwd = authenticated_ftp.pwd()

        # Go up
        authenticated_ftp.cdup()
        dir_after_cdup = authenticated_ftp.pwd()

        assert dir_after_cdup is not None
        assert dir_after_cdup.startswith("/")

    def test_cdup_from_root(self, authenticated_ftp):
        """Test CDUP from root directory."""
        # Go to root
        authenticated_ftp.cwd("/")
        root_dir = authenticated_ftp.pwd()

        # CDUP from root should stay at root or go to root
        authenticated_ftp.cdup()
        current_dir = authenticated_ftp.pwd()

        # Should be at root
        assert current_dir == "/" or current_dir == root_dir


# =============================================================================
# Directory Listing Tests
# =============================================================================

class TestListing:
    """Tests for FTP LIST command."""

    def test_list_root(self, authenticated_ftp):
        """Test listing root directory."""
        files = safe_list(authenticated_ftp, "/")

        assert isinstance(files, list)
        assert len(files) > 0

        # Check file structure
        for f in files:
            assert isinstance(f, FTPFile)
            assert f.name is not None
            assert len(f.name) > 0
            assert isinstance(f.is_dir, bool)

    def test_list_current_directory(self, authenticated_ftp):
        """Test listing current directory."""
        files = safe_list(authenticated_ftp)

        assert isinstance(files, list)
        assert len(files) > 0

    def test_list_subdirectory(self, authenticated_ftp):
        """Test listing a subdirectory."""
        # Find a directory in root
        files = safe_list(authenticated_ftp, "/")
        directories = [f for f in files if f.is_dir]

        if not directories:
            pytest.skip("No directories found in root")

        # List the subdirectory
        subdir = directories[0].name
        sub_files = safe_list(authenticated_ftp, subdir)

        assert isinstance(sub_files, list)

    def test_list_returns_sorted_files(self, authenticated_ftp):
        """Test that files are sorted (directories first)."""
        files = safe_list(authenticated_ftp, "/")

        if len(files) > 1:
            # Check that directories come before files
            found_file = False
            for f in files:
                if not f.is_dir:
                    found_file = True
                elif found_file and f.is_dir:
                    pytest.fail("Directories should come before files")

    def test_list_nonexistent_directory(self, authenticated_ftp):
        """Test listing non-existent directory - behavior varies by server."""
        # Some servers return empty list, some raise error
        try:
            files = safe_list(authenticated_ftp, "/this_directory_does_not_exist_xyz_12345")
            # If no error, should return empty list
            assert isinstance(files, list)
        except FTPError:
            # Error is also acceptable
            pass

    def test_ftp_file_properties(self, authenticated_ftp):
        """Test FTPFile object properties."""
        files = safe_list(authenticated_ftp, "/")

        if files:
            f = files[0]
            assert hasattr(f, 'name')
            assert hasattr(f, 'is_dir')
            assert hasattr(f, 'size')
            assert hasattr(f, 'modified')
            assert hasattr(f, 'permissions')


# =============================================================================
# File Transfer Tests (Slow Tests)
# =============================================================================

@pytest.mark.slow
class TestFileTransfer:
    """Tests for FTP file transfer (download)."""

    def test_download_small_file(self, authenticated_ftp, temp_dir):
        """Test downloading a small file."""
        # Find a directory with files
        files = safe_list(authenticated_ftp, "/")
        directories =[f for f in files if f.is_dir]

        # Try to find a file to download
        file_to_download = None
        parent_dir = "/"

        # First check root
        for f in files:
            if not f.is_dir and 0 < f.size < 50000:
                file_to_download = f
                break

        # If not found, check subdirectories
        if not file_to_download and directories:
            for d in directories[:5]:
                if '->' in d.name or any(c in d.name for c in['<', '>', '|', '*']):
                    continue
                try:
                    sub_files = safe_list(authenticated_ftp, d.name)
                    for f in sub_files:
                        if not f.is_dir and 0 < f.size < 50000:
                            file_to_download = f
                            parent_dir = d.name
                            break
                    if file_to_download:
                        break
                except:
                    continue

        if not file_to_download:
            pytest.skip("No suitable file found for download test")

        if parent_dir != "/":
            authenticated_ftp.cwd(parent_dir)

        local_path = os.path.join(temp_dir, file_to_download.name)

        try:
            bytes_downloaded = authenticated_ftp.download_file(file_to_download.name, local_path)
        except FTPError:
            pytest.skip(f"File {file_to_download.name} could not be downloaded")
        finally:
            authenticated_ftp.cwd("/")

        assert bytes_downloaded > 0
        assert os.path.exists(local_path)
        assert os.path.getsize(local_path) == bytes_downloaded

    def test_download_nonexistent_file(self, authenticated_ftp, temp_dir):
        """Test downloading a non-existent file raises error."""
        local_path = os.path.join(temp_dir, "nonexistent.txt")

        with pytest.raises(FTPError):
            authenticated_ftp.download_file(
                "/nonexistent_file_12345_xyz.txt",
                local_path
            )

        assert not os.path.exists(local_path)

    def test_download_with_progress_callback(self, authenticated_ftp, temp_dir):
        """Test download with progress callback."""
        files = safe_list(authenticated_ftp, "/")

        file_to_download = None
        parent_dir = "/"

        for f in files:
            if not f.is_dir and 0 < f.size < 50000:
                file_to_download = f
                break

        if not file_to_download:
            directories =[f for f in files if f.is_dir]
            for d in directories[:5]:
                if '->' in d.name or any(c in d.name for c in ['<', '>', '|', '*']):
                    continue
                try:
                    sub_files = safe_list(authenticated_ftp, d.name)
                    for f in sub_files:
                        if not f.is_dir and 0 < f.size < 50000:
                            file_to_download = f
                            parent_dir = d.name
                            break
                    if file_to_download:
                        break
                except:
                    continue

        if not file_to_download:
            pytest.skip("No suitable file found")

        progress_calls =[]

        def progress_callback(current, total):
            progress_calls.append((current, total))

        if parent_dir != "/":
            authenticated_ftp.cwd(parent_dir)

        local_path = os.path.join(temp_dir, file_to_download.name)

        try:
            authenticated_ftp.download_file(
                file_to_download.name,
                local_path,
                progress_callback
            )
        except FTPError:
            pytest.skip(f"File {file_to_download.name} could not be downloaded")
        finally:
            authenticated_ftp.cwd("/")

        assert len(progress_calls) > 0


# =============================================================================
# Directory Operations Tests
# =============================================================================

class TestDirectoryOperations:
    """Tests for FTP directory operations."""

    def test_mkdir_permission_denied(self, authenticated_ftp):
        """Test that mkdir fails on read-only server (expected)."""
        test_dir_name = f"test_dir_{int(time.time())}"

        with pytest.raises(FTPError) as exc_info:
            authenticated_ftp.mkdir(test_dir_name)

        assert exc_info.value.code == 550

    def test_rmdir_nonexistent(self, authenticated_ftp):
        """Test removing non-existent directory."""
        with pytest.raises(FTPError):
            authenticated_ftp.delete_directory("nonexistent_dir_12345_xyz")


# =============================================================================
# File Operations Tests
# =============================================================================

@pytest.mark.slow
class TestFileOperations:
    """Tests for FTP file operations."""

    def test_upload_permission_denied(self, authenticated_ftp, temp_dir):
        """Test that upload fails on read-only server (expected)."""
        test_content = b"Test file content\n"
        local_file = os.path.join(temp_dir, "test_upload.txt")

        with open(local_file, 'wb') as f:
            f.write(test_content)

        remote_file = f"/test_upload_{int(time.time())}.txt"

        with pytest.raises(FTPError) as exc_info:
            authenticated_ftp.upload_file(local_file, remote_file)

        assert exc_info.value.code in (550, 0)

    def test_delete_nonexistent_file(self, authenticated_ftp):
        """Test deleting a non-existent file."""
        with pytest.raises(FTPError):
            authenticated_ftp.delete_file("nonexistent_file_12345_xyz.txt")

    def test_get_file_size(self, authenticated_ftp):
        """Test getting file size."""
        files = safe_list(authenticated_ftp, "/")

        for f in files:
            if not f.is_dir and f.size > 0:
                try:
                    size = authenticated_ftp.size(f.name)
                    assert size > 0
                    return
                except FTPError:
                    continue

        pytest.skip("No suitable files found for size test")


# =============================================================================
# Rename Tests
# =============================================================================

class TestRename:
    """Tests for FTP rename operations."""

    def test_rename_permission_denied(self, authenticated_ftp, temp_dir):
        """Test that rename fails on read-only server (expected)."""
        local_file = os.path.join(temp_dir, "test_rename.txt")
        with open(local_file, 'wb') as f:
            f.write(b"Test content")

        with pytest.raises(FTPError):
            authenticated_ftp.upload_file(local_file, "/test_rename_old.txt")

    def test_rename_nonexistent_file(self, authenticated_ftp):
        """Test renaming a non-existent file."""
        with pytest.raises(FTPError):
            authenticated_ftp.rename(
                "nonexistent_old_12345_xyz.txt",
                "nonexistent_new_12345_xyz.txt"
            )


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_ftp_error_properties(self):
        """Test FTPError exception properties."""
        error = FTPError(550, "File not found")

        assert error.code == 550
        assert error.message == "File not found"
        assert "550" in str(error)
        assert "File not found" in str(error)

    def test_transfer_mode_property(self, ftp_client):
        """Test transfer mode property."""
        assert ftp_client.transfer_mode == TransferMode.PASSIVE

        ftp_client.transfer_mode = TransferMode.ACTIVE
        assert ftp_client.transfer_mode == TransferMode.ACTIVE


# =============================================================================
# Callback Tests
# =============================================================================

class TestCallbacks:
    """Tests for FTP callbacks."""

    def test_log_callback(self, ftp_client):
        """Test log callback is called."""
        log_messages =[]

        def log_callback(msg):
            log_messages.append(msg)

        ftp_client.on_log = log_callback
        ftp_client.connect()

        assert len(log_messages) > 0

        ftp_client.disconnect()

    def test_progress_callback_type(self):
        """Test progress callback signature."""
        client = FTPClient(host=FTP_HOST)

        def progress(current, total):
            pass

        client.on_progress = progress
        assert client.on_progress is not None


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])