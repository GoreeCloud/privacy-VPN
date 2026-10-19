"""Secret-handling and create-only output primitives."""
import os
import stat
from pathlib import Path
from .model import Invalid, key


def read_secret(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(Path(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_size > 128:
                raise Invalid("Private key must be a regular mode-0600 file")
            with os.fdopen(os.dup(fd), "r", encoding="ascii") as handle:
                secret = handle.read().strip()
            return key(secret)
        finally:
            os.close(fd)
    except (OSError, UnicodeError) as err:
        raise Invalid("Unable to safely read the private key") from err


def write_files(destination, files):
    path = Path(destination)
    if path.is_symlink():
        raise Invalid("Output directory cannot be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.stat().st_mode & 0o077:
        raise Invalid("Output directory must be mode 0700")
    if any((path / name).exists() or (path / name).is_symlink() for name in files):
        raise Invalid("Refusing to overwrite previously generated files")
    created = []
    try:
        for name, text in files.items():
            output = path / name
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            created.append(output)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
    except Exception:
        for output in created:
            output.unlink(missing_ok=True)
        raise
    return len(created)
