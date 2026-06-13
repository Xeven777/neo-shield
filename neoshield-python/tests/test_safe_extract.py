from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from neoshield.worker.github_client import GithubError, safe_extract


def _archive(path: Path) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        add("owner-repo-sha/README.md", b"hello")
        add("owner-repo-sha/src/app.py", b"print('ok')")

        traversal = tarfile.TarInfo("owner-repo-sha/../../escape.txt")
        traversal.size = 4
        archive.addfile(traversal, io.BytesIO(b"evil"))

        link = tarfile.TarInfo("owner-repo-sha/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)

        big = tarfile.TarInfo("owner-repo-sha/big.txt")
        big.size = 40
        archive.addfile(big, io.BytesIO(b"x" * 40))

    return path


def test_safe_extract_strips_root_and_skips_hostile_entries(tmp_path: Path) -> None:
    archive = _archive(tmp_path / "repo.tar.gz")
    destination = tmp_path / "out"

    extracted = safe_extract(
        archive,
        destination,
        max_files=10,
        max_file_bytes=16,
        max_total_bytes=1024,
    )

    assert extracted == 2
    assert (destination / "README.md").read_text() == "hello"
    assert (destination / "src" / "app.py").exists()
    assert not (tmp_path / "escape.txt").exists()
    assert not (destination / "link").exists()
    assert not (destination / "big.txt").exists()


def test_safe_extract_enforces_file_count(tmp_path: Path) -> None:
    archive = _archive(tmp_path / "repo.tar.gz")

    with pytest.raises(GithubError):
        safe_extract(
            archive,
            tmp_path / "out",
            max_files=1,
            max_file_bytes=1024,
            max_total_bytes=1024,
        )
