"""APK (apk-tools 3, OpenWrt 24.10+/SNAPSHOT) inventory parser.

The installed database at /lib/apk/db/installed is a sequence of blank-line
separated records with one-letter fields: ``P:`` name, ``V:`` version,
``A:`` architecture, ``o:`` origin, ``T:`` description.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

DB_PATH = "/lib/apk/db/installed"
WORLD_PATH = "/etc/apk/world"
REPOSITORIES_PATH = "/etc/apk/repositories"
REPO_DIR = "/etc/apk/repositories.d"


@dataclass(frozen=True)
class PackageEntry:
    name: str
    version: str
    arch: str = ""
    description: str = ""
    source: str = "db"

    def as_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "arch": self.arch,
            "description": self.description,
            "source": self.source,
        }


def parse_installed(lines: List[str]) -> List[PackageEntry]:
    entries: List[PackageEntry] = []
    current: Dict[str, str] = {}
    for line in lines:
        if not line.strip():
            if current.get("P"):
                entries.append(
                    PackageEntry(
                        name=current["P"],
                        version=current.get("V", ""),
                        arch=current.get("A", ""),
                        description=current.get("T", ""),
                    )
                )
            current = {}
            continue
        if len(line) > 2 and line[1] == ":":
            key = line[0]
            value = line[2:]
            current.setdefault(key, value)
    if current.get("P"):
        entries.append(
            PackageEntry(
                name=current["P"],
                version=current.get("V", ""),
                arch=current.get("A", ""),
                description=current.get("T", ""),
            )
        )
    entries.sort(key=lambda item: item.name)
    return entries


def parse_world(lines: List[str]) -> List[str]:
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def parse_repositories(lines: List[str]) -> List[str]:
    """Keep only real repository locations, drop comments and blank lines."""
    result: List[str] = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.split()[0].startswith(("http://", "https://", "ftp://", "file://", "/")):
            result.append(text)
    return result
