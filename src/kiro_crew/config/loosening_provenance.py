"""Whole-file content provenance for the sandbox-sealed keystone config files.

The Linux namespace sandbox seals ``config.json``, ``config.local.json``,
``denied_commands.json`` and ``computer_use.json`` read-only with a per-FILE
read-only bind. Every legitimate writer publishes through ``atomic_write`` (temp
file + ``rename``), and the kernel detaches a file bind whose target is renamed
over from another mount namespace. So the seal on one of these files holds from a
sandbox's spawn only until the gateway's NEXT save of that file, after which a
prompt-injected agent that lands a direct ``open(..., "w")`` in that window can
rewrite it -- turning ``agent.sandbox`` off, clearing the denied-command deny-all,
auto-approving tools, enabling computer use -- and the gateway then reads the
agent's own file as if the operator had written it.

This module closes that WITHOUT depending on the bind holding and WITHOUT a list of
keys to keep current: every gateway write stores the exact bytes it is about to publish
as the ENDORSED COPY before the rename (:func:`endorsing`), and every read -- the load
AND the read half of a read-modify-write -- serves the endorsed copy whenever the
on-disk bytes differ from it, so a later unrelated save cannot re-endorse a tampered
file. Every key is covered, tightening and loosening alike; there is
no key table. The gateway's next legitimate write overwrites both the file and the
endorsed copy, so a tampered file self-heals on the next save.

**Where it applies.** The per-file bind, and the rename-detach that lapses it, exist
ONLY in the Linux namespace sandbox. Off Linux, and on a Linux host where that
sandbox cannot be built (a container without user namespaces), nothing ever seals
these files, so the loaders serve the on-disk file unchanged
(:func:`enforcement_active`). The decision reads HOST FACTS only (platform + userns),
never the file it is protecting, so writing ``sandbox: off`` cannot switch it off.

**Trade-off, stated.** Where it applies, a hand edit to one of these files is ignored
until it is made through the gateway (the dashboard Settings pages, the config API, or
``kirocrew config``), which records a fresh endorsed copy. Kiro Crew's users have no
terminal; the supported way to change these settings is Settings, so this is the
accepted cost of not enumerating keys.

The endorsed copies live under the ``config-provenance`` directory of the data home.
That directory is a read-only DIRECTORY bind in every sandbox
(``sandbox_leaves._CREW_READONLY_LEAVES``), and a directory bind does NOT suffer the
rename-detach: the gateway's writes land on files INSIDE it and leave the directory's
own inode -- what the bind pins -- unchanged. So no sandboxed process can write or
replace an endorsed copy. A copy of ``config.json`` can hold an inline channel token,
but it is no more exposed than ``config.json`` itself: both are readable in-sandbox
(neither is on the read-gate floor), and the copy is written owner-only (0o600).

``docs/system-specs/modules/security.md`` and ``config.md`` describe the seal and
this content check together.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from collections.abc import Iterator
from pathlib import Path

from kiro_crew.atomic_write import atomic_write
from kiro_crew.config.paths import config_dir

logger = logging.getLogger("kiro_crew.config.loader")

#: The sealed data-home directory the endorsed copies live under -- shared with
#: ``write_provenance`` (a read-only, no-follow, pre-created DIRECTORY bind in every
#: sandbox).
RECORD_DIR_LEAF = "config-provenance"
#: The sub-directory holding one endorsed copy per protected leaf.
ENDORSED_SUBDIR = "endorsed"
#: Owner-only on both directory levels and the copies: a copy can carry an inline
#: credential, exactly like the file it mirrors, and the data home leaves nothing
#: readable by other local users (test_owner_only_boot).
_DIR_MODE = 0o700
_FILE_MODE = 0o600

LEAF_CONFIG = "config.json"
LEAF_CONFIG_LOCAL = "config.local.json"
LEAF_DENIED_COMMANDS = "denied_commands.json"
LEAF_COMPUTER_USE = "computer_use.json"

PROTECTED_LEAVES: tuple[str, ...] = (
    LEAF_CONFIG,
    LEAF_CONFIG_LOCAL,
    LEAF_DENIED_COMMANDS,
    LEAF_COMPUTER_USE,
)

#: Leaves whose on-disk file has already been reported as differing from the endorsed
#: copy, so the substitution is logged once per leaf per process. A lost race only
#: duplicates a log line.
_reported: set[str] = set()


def enforcement_active() -> bool:
    """True only where the Linux per-file read-only bind can actually detach.

    The substitution matters only when the namespace sandbox seals these files. Off
    Linux (Windows, macOS), and on a Linux host where the namespace sandbox cannot be
    built (a container without user namespaces), there is no per-file bind to lapse, so
    the loaders serve the on-disk file unchanged. HOST FACTS only (platform + userns),
    so it never reads the file it protects and never recurses into a config load; cached
    by the probe it defers to. Fails toward ENFORCING on Linux: a Linux host whose probe
    raises is treated as sandbox-capable, so the check is not silently dropped where the
    threat may be real.
    """
    if sys.platform != "linux":
        return False
    try:
        from kiro_crew.sandbox import userns_available

        return bool(userns_available())
    except Exception:
        logger.debug("loosening provenance: userns probe failed; enforcing", exc_info=True)
        return True


def _endorsed_dir() -> Path:
    return config_dir() / RECORD_DIR_LEAF / ENDORSED_SUBDIR


def _endorsed_path(leaf: str) -> Path:
    return _endorsed_dir() / leaf


def leaf_for(path: Path) -> str | None:
    """The protected leaf *path* is, or ``None`` for any other file.

    Matched by RESOLVED identity against each protected name under the data home -- the
    same rule as ``write_provenance.staging_hook`` -- so a symlinked ``config.json``
    written through to its target (``crew-settings.json`` in a dotfiles repo) is still
    endorsed as ``config.json``, and a file elsewhere that merely shares a protected
    basename is never mistaken for one.
    """
    try:
        target = path.resolve()
        home = config_dir()
        return next((leaf for leaf in PROTECTED_LEAVES if (home / leaf).resolve() == target), None)
    except OSError:
        return None


def record(leaf: str, content: bytes, *, strict: bool = False) -> None:
    """Store *content* as the gateway-endorsed copy of *leaf*.

    A failed write leaves the PREVIOUS copy in place (``atomic_write`` never leaves it
    half-written): removing it would hand the next load the on-disk bytes, i.e. drop
    the content check exactly when a disk is full. *strict* re-raises the failure, for a
    writer that must not publish what it could not endorse (:func:`endorsing`).
    """
    if leaf not in PROTECTED_LEAVES:
        return
    try:
        # Owner-only on BOTH levels: parents=True would create config-provenance with
        # the umask default, which test_owner_only_boot refuses.
        (config_dir() / RECORD_DIR_LEAF).mkdir(mode=_DIR_MODE, exist_ok=True)
        _endorsed_dir().mkdir(mode=_DIR_MODE, exist_ok=True)
        atomic_write(_endorsed_path(leaf), content, mode=_FILE_MODE)
    except Exception:
        if strict:
            raise
        logger.warning(
            "loosening provenance: could not record the endorsed copy for %s; "
            "the previous copy stays in effect",
            leaf,
            exc_info=True,
        )


@contextlib.contextmanager
def endorsing(leaf: str | None, content: bytes) -> Iterator[None]:
    """Endorse *content* for *leaf* BEFORE the ``with`` body publishes it.

    *content* is the writer's own bytes, never a re-read of the destination, so nothing
    an in-sandbox process lands on the name around the rename can be endorsed. Where the
    sandbox seals these files (:func:`enforcement_active`) the endorsement is required:
    a copy that cannot be read or written aborts the write before anything is
    published, so the gateway never publishes a protected file it has not endorsed; a
    publish that then fails puts the previous copy back. Elsewhere it is best-effort and
    never blocks a save. ``leaf=None`` (not a protected file) is a no-op.
    """
    if leaf is None or leaf not in PROTECTED_LEAVES:
        yield
        return
    enforcing = enforcement_active()
    prior = endorsed_bytes(leaf)  # raises under enforcement when the copy is unreadable
    record(leaf, content, strict=enforcing)
    try:
        yield
    except BaseException:
        if enforcing:
            try:
                if prior is None:
                    _endorsed_path(leaf).unlink(missing_ok=True)
                else:
                    record(leaf, prior, strict=True)
            except Exception:
                logger.warning(
                    "loosening provenance: could not restore the endorsed copy for %s "
                    "after a failed write",
                    leaf,
                    exc_info=True,
                )
        raise


def endorsed_bytes(leaf: str) -> bytes | None:
    """The gateway-endorsed copy of *leaf*, or ``None`` when there is none.

    Where the sandbox seals these files, a copy that EXISTS but cannot be read raises
    (``OSError``) rather than reading as "none": "none" serves the on-disk bytes, so a
    read error would silently drop the content check. Every reader already maps an
    ``OSError`` to its unreadable-file path (defaults, refuse the write, disabled).
    """
    try:
        return _endorsed_path(leaf).read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        if enforcement_active():
            raise
        logger.debug("loosening provenance: endorsed copy for %s unreadable", leaf, exc_info=True)
        return None


def reconcile(leaf: str, disk_bytes: bytes) -> bytes:
    """Return the bytes the loader should parse for *leaf*.

    Where the sandbox seals these files (:func:`enforcement_active`): when the on-disk
    bytes differ from the gateway-endorsed copy, the endorsed copy is returned and the
    substitution is logged once -- so a direct in-sandbox rewrite of ANY key is ignored.
    Elsewhere, or when there is no endorsed copy yet (the first boot before adoption, a
    window in which no sandbox has run to tamper), the on-disk bytes are returned
    unchanged. A missing copy is not reachable by a sandbox: every gateway publish of
    these files endorses first (:func:`endorsing`), and an absent name is pre-created and
    sealed until such a publish, so a file with no copy is one no rename has unsealed.
    An existing but unreadable copy raises ``OSError`` (:func:`endorsed_bytes`).
    """
    if not enforcement_active():
        return disk_bytes
    endorsed = endorsed_bytes(leaf)
    if endorsed is None or endorsed == disk_bytes:
        return disk_bytes
    if leaf not in _reported:
        _reported.add(leaf)
        logger.warning(
            "%s on disk is not the gateway's own write; using the gateway-endorsed copy "
            "(a hand edit takes effect only when saved through the dashboard or config API)",
            leaf,
        )
    return endorsed


# --- One-time upgrade adoption ------------------------------------------------
#
# An install that predates this feature has the protected files but no endorsed copy.
# With no copy to serve, a load returns the on-disk file unchanged, so the first gateway
# boot endorses whatever is on disk and logs it once; after that the copy exists and is
# never re-adopted, so a later in-sandbox rewrite is overridden by the adopted copy. A
# file tampered BEFORE that first boot is adopted as written -- the one case this cannot
# catch, documented as a known limit.


def adopt_if_unendorsed(leaf: str, content: bytes) -> bool:
    """Endorse *content* for *leaf* only when there is no endorsed copy yet."""
    if leaf not in PROTECTED_LEAVES:
        return False
    if _endorsed_path(leaf).exists():
        return False
    record(leaf, content)
    logger.info(
        "loosening provenance: adopted the existing %s as endorsed (one-time, on upgrade)",
        leaf,
    )
    return True


def adopt_unendorsed() -> list[str]:
    """Boot sweep: endorse each protected file that has no endorsed copy yet.

    Called once from ``GatewayOrchestrator.run`` (the entry both the CLI gateway and the
    in-process test gateway reach), BEFORE any session or sandbox runs. A missing file is
    skipped: there is nothing to endorse and a load returns the on-disk file (its safe
    default) anyway. Returns the leaves adopted.
    """
    adopted: list[str] = []
    home = config_dir()
    for leaf in PROTECTED_LEAVES:
        try:
            content = (home / leaf).read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            logger.debug(
                "loosening provenance: could not read %s for adoption", leaf, exc_info=True
            )
            continue
        if adopt_if_unendorsed(leaf, content):
            adopted.append(leaf)
    return adopted
