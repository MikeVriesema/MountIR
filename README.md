# MountIR

```
    __  ___                  __  ________
   /  |/  /___  __  ______  / /_/  _/ __ \
  / /|_/ / __ \/ / / / __ \/ __// // /_/ /
 / /  / / /_/ / /_/ / / / / /__/ // _, _/
/_/  /_/\____/\__,_/_/ /_/\__/___/_/ |_|
```

**Forensic-grade disk image mounting for incident response.**

MountIR mounts disk images **read-only** so analysts can browse evidence
filesystems without altering them. It auto-detects the image format, mounts the
container, enumerates partitions (including LVM), and applies forensic mount
flags (`ro,noatime,noexec,norecovery`). It tracks every mount in a state file so
cleanup is reliable, and speaks JSON for pipeline orchestration.

> ⚠️ MountIR is a **Linux** tool and requires **root/sudo**. All mounts are
> read-only by default to preserve forensic integrity.

---

## Supported formats

| Format | Extensions | Primary tool | Fallback | Verified |
| --- | --- | --- | --- | --- |
| **E01 / L01** | `.e01`, `.l01` | `ewfmount` | – | ✅ |
| **Ex01 / Lx01** *(EWF v2)* | `.ex01`, `.lx01` | `ewfmount` † | – | |
| **DD / Raw / IMG** | `.dd`, `.raw`, `.img`, `.bin`, `.001` | `losetup` | – | ✅ |
| **VMDK** | `.vmdk` | `qemu-nbd` | `vmdkmount` | |
| **VHD / VHDX** | `.vhd`, `.vhdx` | `qemu-nbd` | `vhdimount` | |
| **QCOW2** | `.qcow2`, `.qcow` | `qemu-nbd` | – | |
| **ISO** | `.iso` | `mount -o loop` | – | |
| **AFF** | `.aff` | `affuse` | – | |

**✅ Verified** = confirmed mounted end-to-end against **real evidence images**:

- **E01** — validated on both a single-volume **NTFS** image (no partition
  table) and a partitioned **ext4** Linux image.
- **DD / Raw / IMG** — validated via the `losetup` raw path.

Unmarked formats are implemented and covered by the unit-test suite, but have
not yet been confirmed against real-world samples — treat them as supported but
unverified until you've validated one in your environment.

> **† EWF v2 (Ex01/Lx01) needs modern libewf.** The distro `ewf-tools` package
> is the frozen 2014 *legacy* libewf line (`20140807`), which only reads EWF v1
> (E01/L01). `mountir setup` builds the maintained libyal release from source
> (pinned to `20240506`) so `ewfmount` can also open EnCase v7 Ex01/Lx01
> containers — see [Built from source](#built-from-source).

Detection uses the file extension first, then falls back to `file(1)` magic
bytes, so correctly-formatted images with the wrong extension still mount.
Multi-segment EWF sets (`.E01`/`.E02`/…) and split raw (`.001`/`.002`/…) are
handled automatically — just point MountIR at the first segment.

<details>
<summary>Additional formats the engine also handles</summary>

AFF4 (`.aff4`), VirtualBox VDI (`.vdi`), OVA (`.ova`), Apple DMG (`.dmg`) and
sparseimage/sparsebundle, and Xen XVA (`.xva`). These ship with handlers but are
outside the core IR set above; tool availability varies by distro.
</details>

---

## Features

- **Read-only by default** — forensic mount flags `ro,noatime,noexec,norecovery`
  applied per filesystem.
- **Automatic format detection** via extension + `file(1)` magic.
- **Robust filesystem detection** — probes each partition with `blkid -p`
  (low-level, works on freshly-attached loop devices), falling back to `lsblk`
  and `file(1)` magic, then mounts with driver fallbacks (e.g. `ntfs3` →
  `ntfs-3g`) and a final auto-detect attempt. Reports a best-effort **OS guess**
  (Windows / Linux / macOS).
- **Partition detection** with `fdisk`/`blkid`, plus **LVM** discovery and
  activation.
- **State tracking** — every mount is recorded so `unmount` and `list` are
  reliable, and stale mounts (e.g. after a reboot) are flagged. `clean`
  scavenges orphaned mounts from the mount base.
- **JSON I/O** for orchestration (Whirlpool) and an optional **Maelstrom**
  post-mount collection callback.
- **Self-bootstrapping** — on first run MountIR pulls every dependency it can
  (see below).

---

## Requirements

- **Linux** (Debian/Ubuntu recommended for automatic dependency install).
- **Python 3.8+**.
- **root / sudo** for `mount` and `unmount`.

### Why root is required

Mounting evidence is a privileged kernel operation — `mount(2)`, loop devices
(`losetup`), the NBD module (`qemu-nbd`/`modprobe nbd`), `kpartx`, and LVM all
need `CAP_SYS_ADMIN`. There is **no way around this**: `mount` and `unmount`
must run as root, and aliasing or symlinking `mountir` changes only the command
*name*, not the privileges — you will still run `sudo mountir mount …`.

The read-only commands **`list`** and **`check`** do **not** need root.

| Command | Root needed? |
| --- | --- |
| `mount`, `unmount`, `clean` | ✅ yes (`sudo`) |
| `setup` / `install-deps` | ✅ yes (installs apt packages) |
| `list`, `check` | ❌ no |

---

## Installation & first run

```bash
# Clone or copy the project so the package directory is named "MountIR"
cd /opt   # (anywhere on your PATH-able tree)
git clone <repo> MountIR

# First run pulls ALL dependencies automatically (Python + system tools):
sudo python3 MountIR/mountir.py setup
```

**On its first invocation MountIR bootstraps itself.** It will:

1. **Create a project-local virtualenv** (`.venv/`) and install the pinned
   Python dependencies **into it** — never into the system/root interpreter, so
   it won't pollute the OS Python or trip PEP 668
   (`externally-managed-environment`) on modern Debian/Ubuntu.
2. **Re-launch itself inside that venv** so the dependencies load from there.
3. `apt-get install` any missing system forensic tools (E01, qemu, AFF, …).

The venv lives in the project directory and is reused on later runs (deps are
only installed when the venv is first created or via `setup`). A marker
(`/var/lib/mountir/.bootstrapped`, falling back to the project directory) records
that the system-tool step has run, so it only happens once. You can also trigger
the whole thing explicitly at any time:

```bash
sudo python3 mountir.py setup     # re-run the full dependency install
python3 mountir.py check          # report what is / isn't installed
```

**Opting out of auto-bootstrap:** pass `--no-setup` or set the environment
variable `MOUNTIR_NO_BOOTSTRAP=1`. MountIR then runs against the current
interpreter and skips both the venv and the system-tool install — in that case
install `colorama` yourself (optional; output just won't be coloured without it).

## Run `mountir` as a system command

So you can call `mountir` from anywhere instead of `python3 /path/to/mountir.py`,
put it on your `PATH`. **Recommended:** make the entry point executable and
symlink it into `/usr/local/bin` (already on every user's `PATH`):

```bash
sudo chmod +x /opt/MountIR/mountir.py
sudo ln -s /opt/MountIR/mountir.py /usr/local/bin/mountir
```

The script's shebang (`#!/usr/bin/env python3`) and `__file__` resolution handle
the rest — the symlink resolves back to the real project, finds its `.venv`, and
re-launches inside it automatically. Now:

```bash
sudo mountir mount /evidence/disk.E01     # mount/unmount need root
mountir list                              # list/check do not
mountir check
```

> **You still need `sudo` for `mount`/`unmount`.** The symlink only renames the
> command; it can't grant privileges. See [Why root is required](#why-root-is-required).

### Optional: a `mountir` that elevates itself

If you'd rather not type `sudo` for mounts, install a small wrapper that elevates
only when needed. Replace the symlink above with:

```bash
sudo tee /usr/local/bin/mountir >/dev/null <<'EOF'
#!/usr/bin/env bash
# Run privileged subcommands under sudo automatically.
case "$1" in
  mount|unmount|setup|install-deps)
    [ "$(id -u)" -ne 0 ] && exec sudo /opt/MountIR/mountir.py "$@" ;;
esac
exec /opt/MountIR/mountir.py "$@"
EOF
sudo chmod +x /usr/local/bin/mountir /opt/MountIR/mountir.py
```

Now `mountir mount /evidence/disk.E01` prompts for `sudo` itself, while
`mountir list` / `check` run unprivileged. (A passwordless alternative is a
`sudoers` `NOPASSWD` rule for the script — only if your environment allows it.)

> **Shell `alias` won't work for this** — aliases aren't expanded after `sudo`,
> and they only exist in interactive shells. Use a symlink or wrapper in
> `/usr/local/bin` as above.

---

## Dependencies

All dependencies are **pinned**. Python deps live in `requirements.txt`
(runtime) and `requirements-dev.txt` (tests), and are installed into the
project-local `.venv/` by the first-run bootstrap (or `mountir setup`).

### Python packages

| Package | Version | Purpose |
| --- | --- | --- |
| `colorama` | `0.4.6` | Cross-platform coloured terminal output |
| `pytest` *(dev)* | `9.0.3` | Test runner (`requirements-dev.txt`) |

`mountir setup` installs these into `.venv/` for you. To manage them manually:

```bash
python3 -m pip install -r requirements.txt        # runtime
python3 -m pip install -r requirements-dev.txt     # + tests
```

### System packages (apt)

Installed automatically by `mountir setup`. The canonical mapping lives in
[`bootstrap.py`](bootstrap.py) (`SYSTEM_PACKAGES`):

| Tool(s) | apt package | Used for |
| --- | --- | --- |
| `ewfmount` | `ewf-tools` | E01 / L01 (apt is the 2014 legacy line; Ex01/Lx01 need [modern libewf](#built-from-source)) |
| `qemu-nbd` | `qemu-utils` | VMDK, VHD/VHDX, QCOW2, VDI (primary) |
| `affuse` | `afflib-tools` | AFF |
| `vmdkmount` | `libvmdk-utils` | VMDK (fallback) |
| `vhdimount` | `libvhdi-utils` | VHD/VHDX (fallback) |
| `kpartx` | `kpartx` | Partition device mapping |
| `pvs` | `lvm2` | LVM detection / activation |
| `fusermount` | `fuse` | FUSE unmounting |
| `ntfs-3g` | `ntfs-3g` | NTFS mounting |
| `mmls` | `sleuthkit` | Partition layout |
| `fdisk`, `blkid`, `losetup`, `mount` | `util-linux` | Loop devices, partitions, mounting |
| `file` | `file` | Magic-byte format detection |

Manual install on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install ewf-tools qemu-utils afflib-tools libvmdk-utils \
                     libvhdi-utils kpartx lvm2 fuse ntfs-3g sleuthkit \
                     util-linux file
```

### Built from source

Two drivers aren't in apt (or are too old there), so `mountir setup` builds them
from source into `/usr/local/bin` — best-effort, so a failed optional build
warns but never aborts setup:

| Tool | Source | Adds |
| --- | --- | --- |
| `apfs-fuse` | [sgan81/apfs-fuse](https://github.com/sgan81/apfs-fuse) | read-only APFS (macOS) — no apt package exists |
| `ewfmount` *(libewf)* | [libyal/libewf](https://github.com/libyal/libewf) | EWF v2 **Ex01/Lx01** — apt ships only the 2014 legacy line |

The from-source `ewfmount` lands in `/usr/local/bin` and shadows the apt one.
The libewf build is **pinned to `20240506`** for forensic reproducibility (you
want to know exactly which tool version touched the evidence). To pull a
different release, set the version and force a rebuild over the existing install:

```bash
sudo MOUNTIR_LIBEWF_VERSION=20240506 mountir setup --force
```

> ⚠️ Bumping libewf is deliberate: a newer upstream release may change tool
> behaviour or fail to build. The pin is the tested default — only override it
> if you specifically need another version.

`mountir check` reports the installed `ewfmount` version and whether it can read
Ex01/Lx01.

---

## Usage

Invoke MountIR in any of these equivalent ways:

```bash
sudo python3 mountir.py <command> ...        # direct
sudo python3 -m MountIR.mountir <command> ... # as a module (run from parent dir)
sudo mountir <command> ...                    # if symlinked onto PATH
```

### Mount a forensic disk image

```bash
sudo mountir mount <image-path> \
  [--mount-base DIR] [--case-id ID] [--no-partitions] \
  [--json-input FILE] [--maelstrom] [--maelstrom-profiles PROFILE ...] \
  [-v] [--json]
```

| Option | Description |
| --- | --- |
| `--mount-base DIR` | Base directory for mount points (default `/mnt/mountir`) |
| `--case-id ID` | Case identifier, used in mount-point naming |
| `--no-partitions` | Mount the container only; skip partition detection |
| `--json-input FILE` | Read the mount request from a JSON file (`-` = stdin) |
| `--maelstrom` | Run Maelstrom on mounted filesystems after mounting |
| `--maelstrom-profiles ...` | Profiles to pass to Maelstrom |
| `-v`, `--verbose` | Verbose logging |
| `--json` | Emit machine-readable JSON to stdout |

### Unmount a mounted image

```bash
sudo mountir unmount <mount-id-or-path> [-v] [--json]
sudo mountir unmount --all                      # unmount everything
```

### List mounted images

```bash
mountir list [-v] [--json]
```

### Clean up orphaned mounts

```bash
sudo mountir clean                    # release & remove everything under /mnt/mountir
sudo mountir clean --mount-base DIR   # clean a custom base
```

Unmounts anything still mounted under the base (deepest-first, with a lazy
fallback), detaches the backing loop devices, removes the leftover directories,
and prunes stale state entries. It refuses to run against system paths like `/`
or `/mnt` unless you pass `--force`.

### Check / install dependencies

```bash
mountir check            # report tool availability
sudo mountir setup       # install all dependencies (Python + system tools)
```

---

## Example

```bash
# Mount an EnCase Ex01 image for case IR-2026-001
sudo mountir mount /evidence/laptop.Ex01 --case-id IR-2026-001 -v

# See what is mounted
mountir list

# Tear it down when finished
sudo mountir unmount IR-2026-001_laptop_a1b2c3
```

### Mount layout

Each mount is created under `--mount-base` in a self-describing tree:

```
/mnt/mountir/<mount-id>/
├── container/                 # FUSE/raw container (e.g. ewf1)
└── partitions/
    ├── p1_ntfs_Windows/       # partition 1, NTFS, label "Windows"
    └── p2_ext4_root/          # partition 2, ext4, label "root"
```

---

## JSON orchestration

`mount --json-input` accepts a request document (file or stdin) so MountIR can be
driven by upstream tools such as Whirlpool:

```json
{
  "image_path": "/evidence/disk.E01",
  "case_id": "IR-2026-001",
  "mount_base": "/mnt/case001",
  "mount_options": { "no_partitions": false },
  "maelstrom_callback": {
    "enabled": true,
    "profiles": ["eventlogs", "registry"],
    "output": "/evidence/collected"
  }
}
```

`mount --json` and `list --json` emit structured results on stdout (human-
readable status always goes to stderr, keeping stdout clean for pipelines).

---

## State & logs

| Artifact | Location (preferred → fallback) |
| --- | --- |
| Mount state | `/var/lib/mountir/mountir_state.json` → project dir |
| Bootstrap marker | `/var/lib/mountir/.bootstrapped` → project dir |
| Logs | `../logs/mountir_<timestamp>.log` → `./logs` → `/tmp` |

`list` cross-checks `/proc/mounts` and flags entries that are no longer mounted
as `[STALE]`; clear them with `unmount --all`.

---

## Troubleshooting & cleanup

### "Failed to FUSE-unmount" / unmount leaves things behind

The most common cause is a **shell or process sitting inside the mount** — you
can't unmount a filesystem while something is using it. If your prompt is inside
`/mnt/mountir/<id>/…`, that's the culprit.

```bash
cd ~                                  # leave the mount FIRST
sudo mountir unmount --all            # now it can release cleanly
```

MountIR now falls back to a **lazy unmount** when a mount is busy, so cleanup
generally succeeds even if something is still attached (you'll see a
`Lazy-unmounted busy …` warning). Always `cd` out anyway — it's the real fix.

### Cleaning up stale mounts under the mount base

The easy way — let MountIR scavenge its own mount base:

```bash
cd ~                                  # don't be inside the mount
sudo mountir clean                    # release & remove everything under /mnt/mountir
mountir list                          # should now be empty
```

`clean` unmounts deepest-first (lazily if busy), detaches backing loop devices,
removes the leftover directories, and prunes stale state. It only touches the
mount base you give it and refuses system paths unless `--force` is passed.

#### Manual cleanup (other tools / paths MountIR doesn't track)

First, **look before you delete:**

```bash
findmnt -R /mnt                       # tree of everything mounted under /mnt
```

> ⚠️ Do **not** touch system mounts such as `/mnt/wsl`, `/mnt/wslg`, or
> `/mnt/c` (WSL/host). Only clean up mount points you created for evidence.

```bash
# Unmount deepest-first (partitions before their container)
sudo umount -R /mnt/<dir> 2>/dev/null || sudo umount -l /mnt/<dir>/container

# Detach any loop devices still pointing at the image
losetup -a                            # find the /dev/loopN for your image
sudo losetup -d /dev/loopN

# Remove empty mount-point dirs (rmdir refuses if still mounted — that's a safety net)
sudo rmdir /mnt/<dir>/partitions/* 2>/dev/null
sudo rmdir /mnt/<dir>/{partitions,container} /mnt/<dir>
```

Use `rmdir` (not `rm -rf`) on mount-point directories: it fails safely if a path
is still mounted, so you can't accidentally delete into a live evidence mount.
Confirm a path is unmounted with `mountpoint -q /mnt/<dir>/container`.

---

## Testing

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

The suite is hermetic (subprocess/`shutil.which` are mocked), so it runs on any
platform without the forensic tools installed. To skip the first-run bootstrap
while developing, set `MOUNTIR_NO_BOOTSTRAP=1`.

---

## Project layout

```
MountIR/
├── mountir.py        # CLI entry point (mount / unmount / list / check / setup)
├── bootstrap.py      # dependency declarations + first-run install
├── detector.py       # format detection (extension + magic)
├── handlers/         # one mount handler per format
├── partition.py      # partition + LVM detection / mounting
├── state.py          # JSON mount-state persistence
├── utils.py          # logging, subprocess, tool checks, NBD/FUSE helpers
├── requirements.txt  # pinned runtime deps
├── requirements-dev.txt
├── .venv/            # project virtualenv (created on first run; git-ignored)
└── tests/            # pytest suite
```

---

## Safety notes

- Every mount uses `ro` plus `noatime,noexec,norecovery`; NTFS/HFS recovery is
  suppressed so the source image is never written to.
- MountIR never writes to the evidence image. Temporary conversions (DMG,
  split-raw, etc.) are written to throwaway `mountir_*` temp directories and
  cleaned up on unmount.
- Always `unmount` (or `unmount --all`) before detaching evidence media.
```
