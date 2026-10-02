#!/usr/bin/env bash
# Say what kind of storage a directory is on.
#
#   tools/storage_class.sh <directory>
#   -> class=<ram|local|network|other> fstype=<..> source=<..> mount=<..> path=<..>
#
# An XMSS member burns its slot durably before signing: one journal write and
# one sync_data per signature. What that costs is a property of the storage
# under the state file, not of the signature scheme: almost nothing on a
# RAM-backed filesystem, a device flush on a local disk, a round trip on network
# storage. A `sign_protocol` figure is therefore only meaningful together with
# this classification, and one taken on RAM does not describe durable signing.
#   ram      tmpfs, ramfs and similar: sync_data returns without any device
#   local    a block-device filesystem on this host (ext4, xfs, btrfs, zfs, ...)
#   network  NFS, SMB/CIFS, Ceph, GlusterFS, 9p, sshfs, ...
#   other    anything else (overlay, FUSE, unknown): reported, not interpreted
set -euo pipefail
export LC_ALL=C

[ "$#" -eq 1 ] || { echo "usage: storage_class.sh <directory>" >&2; exit 2; }
[ -d "$1" ] || { echo "storage_class: not a directory: $1" >&2; exit 2; }
path="$(cd "$1" && pwd -P)"

fstype=""; source=""; mount=""
if command -v findmnt >/dev/null 2>&1; then
  fstype="$(findmnt -no FSTYPE -T "$path" 2>/dev/null | head -1 || true)"
  source="$(findmnt -no SOURCE -T "$path" 2>/dev/null | head -1 || true)"
  mount="$(findmnt -no TARGET -T "$path" 2>/dev/null | head -1 || true)"
fi
if [ -z "$fstype" ]; then
  read -r source fstype mount < <(df -PT "$path" 2>/dev/null | awk 'NR == 2 { print $1, $2, $7 }') || true
fi
[ -n "$fstype" ] || { echo "storage_class: cannot determine the filesystem of $path" >&2; exit 1; }

case "$fstype" in
  tmpfs|ramfs|devtmpfs|hugetlbfs) class=ram ;;
  ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|jfs|reiserfs|bcachefs|ntfs|ntfs3|vfat|exfat|apfs|hfsplus) class=local ;;
  nfs|nfs4|cifs|smb3|smbfs|ceph|glusterfs|9p|lustre|afs|fuse.sshfs|fuse.glusterfs|fuse.ceph) class=network ;;
  *) class=other ;;
esac
printf 'class=%s fstype=%s source=%s mount=%s path=%s\n' \
  "$class" "$fstype" "${source:-unknown}" "${mount:-unknown}" "$path"
