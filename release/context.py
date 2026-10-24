"""Strict frozen-source boundary shared by the local packer and CI builder."""
import hashlib
import json
import pathlib
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(value):
    path = pathlib.PurePosixPath(value)
    return (isinstance(value, str) and value == path.as_posix() and not path.is_absolute()
            and all(part not in ("..", ".git", "private", "output") for part in path.parts)
            and not path.name.startswith(".env") and "\\" not in value)


def extract_verified(archive, destination, descriptor):
    destination = pathlib.Path(destination)
    if destination.exists():
        raise RuntimeError("source_destination_already_exists")
    if digest(pathlib.Path(archive).read_bytes()) != descriptor["archive_sha256"]:
        raise RuntimeError("source_archive_digest_mismatch")
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if len(members) != descriptor["source_file_count"] + 1 or len({m.name for m in members}) != len(members):
            raise RuntimeError("source_inventory_count_mismatch")
        if any(not m.isfile() or not safe_name(m.name) or m.size > 2 * 1024 * 1024 for m in members):
            raise RuntimeError("unsafe_source_archive_entry")
        if sum(m.size for m in members) > 32 * 1024 * 1024:
            raise RuntimeError("source_archive_too_large")
        manifest = stream.extractfile("source-files.json").read()
        if digest(manifest) != descriptor["source_manifest_sha256"]:
            raise RuntimeError("source_manifest_digest_mismatch")
        files = json.loads(manifest)
        if digest(json.dumps(files, sort_keys=True).encode()) != descriptor["source_tree_sha256"]:
            raise RuntimeError("source_tree_identity_mismatch")
        if set(files) != {m.name for m in members} - {"source-files.json"}:
            raise RuntimeError("source_inventory_mismatch")
        contents = {}
        for name, expected in files.items():
            value = stream.extractfile(name).read()
            if digest(value) != expected:
                raise RuntimeError("source_file_digest_mismatch")
            contents[name] = value
    # Validate everything before writing any executable build input.
    destination.mkdir(mode=0o700, parents=True)
    for name, value in contents.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o600)
    return files
