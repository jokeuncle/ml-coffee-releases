"""Public builder: decrypt one pinned private snapshot, compile, never sign releases."""
import argparse
import base64
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

from context import digest, extract_verified

TARGETS = [("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"),
           ("darwin", "arm64"), ("windows", "amd64"), ("windows", "arm64")]


def descriptor(path):
    value = json.loads(pathlib.Path(path).read_text())
    if value["repository"] != "jokeuncle/ml-coffee-releases" or not re.fullmatch(r"v\d+\.\d+\.\d+", value["version"]):
        raise RuntimeError("invalid_build_identity")
    for key in ["cipher_sha256", "certificate_sha256", "archive_sha256", "source_manifest_sha256", "source_tree_sha256", "skill_checksum"]:
        if not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise RuntimeError("invalid_build_digest")
    if not re.fullmatch(r"[0-9a-f]{40}", value["private_source_base_commit"]) or not re.fullmatch(r"\d+\.\d+\.\d+", value["go_version"]):
        raise RuntimeError("invalid_build_revision_or_toolchain")
    if len(base64.b64decode(value["verification_key_b64"], validate=True)) != 32:
        raise RuntimeError("invalid_verification_key")
    datetime.datetime.fromisoformat(value["build_time"])
    if " " in value["build_time"] or "\n" in value["build_time"]:
        raise RuntimeError("invalid_build_timestamp")
    for key in ["cipher_asset", "certificate_asset"]:
        if pathlib.PurePosixPath(value[key]).name != value[key]:
            raise RuntimeError("invalid_input_asset_name")
    return value


def temp_child(path):
    root = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve()
    path = pathlib.Path(path).resolve()
    if path.parent != root or not path.name.startswith("mlcoffee-") or path.is_symlink():
        raise RuntimeError("owned_runner_temporary_path_required")
    return path


def unpack(value, inputs, source):
    inputs, source = temp_child(inputs), temp_child(source)
    encrypted = inputs / value["cipher_asset"]
    cert = inputs / value["certificate_asset"]
    if digest(encrypted.read_bytes()) != value["cipher_sha256"] or digest(cert.read_bytes()) != value["certificate_sha256"]:
        raise RuntimeError("sealed_input_integrity_failed")
    key = inputs / "ephemeral-key.pem"
    archive = inputs / "private-source.tar.gz"
    secret = os.environ.pop("MLC_BUILD_DECRYPTION_KEY", "")
    if not secret.startswith("-----BEGIN PRIVATE KEY-----") or len(secret) > 8192:
        raise RuntimeError("ephemeral_context_key_missing")
    key.write_text(secret)
    key.chmod(0o600)
    try:
        result = subprocess.run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(encrypted),
                                 "-inkey", str(key), "-recip", str(cert), "-out", str(archive)], capture_output=True)
        if result.returncode:
            raise RuntimeError("context_decryption_failed")
        extract_verified(archive, source, value)
    finally:
        key.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("go-version=" + value["go_version"] + "\n")
    print(json.dumps({"source_verified": True, "source_tree_sha256": value["source_tree_sha256"]}))


def seal_failure(inputs, output, log):
    certs = list(pathlib.Path(inputs).glob("*.crt.pem"))
    if len(certs) != 1:
        raise RuntimeError("private_diagnostic_certificate_missing")
    result = subprocess.run(["openssl", "cms", "-encrypt", "-aes-256-gcm", "-binary", "-outform", "DER",
                             "-in", str(log), "-out", str(output / "build-diagnostic.log.cms"), str(certs[0])], capture_output=True)
    if result.returncode:
        raise RuntimeError("private_diagnostic_encryption_failed")


def build(value, inputs, source, output):
    source, output = temp_child(source), temp_child(output)
    output.mkdir(mode=0o700, exist_ok=False)
    # Recheck after setup-go; no step may alter the private source unnoticed.
    import hashlib
    files = {str(p.relative_to(source)): digest(p.read_bytes()) for p in source.rglob("*") if p.is_file()}
    if hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest() != value["source_tree_sha256"]:
        raise RuntimeError("source_changed_before_compilation")
    flags = " ".join(["-s -w", "-X github.com/jokeuncle/ml-coffee/internal/api.DefaultEndpoint=https://getmlcoffee.com",
                      "-X github.com/jokeuncle/ml-coffee/internal/buildinfo.Version=" + value["version"],
                      "-X github.com/jokeuncle/ml-coffee/internal/buildinfo.CompatibilityID=mlc-cli-skill-v2",
                      "-X github.com/jokeuncle/ml-coffee/internal/buildinfo.GitCommit=" + value["private_source_base_commit"] + "+tree." + value["source_tree_sha256"][:16],
                      "-X github.com/jokeuncle/ml-coffee/internal/buildinfo.BuildTime=" + value["build_time"],
                      "-X github.com/jokeuncle/ml-coffee/cmd/agent.UpdatePublicKeyBase64=" + value["verification_key_b64"]])
    log = pathlib.Path(os.environ["RUNNER_TEMP"]) / "mlcoffee-private-build.log"
    names = []
    try:
        with log.open("wb") as stream:
            for system, arch in TARGETS:
                name = "mlc-" + system + "-" + arch + (".exe" if system == "windows" else "")
                env = dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=arch, GOTOOLCHAIN="local")
                result = subprocess.run(["go", "build", "-trimpath", "-mod=readonly", "-ldflags", flags, "-o", str(output / name), "."],
                                        cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise RuntimeError("compile_failed")
                names.append(name)
        config = pathlib.Path(os.environ["RUNNER_TEMP"]) / "mlcoffee-empty-config.yaml"
        config.write_text("{}\n")
        result = subprocess.run([str(output / "mlc-linux-amd64"), "--config", str(config), "agent", "release-info"], capture_output=True)
        info = json.loads(result.stdout)
        if result.returncode or info != {"version": value["version"], "compatibility_id": "mlc-cli-skill-v2", "skill_checksum": value["skill_checksum"]}:
            raise RuntimeError("compiled_release_identity_mismatch")
        (output / "checksums-binaries.txt").write_text("".join(digest((output / name).read_bytes()) + "  " + name + "\n" for name in sorted(names)))
        (output / "build-input.json").write_text(json.dumps(value, indent=2) + "\n")
        (output / "release-info.json").write_text(json.dumps(info, indent=2) + "\n")
        print(json.dumps({"compiled_platforms": len(names), "source_verified": True, "signing_key_loaded": False}))
    except Exception:
        if log.exists():
            seal_failure(inputs, output, log)
        raise RuntimeError("build_failed_see_encrypted_diagnostic") from None
    finally:
        log.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["unpack", "build", "cleanup"])
    parser.add_argument("descriptor")
    parser.add_argument("inputs")
    parser.add_argument("source")
    parser.add_argument("output", nargs="?")
    args = parser.parse_args()
    if args.mode == "cleanup":
        for path in [args.inputs, args.source]:
            owned = temp_child(path)
            if owned.exists():
                shutil.rmtree(owned)
        (pathlib.Path(os.environ["RUNNER_TEMP"]) / "mlcoffee-private-build.log").unlink(missing_ok=True)
    else:
        value = descriptor(args.descriptor)
        if args.mode == "unpack":
            unpack(value, args.inputs, args.source)
        else:
            build(value, args.inputs, args.source, args.output)


if __name__ == "__main__":
    main()
