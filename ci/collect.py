#!/usr/bin/env python3
"""W2-MCPCONF-CI-CRED-VERIFY — trusted evidence collector (base repo main).

Runs after the untrusted payload has executed on the runner. Reads /tmp/vfy/raw,
derives the sha256-equality measurements, writes evidence/ (report + raw copies),
and scrubs the real ephemeral GITHUB_TOKEN from all artifact bytes.

Benign lab: dummy canaries only; the only real secret is the auto-generated,
repo-scoped, job-lifetime GITHUB_TOKEN, which is hashed then scrubbed.
"""
import hashlib
import json
import os
import shutil
import sys

RAW = "/tmp/vfy/raw"
EVID = os.path.join(os.getcwd(), "evidence")


def sha256_text(s):
    return hashlib.sha256(s.encode()).hexdigest()


def read_raw():
    files = {}
    if os.path.isdir(RAW):
        for root, _dirs, names in os.walk(RAW):
            for name in names:
                p = os.path.join(root, name)
                try:
                    with open(p, "rb") as fh:
                        files[os.path.relpath(p, RAW)] = fh.read()
                except OSError:
                    pass
    return files


def first_value(files, needle):
    """First `needle=<value>` occurrence: returns (relpath, value, marker)."""
    for rel in sorted(files):
        data = files[rel]
        i = data.find(needle)
        if i >= 0:
            j = data.find(b"\n", i)
            seg = data[i:j if j >= 0 else len(data)]
            parts = seg.split(b"=", 1)
            marker = needle.decode(errors="replace").rstrip("=")
            if len(parts) == 2:
                return rel, parts[1].rstrip(b"\r"), marker
    return None, None, None


def first_occurrence(files, needle):
    """First raw occurrence of `needle` (a value): returns (relpath, value)."""
    for rel in sorted(files):
        data = files[rel]
        i = data.find(needle)
        if i >= 0:
            j = data.find(b"\n", i)
            seg = data[i:j if j >= 0 else len(data)]
            return rel, seg.rstrip(b"\r")
    return None, None


def occurrences(files, needle):
    return {rel: data.count(needle) for rel, data in files.items() if needle in data}


def main():
    mode = os.environ.get("VFY_MODE", "?")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    job_canary = os.environ.get("VFY_JOB_SECRET", "")
    files = read_raw()
    report = {"mode": mode}

    markers = files.get("spawn-markers.txt", b"").decode(errors="replace").splitlines()
    report["spawn_markers"] = [m for m in markers if m.strip()]
    report["spawn_count"] = len(report["spawn_markers"])

    leaks = []
    for rel, data in files.items():
        if rel.startswith("selfenv-"):
            for probe in (
                b"GEMINI_API_KEY=",
                b"VFY_JOB_SECRET=",
                b"GITHUB_TOKEN=",
                b"VFY_LATE_STEP=",
                b"VFY_LATE_ENV=",
            ):
                if probe in data:
                    leaks.append(f"{rel}:{probe.decode()}")
    report["selfenv_secret_leaks"] = leaks
    report["selfenv_clean"] = "YES" if not leaks else "NO"

    if github_token:
        report["github_token_env_sha256"] = sha256_text(github_token)
        hits = occurrences(files, github_token.encode())
        report["github_token_occurrences"] = sum(hits.values())
        report["github_token_capture_files"] = len(hits)
        report["github_token_capture_file_list"] = sorted(hits)[:5]
        rel, val = first_occurrence(files, github_token.encode())
        if rel:
            report["github_token_capture_file"] = rel
            report["github_token_captured_sha256"] = sha256_text(val.decode())
            report["github_token_hash_match"] = (
                "YES" if sha256_text(val.decode()) == sha256_text(github_token) else "NO"
            )
        else:
            report["github_token_hash_match"] = "NO-CAPTURE"
    else:
        report["github_token_hash_match"] = "NO-ENV-TOKEN"

    if job_canary:
        report["vfy_job_env_sha256"] = sha256_text(job_canary)
        hits = occurrences(files, job_canary.encode())
        report["vfy_job_capture_files"] = len(hits)
        report["vfy_job_value_hits"] = sum(hits.values())
        report["vfy_job_capture_file_list"] = sorted(hits)[:5]
        rel, val = first_occurrence(files, job_canary.encode())
        if rel:
            report["vfy_job_captured_sha256"] = sha256_text(val.decode())
            report["vfy_job_hash_match"] = (
                "YES" if sha256_text(val.decode()) == sha256_text(job_canary) else "NO"
            )
            report["vfy_job_capture_file"] = rel
        else:
            report["vfy_job_hash_match"] = "NO-CAPTURE"
    else:
        report["vfy_job_hash_match"] = "NO-ENV-CANARY"

    expected = ""
    lp = os.path.join(RAW, "late-expected.sha")
    if os.path.isfile(lp):
        with open(lp) as fh:
            expected = fh.read().strip()
    report["late_expected_sha256"] = expected

    for label, needle in (("proc_environ", b"VFY_LATE_STEP="), ("filecmd", b"VFY_LATE_ENV=")):
        rel, val, marker = first_value(files, needle)
        if val is not None:
            got = sha256_text(val.decode())
            report[f"late_{label}_channel_file"] = rel
            report[f"late_{label}_captured_sha256"] = got
            report[f"late_{label}_hash_match"] = (
                "YES" if expected and got == expected else "NO"
            )
        else:
            report[f"late_{label}_hash_match"] = "NO-CAPTURE"
    report["watch_exit_log"] = "YES" if "watch/exit.log" in files else "NO"
    for k in sorted(files):
        if k.startswith("watch/"):
            report.setdefault("watch_files", []).append(k)

    os.makedirs(EVID, exist_ok=True)
    if os.path.isdir(RAW):
        shutil.copytree(RAW, os.path.join(EVID, "raw"), dirs_exist_ok=True)
    if os.path.isfile("/tmp/vfy/gemini.log"):
        shutil.copyfile("/tmp/vfy/gemini.log", os.path.join(EVID, "gemini.log"))

    with open(os.path.join(EVID, "capture-report.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    with open(os.path.join(EVID, "capture-report.txt"), "w") as fh:
        for key in sorted(report):
            fh.write(f"{key}={report[key]}\n")

    token_bytes = github_token.encode()
    if token_bytes:
        for root, _dirs, names in os.walk(EVID):
            for name in names:
                p = os.path.join(root, name)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                if token_bytes in data:
                    with open(p, "wb") as fh:
                        fh.write(data.replace(token_bytes, b"REDACTED_GITHUB_TOKEN"))

    for key in sorted(report):
        print(f"{key}={report[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
