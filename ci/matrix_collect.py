#!/usr/bin/env python3
"""W2-MCPCONF-CI-CRED-VERIFY — surface-matrix collector (base repo main).

Compares the spawned MCP/hook child self-environments across three raw-CLI
invocations that differ only in the SURFACE variable (GITHUB_SHA removed):

  case A: SURFACE unset   -> is the code's strict branch reachable at all?
  case B: SURFACE=Github  -> exact literal the bundle checks
  case C: SURFACE=GitHub  -> exact literal the official action sets

Expected (from byte-level bundle read): the benign marker VFY_SURF_MARK is
present in the sanitized child env for non-strict cases and absent for strict.
"""
import json
import os
import sys

EVID = os.path.join(os.getcwd(), "evidence")
CASES = ("A", "B", "C")


def main():
    report = {"job": "surface-matrix"}
    for case in CASES:
        src = f"/tmp/vfy/matrix-{case}"
        entry = {"files": [], "selfenv_mcp": None, "selfenv_hook": None}
        if os.path.isdir(src):
            entry["files"] = sorted(os.listdir(src))
            for name in ("selfenv-mcp.txt", "selfenv-hook.txt"):
                p = os.path.join(src, name)
                if os.path.isfile(p):
                    entry[name.split(".")[0].replace("selfenv-", "")] = open(p).read()
        mcp = entry.get("mcp") or ""
        hook = entry.get("hook") or ""
        entry["spawn_marker"] = os.path.isfile(os.path.join(src, "spawn-markers.txt"))
        entry["vfy_surf_mark_in_mcp"] = "VFY_SURF_MARK=" in mcp
        entry["vfy_surf_mark_in_hook"] = "VFY_SURF_MARK=" in hook
        entry["gemini_api_key_in_mcp"] = "GEMINI_API_KEY=" in mcp
        entry["github_sha_in_mcp"] = "GITHUB_SHA=" in mcp
        report[f"case_{case}"] = entry

    os.makedirs(EVID, exist_ok=True)
    for case in CASES:
        src = f"/tmp/vfy/matrix-{case}"
        if os.path.isdir(src):
            dst = os.path.join(EVID, f"matrix-{case}")
            os.makedirs(dst, exist_ok=True)
            for name in os.listdir(src):
                p = os.path.join(src, name)
                if os.path.isfile(p):
                    with open(p, "rb") as fh:
                        data = fh.read()
                    with open(os.path.join(dst, name), "wb") as fh:
                        fh.write(data)
    if os.path.isfile("/tmp/vfy/raw/provenance.txt"):
        os.makedirs(os.path.join(EVID, "raw"), exist_ok=True)
        with open("/tmp/vfy/raw/provenance.txt", "rb") as fh:
            data = fh.read()
        with open(os.path.join(EVID, "raw", "provenance.txt"), "wb") as fh:
            fh.write(data)

    verdicts = {}
    for case in CASES:
        e = report[f"case_{case}"]
        if not e["spawn_marker"]:
            verdicts[case] = "NO-SPAWN"
        elif case == "B":
            verdicts[case] = "STRICT" if not e["vfy_surf_mark_in_mcp"] else "NON-STRICT"
        else:
            verdicts[case] = "NON-STRICT" if e["vfy_surf_mark_in_mcp"] else "STRICT"
    report["verdicts"] = verdicts
    report["case_mismatch_note"] = (
        "case C uses the exact literal the official action sets; if C == A (NON-STRICT) "
        "then SURFACE='GitHub' does not trigger the strict branch"
    )

    with open(os.path.join(EVID, "matrix-report.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    with open(os.path.join(EVID, "matrix-report.txt"), "w") as fh:
        for case in CASES:
            e = report[f"case_{case}"]
            fh.write(
                f"case_{case}: spawn={e['spawn_marker']} "
                f"mark_in_mcp={e['vfy_surf_mark_in_mcp']} "
                f"mark_in_hook={e['vfy_surf_mark_in_hook']} "
                f"gemini_key_in_mcp={e['gemini_api_key_in_mcp']} "
                f"verdict={verdicts[case]}\n"
            )
    print(open(os.path.join(EVID, "matrix-report.txt")).read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
