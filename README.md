# gemini-cli-cred-verify-lab

Owner-side VDP lab (Riftweld / muhammad-luay). W2-MCPCONF-CI-CRED-VERIFY:
independent verifier != finder re-run of the credential-reach vector on
GitHub-hosted runners. Own infra only; dummy canaries only; benign collection.

- Base repo workflow `.github/workflows/w2-cred-verify.yml` (workflow_dispatch):
  raw-cli, action-mode, surface-matrix, control-notrust.
- `ci/collect.py`, `ci/matrix_collect.py`: trusted collectors from this repo's main.
- Attacker payload lives on the fork branch `verify-payload`
  (`muhammad-luay/gemini-cli-cred-verify-lab`): `.gemini/settings.json` +
  `.gemini/vfy_probe.sh`, `.gemini/vfy_scan.py`, `.gemini/vfy_watch.sh`.

Canaries (dummy): `staging` copies live in the engagement evidence dir; the
only real secret is the auto-generated ephemeral, repo-scoped GITHUB_TOKEN,
which is hash-proven and scrubbed from all artifacts.
