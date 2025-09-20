old ftp daemon, diffs are located in `build`

SHERPA:
https://github.com/AIxCyberChallenge/sherpa/tree/main

Example usage:
`python fuzz_unharnessed_repo.py --repo https://github.com/FoVeSx/ftpd.git --ref 8fcd948979f5927ba23f73903cb3203495b5bfa0`

To modify the model used in script:
`CODEX_ANALYSIS_MODEL = os.environ.get("CODEX_ANALYSIS_MODEL", "gpt-5")`

For the o3 run, cost average has been around $1.10. Rate limited due to only 30K TPM

