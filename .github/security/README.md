# Organization repository malware gate

The organization ruleset runs three independent, non-executing checks on pull
requests targeting protected default branches:

1. The shared composite action blocks high-confidence repository and workflow
   behavior, including poisoned configuration entrypoints, shell downloaders,
   fake font payloads, dangerous lifecycle scripts, known campaign indicators,
   and force-push artifacts.
2. ClamAV and pinned YARA-Forge rules scan an inert archive for known malware
   families and suspicious binaries.
3. GuardDog analyzes npm manifests for malicious dependency behavior.

The workflow has read-only GitHub permissions, does not persist checkout
credentials, and does not install dependencies or execute repository code.
External scanner inputs are pinned by commit, digest, or verified checksum.

No malware scanner can prove that a repository is safe. This gate complements
required pull requests, independent review, signed commits, protected branches,
short-lived credentials, and endpoint security.
