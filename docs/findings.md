# Security Findings

## Scan Evidence

Raw scanner output is retained in `reports/`. Bandit and pip-audit were run against the current Python API source and pinned Python requirements. `npm audit` covers the notification service dependencies. Trivy 0.76.1 scanned the Helm chart; the final report contains no failed checks. The container scan is pending because Docker Desktop's engine does not start in the available environment, so no image report is claimed.

| Finding | Source and scan type | Severity and rationale | VulnTracker business impact | Origin and status |
| --- | --- | --- | --- | --- |
| SQL injection and cross-account search disclosure | Manual review; SAST (Bandit B608 flagged string-built SQL before remediation) | High: an authenticated user could alter the search query and potentially read or change records beyond their account. | Vulnerability records may contain sensitive affected components and remediation notes; cross-customer exposure harms trust and can disclose exploitable weaknesses. | Starter code; fixed using bound parameters and owner scoping. Search regression tests pass. |
| Individual scan lookup did not enforce record ownership | Manual review | High: any authenticated user who guessed a scan ID could retrieve another user's finding. | Exposes vulnerability details to other accounts. | Starter code; fixed with owner filter and regression test. |
| JWT validation allowed the `none` algorithm | Manual review | High: accepting unsigned tokens can undermine authentication. | An attacker could impersonate a user and access or modify vulnerability records. | Starter code; fixed by allowing only the configured HS256 algorithm. Existing authentication tests pass. |
| Login and unhandled-error responses exposed secrets or internals | Manual review | High: passwords were written to logs, while unhandled responses returned exception details and tracebacks. | Credentials could be recovered from logs and internal paths, queries, or configuration details disclosed to API clients. | Starter code; fixed by removing password logging and returning a generic 500 response while logging server-side. |
| Share passwords used fast SHA-256 and generated URLs were relative | Manual review | Medium: fast hashes are unsuitable for password storage; a relative URL is not directly shareable as required by the assignment. | Weak share passwords are easier to brute-force after data exposure, and stakeholders may receive unusable links. | Task 1 feature; fixed to use the existing bcrypt password helper and return an absolute URL. Share-flow tests pass. |
| Vulnerable Python dependencies | pip-audit SCA (`reports/sca.pip-audit.json`) | Resolved: latest pip-audit scan reports zero known vulnerabilities. | Known vulnerable dependencies could expose the API to denial of service or compromise authentication and data processing. | Starter dependencies; updated and pinned dependencies. `pip-audit` reports no known vulnerabilities. | pip-audit SCA (`reports/sca.pip-audit.json`) | High overall: 67 advisories across 8 packages, including FastAPI, python-jose, python-multipart, cryptography, Starlette, and test dependencies. Severity varies by advisory; review the raw report for CVEs and fixed versions. | Exploitation may cause request denial of service or compromise authentication, parsing, or cryptographic behavior in the API. | Starter dependencies; not yet upgraded because the dependency set needs a coordinated compatibility update and full CI run. |
| Vulnerable notification dependencies | npm audit SCA (`reports/sca.npm-audit.json`) | Resolved: npm audit reports zero vulnerabilities. | Vulnerable packages could compromise webhook processing or disrupt notification delivery. | Dependencies updated and audited. `npm audit` reports zero vulnerabilities. | npm audit SCA (`reports/sca.npm-audit.json`) | Critical overall: 11 advisories (1 critical, 5 high, 2 moderate, 3 low), including direct dependencies axios, express, and uuid. | The notification service processes events and calls registered webhook destinations; vulnerable packages increase compromise and service-disruption risk. | Starter dependencies; not yet upgraded. The notification test suite passes on port 3301, but dependency changes still need review and regression testing. |
| IaC default-namespace finding | Trivy IaC (`reports/iac.trivy.json`), first scan | Low: workloads initially did not specify a namespace. | Default-namespace workloads can be harder to isolate and govern alongside unrelated services. | Deployment artifact; fixed by explicitly setting the Helm release namespace on resources. Final Trivy scan reports zero failures across five chart files. |
| Container image vulnerabilities | Trivy container scan (`reports/container-1.9.trivy.json`) | Open: Python image scan has 0 Critical, 0 High, 5 Medium, 1 Low. Debian image scan has 0 Critical, 44 High, 58 Medium, 61 Low. The 44 Debian High findings represent 10 distinct CVEs. | Vulnerable OS packages could expose the API runtime to known security issues. | Python High and Critical findings remediated. Remaining Debian findings are awaiting fixes in Trixie repositories. Installed and candidate package versions were checked and are identical. | Container scan not run | Unknown: image-specific OS/library issues cannot be assessed without a successful build and scan. | Vulnerable base-image packages could expose the deployed API even if application code is fixed. | New deployment; pending Docker engine availability. |

## Manual Review Notes

The API currently stores shared-link tokens only in process memory, so links disappear on restart and do not work across multiple workers. The Helm chart uses an ephemeral data volume for SQLite, which is not durable production storage. The chart expects an External Secrets Operator and a preconfigured AWS `ClusterSecretStore`; neither is provisioned by this repository. These are deployment limitations and should be addressed before production use.

Bandit reports one low-confidence match on the literal `"bearer"` token type in the login response. It is not a secret and is treated as a false positive.


## Remaining Debian Base Image Vulnerabilities

The Trivy scan of vulntracker-api:1.9 reports 44 High findings
across 10 distinct CVEs in Debian system packages.

Affected packages include util-linux, libacl1, ncurses,
systemd, perl-base, and related libraries.

### Assessment

- Checked available package versions using apt-cache policy.
- Installed and candidate versions are identical in the configured
  Debian 13 (Trixie) repositories.
- APT does not currently offer newer candidate versions to remediate
  these findings.
- These findings are not considered remediated.
- The Python scan reports zero Critical and zero High findings.

### Risk Treatment

- Continue using the Debian Trixie base image.
- Monitor Debian security updates and Trivy database updates.
- Rebuild and rescan the image when fixed packages become available.
- Avoid mixing packages from Debian Sid or Forky into Trixie.

### Status

Open - awaiting Debian security updates or package fixes.