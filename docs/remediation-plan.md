# Remediation Plan

## Completed

| Finding | Change | Verification |
| --- | --- | --- |
| SQL injection in scan search and cross-account search results | Replaced interpolated SQL with SQLAlchemy bound parameters and added an owner filter. | Python test confirms a user's search results exclude another user's records; full API suite passes. |
| Cross-account scan access | Added an owner filter to `GET /scans/{scan_id}` and retained owner checks when creating shares. | Regression test expects 404 when another account reads or shares a scan. |
| JWT algorithm confusion | Removed `none` from the JWT decoder's allowed algorithms. | Existing login-protected API tests pass. |
| Credential and traceback disclosure | Removed password values from login logs and made unhandled API errors return a generic message. | API suite passes; manually inspected response/logging code. |
| Share link password storage and URL requirements | Share passwords now use the bcrypt password helper; links use the incoming request host to construct an absolute URL. | Tests cover protected and unprotected retrieval, wrong/missing password, and absolute URL format. |
| Helm namespace finding | Added `.Release.Namespace` to chart resources flagged by Trivy. | Final `reports/iac.trivy.json` has zero failures across five Helm files. |

## Deferred Findings and Residual Risk

| Finding | Residual risk | Effort to remediate | Compensating controls |
| --- | --- | --- | --- |
| Remaining Debian OS package vulnerabilities | 44 High, 58 Medium, and 61 Low findings remain in the Debian base image, representing 10 distinct CVEs among the High findings. | Await Debian Trixie package fixes. Rebuild and rescan when updated packages become available. | Monitor Debian Security Tracker and Trivy updates. Continue using the supported Trixie repositories. Do not mix Debian Sid or Forky packages into the image. | Known vulnerabilities remain in the pinned FastAPI, python-jose, python-multipart, cryptography, Starlette, and test dependency graph. Affected paths vary by advisory; treat this as high priority until reviewed and upgraded. | Upgrade direct pins to supported patched versions, resolve transitive dependencies, run `pip-audit` again, and run API tests plus CI on the required Python version. | Limit network exposure, keep the service behind authenticated ingress, and monitor vendor advisories. These do not replace upgrading. |
 | The notification service's pinned axios, express, uuid, and transitive packages include known advisories. | Upgrade direct and transitive packages to compatible fixed releases, run `npm audit`, and execute the Node test suite. | Restrict service network access and avoid exposing its management endpoints publicly. The current service has limited controls, so this is not sufficient for production. |
 | The image may contain vulnerable OS or Python packages; the required image-level review is absent. | Start Docker Desktop successfully, build the root Dockerfile, run Trivy against the built image, save JSON to `reports/container.trivy.json`, triage findings, and rebuild after fixes. | Use the pinned slim base image, non-root user, read-only runtime filesystem in Helm, dropped Linux capabilities, and health check. These reduce exposure but do not identify image CVEs. |
| Shared links stored in process memory | Tokens are lost on restart and are not shared across replicas. | Persist token hashes, scan/owner IDs, expiry, and password hashes in a database table; add revocation and cleanup behavior. | Keep one API process and treat links as temporary prototype functionality. Do not rely on this for production stakeholder sharing. |
| SQLite in an ephemeral Helm volume | Data is lost when the pod is replaced and does not support safe multi-replica operation. | Migrate to a managed database with backups, encryption, access controls, and a durable connection secret from the secret manager. | Run a single replica and back up data outside the pod for any non-disposable use. |
| External Secrets infrastructure is a prerequisite | The chart will not provide `SECRET_KEY` until an External Secrets Operator and AWS `ClusterSecretStore` are installed and configured. | Provision the operator, least-privilege AWS IAM identity, secret path, and cluster store through reviewed infrastructure code. | Do not deploy until the external secret is synchronized; Kubernetes `secretKeyRef` requires the generated Secret. |

## Environment Limitations

Docker Desktop became available and the production container image was successfully built and scanned using Trivy 1.9.

The final container test confirmed that the application starts successfully, passes its Docker health check, and returns a successful response from the `/health` endpoint.

Python and Node.js dependency scans completed successfully with zero known vulnerabilities reported by pip-audit and npm audit.

The remaining Debian OS vulnerabilities are documented as residual risks because the configured Debian Trixie repositories do not currently offer newer candidate package versions. These findings remain open pending upstream fixes.

| Python dependency vulnerabilities | Updated and pinned dependencies; removed pip, setuptools, and wheel from the production virtual environment. | `pip-audit` reports zero known vulnerabilities. Trivy 1.9 reports zero Critical and High Python findings. |
| Node.js dependency vulnerabilities | Updated vulnerable notification service dependencies. | `npm audit` reports zero vulnerabilities; Node test suite passes. |
| Container image vulnerabilities | Implemented a multi-stage Docker build, removed unnecessary build tools from the runtime image, upgraded available OS packages, and removed vulnerable system setuptools. | Trivy 1.9 reports zero Critical and High Python findings. Container starts successfully, passes its health check, and `/health` returns status OK. |