# Security Policy

## Supported versions

GuardGate is a portfolio project. Only the latest commit on `main` receives fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.
Use GitHub's private reporting instead: **Security → Advisories → Report a vulnerability** on this repository.

Include the affected component (auth-service, gateway, demo-service, CI pipeline), steps to reproduce,
and the impact you expect. You will get an acknowledgement within 7 days.

## What is in scope

- Authentication and authorization bypass, token forgery or replay, rate-limit bypass
- Information leakage in error responses or logs
- Container or CI/CD pipeline weaknesses (e.g. a scan that can pass without scanning)

## Known, accepted risks

Time-boxed risk acceptances are listed with their justification and expiry date in
[`.trivyignore.yaml`](.trivyignore.yaml). A CI guard (`scripts/check-risk-acceptance.sh`) fails the build
if the code starts using a feature that an accepted CVE depends on.

## Verifying release artifacts

Container images on GHCR are signed with Sigstore cosign (keyless) and carry a CycloneDX SBOM attestation.
See the "CI/CD DevSecOps" section of the README for the `cosign verify` command.
