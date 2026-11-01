"""Attack chains + likelihood briefing for external scans."""

from __future__ import annotations

from app.core.models import AssessmentResult, Likelihood, Severity


def build_attack_chains(result: AssessmentResult) -> list[dict]:
    texts = " ".join(f.title + " " + f.description for f in result.findings).lower()
    chains: list[dict] = []

    def has(*needles: str) -> bool:
        return any(n in texts for n in needles)

    if has("dmarc missing") or (has("dmarc") and has("missing")):
        chains.append(
            {
                "name": "Spoofed mail → credential / BEC",
                "likelihood": "Most likely",
                "effort": "Low",
                "blast_radius": "Credential theft, invoice fraud",
                "why": "Missing/weak DMARC lets attackers send mail that looks like it comes from you.",
                "steps": [
                    "Spoof trusted sender addresses",
                    "Phish credentials or device-code approvals",
                    "Cash out via mailbox or finance fraud",
                ],
            }
        )

    if has("getcredentialtype"):
        chains.append(
            {
                "name": "User validation → password spray",
                "likelihood": "Most likely",
                "effort": "Low–medium",
                "blast_radius": "Account takeover of weak accounts",
                "why": "GetCredentialType lets attackers confirm which emails exist before spraying.",
                "steps": [
                    "Validate users via GetCredentialType",
                    "Spray against managed auth or legacy protocols",
                    "Access mail / SharePoint as the user",
                ],
            }
        )

    if has("device code"):
        chains.append(
            {
                "name": "Device-code phishing",
                "likelihood": "Most likely",
                "effort": "Low",
                "blast_radius": "Token theft without guessing passwords",
                "why": "Victims complete a real Microsoft login for the attacker.",
                "steps": [
                    "Send convincing device-code instructions",
                    "Capture OAuth tokens",
                    "Read mail/files or plant persistence",
                ],
            }
        )

    if has("ropc") or has("basic authentication") or has("ews advertises basic"):
        chains.append(
            {
                "name": "Legacy / ROPC MFA bypass class",
                "likelihood": "Most likely",
                "effort": "Medium",
                "blast_radius": "Auth without interactive MFA",
                "why": "Legacy and ROPC-style flows historically skip interactive MFA prompts.",
                "steps": [
                    "Identify allowed legacy/ROPC surfaces",
                    "Authenticate with password only",
                    "Pull tokens or mailbox data",
                ],
            }
        )

    if has("federated") or has("adfs"):
        chains.append(
            {
                "name": "Federation / ADFS follow-on",
                "likelihood": "Possible",
                "effort": "Medium–high",
                "blast_radius": "Tenant-wide if IdP is owned",
                "why": "Federated tenants expose on-prem IdP surfaces attackers prefer for Golden SAML-style outcomes.",
                "steps": [
                    "Hit AuthURL / MEX / IdP-initiated pages",
                    "Map relying parties",
                    "Abuse weak federation configuration",
                ],
            }
        )

    if has("dangling cname") or has("takeover"):
        chains.append(
            {
                "name": "Azure subdomain takeover",
                "likelihood": "Possible",
                "effort": "Low–medium",
                "blast_radius": "Trusted-host phishing / content control",
                "why": "Dangling Microsoft-platform CNAMEs can be claimed by an attacker.",
                "steps": [
                    "Find dangling CNAME to Azure service",
                    "Claim the resource name",
                    "Host phishing on a trusted hostname",
                ],
            }
        )

    if has("odata") and has("anonymously"):
        chains.append(
            {
                "name": "Anonymous Power Pages data leak",
                "likelihood": "Most likely",
                "effort": "Low",
                "blast_radius": "Business data exposure",
                "why": "Anonymous OData 200 means direct data access without login.",
                "steps": [
                    "Query exposed OData entities",
                    "Extract contacts/accounts",
                    "Use data for fraud or further phish",
                ],
            }
        )

    if not chains:
        chains.append(
            {
                "name": "Baseline external recon → phishing",
                "likelihood": "Possible",
                "effort": "Low",
                "blast_radius": "Improved targeting",
                "why": "Even without misconfigurations, public fingerprinting improves attacker lures.",
                "steps": [
                    "Fingerprint tenant and services",
                    "Craft tenant-specific phishing",
                    "Aim for device-code or consent abuse",
                ],
            }
        )

    # Sort: Most likely first
    order = {"Most likely": 0, "Possible": 1, "Less likely": 2}
    chains.sort(key=lambda c: order.get(c.get("likelihood", "Possible"), 9))
    return chains[:6]


def build_likelihood_briefing(result: AssessmentResult) -> dict:
    """Clear High/Medium/Low + most/less likely messaging for the UI."""
    hml = result.high_medium_low_counts()
    most = [f for f in result.findings if f.likelihood == Likelihood.MOST_LIKELY and f.severity in {Severity.HIGH, Severity.MEDIUM}]
    possible = [f for f in result.findings if f.likelihood == Likelihood.POSSIBLE and f.severity != Severity.INFO]
    less = [f for f in result.findings if f.likelihood == Likelihood.LESS_LIKELY]

    def pack(items: list, limit: int = 5) -> list[dict]:
        return [
            {
                "title": f.title,
                "severity": f.severity.value,
                "why": f.why or f.description,
                "attack_path": f.attack_path,
                "remediation": f.remediation,
            }
            for f in sorted(items, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.severity.value, 9))[:limit]
        ]

    top_chain = (result.metadata.get("attack_chains") or build_attack_chains(result) or [{}])[0]
    return {
        "counts": hml,
        "headline": (
            f"{hml['high']} High · {hml['medium']} Medium · {hml['low']} Low findings on {result.tenant_domain}."
        ),
        "most_likely_bypass": {
            "summary": top_chain.get("name", "Review High findings first"),
            "why": top_chain.get("why", ""),
            "steps": top_chain.get("steps", []),
            "items": pack(most),
        },
        "possible": {"items": pack(possible)},
        "less_likely": {
            "summary": "Informational or well-mitigated signals — still verify, but deprioritize.",
            "items": pack(less, 4),
        },
    }