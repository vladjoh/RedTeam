"""Derive plain-English attack chains from findings (external-focused)."""

from __future__ import annotations

from app.core.models import AssessmentResult, Severity


def build_attack_chains(result: AssessmentResult) -> list[dict]:
    titles = {f.title.lower() for f in result.findings}
    texts = " ".join(f.title + " " + f.description for f in result.findings).lower()
    chains: list[dict] = []

    def has(*needles: str) -> bool:
        return any(n in texts for n in needles)

    if has("dmarc") and has("missing") or has("dmarc record missing"):
        chains.append(
            {
                "name": "Spoofed mail to credential harvest",
                "effort": "Low",
                "blast_radius": "Credential theft, BEC",
                "steps": [
                    "Abuse weak/missing DMARC (and SPF) to spoof trusted senders",
                    "Phish users or push device-code instructions",
                    "Reuse harvested credentials against Entra / legacy protocols",
                ],
            }
        )

    if has("getcredentialtype") or has("user-existence"):
        chains.append(
            {
                "name": "Validated user list → password spray",
                "effort": "Low–medium",
                "blast_radius": "Account takeover of weak accounts",
                "steps": [
                    "Use GetCredentialType / realm discovery to validate identities",
                    "Spray against managed cloud auth or legacy protocols",
                    "Pivot into mail / SharePoint once a weak account falls",
                ],
            }
        )

    if has("federated") or has("adfs"):
        chains.append(
            {
                "name": "Federation / ADFS follow-on",
                "effort": "Medium–high",
                "blast_radius": "Tenant-wide impersonation if IdP is owned",
                "steps": [
                    "Locate AuthURL / ADFS from realm discovery",
                    "Probe federation endpoints and relying-party exposure",
                    "Abuse federation weaknesses toward Golden SAML-style outcomes",
                ],
            }
        )

    if has("device code") or has("oauth phishing"):
        chains.append(
            {
                "name": "Device-code phishing",
                "effort": "Low",
                "blast_radius": "Token theft without password",
                "steps": [
                    "Social-engineer victim into completing device-code login",
                    "Receive OAuth tokens for Graph / mail / files",
                    "Persist via consented app or mailbox rules",
                ],
            }
        )

    if has("sharepoint") and has("host"):
        chains.append(
            {
                "name": "Collaboration surface abuse",
                "effort": "Medium",
                "blast_radius": "Data exposure via sharing links",
                "steps": [
                    "Confirm SharePoint/OneDrive hostname footprint",
                    "Hunt anonymous / guest sharing edges",
                    "Exfiltrate or plant malicious content for internal users",
                ],
            }
        )

    # Always provide at least one narrative for empty/edge cases
    if not chains:
        chains.append(
            {
                "name": "Baseline external reconnaissance",
                "effort": "Low",
                "blast_radius": "Improved targeting for phishing",
                "steps": [
                    "Fingerprint tenant and region from public OIDC metadata",
                    "Classify managed vs federated authentication",
                    "Prioritize phishing and spray against observed services",
                ],
            }
        )

    # Rank by severity presence
    high = sum(1 for f in result.findings if f.severity in {Severity.CRITICAL, Severity.HIGH})
    for c in chains:
        c["signal_strength"] = "High" if high >= 2 else "Moderate"
    return chains[:5]