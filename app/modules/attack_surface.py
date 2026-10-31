"""External attack-surface discovery (no Graph token required)."""

from __future__ import annotations

from urllib.parse import quote

import dns.resolver
import requests

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class AttackSurfaceModule(AssessmentModule):
    category = AssessmentCategory.ATTACK_SURFACE
    supported_profiles = {AttackProfile.EXTERNAL, AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        domain = self.tenant

        # OpenID configuration
        oidc_url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        try:
            r = requests.get(oidc_url, timeout=15)
            if r.ok:
                data = r.json()
                findings.append(
                    self.finding(
                        profile,
                        "Tenant OpenID configuration exposed",
                        Severity.INFO,
                        f"Issuer confirmed: {data.get('issuer')}",
                        evidence={"url": oidc_url, "tenant_region_scope": data.get("tenant_region_scope")},
                        barrier="Public IdP metadata is expected for OIDC.",
                        attack_path="Fingerprint tenant → craft phishing / federation attacks.",
                        remediation="Monitor auth anomalies; review custom domain exposure.",
                    )
                )
            else:
                findings.append(
                    self.finding(
                        profile,
                        "OpenID configuration not reachable for domain",
                        Severity.PASS,
                        f"HTTP {r.status_code} for {oidc_url}",
                        barrier="Unknown or unreachable tenant reduces external fingerprinting.",
                    )
                )
        except requests.RequestException as exc:
            findings.append(
                self.finding(
                    profile,
                    "OpenID probe failed",
                    Severity.INFO,
                    str(exc),
                    evidence={"url": oidc_url},
                )
            )

        # DNS MX / TXT hints
        for record_type in ("MX", "TXT"):
            try:
                answers = dns.resolver.resolve(domain.replace(".onmicrosoft.com", ".com") if False else domain, record_type)
                values = [str(r) for r in answers]
                findings.append(
                    self.finding(
                        profile,
                        f"DNS {record_type} records for tenant domain",
                        Severity.INFO,
                        f"Found {len(values)} {record_type} record(s).",
                        evidence={"records": values[:10]},
                        attack_path="Map mail routing / SPF / verification tokens.",
                    )
                )
            except Exception:  # noqa: BLE001
                # onmicrosoft.com often has limited public DNS; try as-is silently
                pass

        # GetUserRealm-style realm discovery (read-only)
        realm_url = "https://login.microsoftonline.com/getuserrealm.srf"
        try:
            sample = f"probe@{domain}"
            r = requests.get(realm_url, params={"login": sample, "xml": "1"}, timeout=15)
            findings.append(
                self.finding(
                    profile,
                    "User realm discovery endpoint reachable",
                    Severity.MEDIUM if r.ok else Severity.INFO,
                    "GetUserRealm responds for constructed identities; useful for Managed/Federated classification.",
                    evidence={"status": r.status_code, "sample_login": sample, "body_snippet": r.text[:400]},
                    barrier="Smart Lockout and Conditional Access reduce spray effectiveness.",
                    attack_path="Classify auth type → password spray or federation abuse.",
                    remediation="Enable Smart Lockout; prefer phishing-resistant MFA.",
                )
            )
        except requests.RequestException as exc:
            findings.append(
                self.finding(profile, "Realm discovery probe failed", Severity.INFO, str(exc))
            )

        # Federation metadata hint
        try:
            fed = requests.get(
                f"https://login.microsoftonline.com/{quote(domain)}/federationmetadata/2007-06/federationmetadata.xml",
                timeout=15,
            )
            if fed.ok:
                findings.append(
                    self.finding(
                        profile,
                        "WS-Federation metadata available",
                        Severity.INFO,
                        "Federation metadata document is publicly downloadable.",
                        evidence={"bytes": len(fed.content)},
                        barrier="Metadata alone is not credential access.",
                        attack_path="Study claims/endpoints for federation misconfiguration.",
                    )
                )
        except requests.RequestException:
            pass

        if not findings:
            findings = demo_findings(profile, [self.category], self.tenant)
        # Attach raw JSON for debugging without secrets
        for f in findings:
            f.evidence.setdefault("module", "attack_surface")
            f.evidence.setdefault("read_only", True)
        return findings