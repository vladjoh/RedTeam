"""External Entra / M365 reconnaissance (unauthenticated, read-only).

Own product surface inspired by the problem space of tools like EntraScout:
tenant fingerprint, federation, mail DNS, M365 service hints, and auth
enumeration risk — without copying their code or phase catalog.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests

from app.core.models import AssessmentCategory, AttackProfile, Finding, Severity
from app.modules.base import AssessmentModule

USER_AGENT = "M365RedTeam/0.2 (+authorized-assessment; read-only)"


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    return s


def _dns_texts(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(r).strip('"') for r in answers]
    except Exception:  # noqa: BLE001
        return []


class ExternalEntraModule(AssessmentModule):
    """Primary external attacker module — live public probes."""

    category = AssessmentCategory.ATTACK_SURFACE
    supported_profiles = {AttackProfile.EXTERNAL, AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list[Finding]:
        # External public probes always run live; demo_mode only gates Graph modules.
        domain = self.tenant.strip()
        http = _session()
        findings: list[Finding] = []
        fingerprint: dict[str, Any] = {"input_domain": domain}

        findings.extend(self._tenant_openid(http, domain, profile, fingerprint))
        findings.extend(self._openid_guid_hint(http, domain, profile, fingerprint))
        findings.extend(self._user_realm(http, domain, profile, fingerprint))
        findings.extend(self._credential_type_risk(http, domain, profile, fingerprint))
        findings.extend(self._federation_metadata(http, domain, profile))
        findings.extend(self._login_branding(http, domain, profile))
        findings.extend(self._dns_mail_posture(domain, profile, fingerprint))
        findings.extend(self._autodiscover(http, domain, profile))
        findings.extend(self._sharepoint_onedrive(http, domain, profile, fingerprint))
        findings.extend(self._device_code_surface(profile))
        findings.extend(self._b2c_external_id_hints(http, domain, profile))

        # Attach fingerprint roll-up as informational finding
        findings.insert(
            0,
            self.finding(
                profile,
                "External Entra footprint summary",
                Severity.INFO,
                self._summary_text(fingerprint),
                evidence={"fingerprint": fingerprint, "module": "external_entra"},
                barrier="Public Microsoft endpoints intentionally expose tenant discovery metadata.",
                attack_path="Fingerprint → classify federation → enumerate users/services → choose initial access.",
                remediation="Assume attackers can gather the same public signals; prioritize Smart Lockout, phishing-resistant MFA, and mail auth (SPF/DKIM/DMARC).",
            ),
        )

        for f in findings:
            f.evidence.setdefault("module", "external_entra")
            f.evidence.setdefault("read_only", True)
            f.evidence.setdefault("authorized_use", True)
        return findings

    def _summary_text(self, fp: dict[str, Any]) -> str:
        bits = [f"Target `{fp.get('input_domain')}`."]
        if fp.get("tenant_id"):
            bits.append(f"Tenant ID `{fp['tenant_id']}`.")
        if fp.get("region"):
            bits.append(f"Region `{fp['region']}`.")
        if fp.get("namespace_type"):
            bits.append(f"Namespace `{fp['namespace_type']}`.")
        if fp.get("federation_brand"):
            bits.append(f"Federation brand `{fp['federation_brand']}`.")
        if fp.get("mail_domain"):
            bits.append(f"Mail domain probed `{fp['mail_domain']}`.")
        bits.append("Verify every finding against your authorized target before remediation.")
        return " ".join(bits)

    def _tenant_openid(
        self, http: requests.Session, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        try:
            r = http.get(url, timeout=20)
            if not r.ok:
                return [
                    self.finding(
                        profile,
                        "OpenID configuration not found for domain",
                        Severity.PASS if r.status_code == 400 else Severity.INFO,
                        f"HTTP {r.status_code} for `{domain}` — may not be an Entra-backed domain, or vanity domain not verified.",
                        evidence={"url": url, "status": r.status_code},
                        barrier="Unknown domain reduces external fingerprinting.",
                    )
                ]
            data = r.json()
            issuer = data.get("issuer", "")
            m = re.search(r"login\.microsoftonline\.com/([0-9a-fA-F-]{36})/", issuer)
            if m:
                fp["tenant_id"] = m.group(1)
            fp["region"] = data.get("tenant_region_scope") or data.get("cloud_instance_name")
            fp["issuer"] = issuer
            return [
                self.finding(
                    profile,
                    "Entra tenant fingerprint via OpenID metadata",
                    Severity.INFO,
                    f"Public OIDC metadata confirms issuer and cloud region for `{domain}`.",
                    evidence={
                        "url": url,
                        "issuer": issuer,
                        "tenant_id": fp.get("tenant_id"),
                        "tenant_region_scope": data.get("tenant_region_scope"),
                        "token_endpoint": data.get("token_endpoint"),
                    },
                    barrier="OIDC discovery is expected for cloud identity.",
                    attack_path="Confirm tenant → craft phishing / device-code / federation follow-ups.",
                    remediation="Monitor anomalous sign-ins; treat public metadata as attacker-visible.",
                )
            ]
        except requests.RequestException as exc:
            return [
                self.finding(
                    profile,
                    "OpenID probe failed",
                    Severity.INFO,
                    str(exc),
                    evidence={"url": url},
                )
            ]

    def _openid_guid_hint(
        self, http: requests.Session, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        """Resolve tenant GUID via getuserrealm JSON when OpenID path used domain name."""
        if fp.get("tenant_id"):
            return []
        try:
            r = http.get(
                "https://login.microsoftonline.com/getuserrealm.srf",
                params={"login": f"probe@{domain}", "json": "1"},
                timeout=20,
            )
            if r.ok:
                data = r.json()
                # NameSpaceType etc.; TenantId sometimes present in related APIs
                tid = data.get("EnterpriseID") or data.get("TenantId")
                if tid and re.match(r"^[0-9a-fA-F-]{36}$", str(tid)):
                    fp["tenant_id"] = tid
        except requests.RequestException:
            pass
        return []

    def _user_realm(
        self, http: requests.Session, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            r = http.get(
                "https://login.microsoftonline.com/getuserrealm.srf",
                params={"login": f"probe@{domain}", "json": "1"},
                timeout=20,
            )
            if not r.ok:
                return [
                    self.finding(
                        profile,
                        "GetUserRealm not conclusive",
                        Severity.INFO,
                        f"HTTP {r.status_code}",
                        evidence={"status": r.status_code},
                    )
                ]
            data = r.json()
            ns = data.get("NameSpaceType") or data.get("NamespaceType")
            fp["namespace_type"] = ns
            fp["federation_brand"] = data.get("FederationBrandName") or data.get("FederationGlobalVersion")
            fp["cloud_instance"] = data.get("CloudInstanceName")
            auth_url = data.get("AuthURL") or data.get("AuthURL")
            if data.get("AuthURL"):
                fp["auth_url"] = data.get("AuthURL")

            sev = Severity.MEDIUM if ns == "Federated" else Severity.INFO
            desc = f"Realm discovery classifies `{domain}` as **{ns or 'Unknown'}**."
            if ns == "Federated":
                desc += " Federated tenants shift risk to the IdP (often ADFS) — federation endpoints become high-value targets."
            elif ns == "Managed":
                desc += " Managed cloud auth — password spray, legacy auth, and device-code phishing are typical next steps for attackers."
            elif ns == "Unknown":
                desc += " Domain may not be verified in Entra, or user does not exist in a way that reveals namespace."

            findings.append(
                self.finding(
                    profile,
                    f"Federation / namespace type: {ns or 'Unknown'}",
                    sev,
                    desc,
                    evidence={"getuserrealm": data},
                    barrier="Federation hardening, Smart Lockout, Conditional Access.",
                    attack_path="Managed → spray/phishing; Federated → ADFS/IdP attack surface.",
                    remediation="For Federated: harden ADFS (MFA, no IdP-initiated leakage). For Managed: block legacy auth + enforce phishing-resistant MFA.",
                )
            )

            # XML federation metadata if AuthURL suggests ADFS
            auth = data.get("AuthURL") or ""
            if "adfs" in auth.lower() or ns == "Federated":
                findings.append(
                    self.finding(
                        profile,
                        "Federated AuthURL exposed via realm discovery",
                        Severity.HIGH if "adfs" in auth.lower() else Severity.MEDIUM,
                        f"AuthURL points to `{auth or 'n/a'}`. Attackers use this to locate federation services.",
                        evidence={"AuthURL": auth, "FederationBrandName": data.get("FederationBrandName")},
                        barrier="ADFS network controls, WAF, disable unused endpoints.",
                        attack_path="Hit ADFS MEX / IdP-initiated sign-on → RP enumeration → Golden SAML prep.",
                        remediation="Restrict ADFS endpoints; remove debug relying parties; prefer cloud auth where possible.",
                    )
                )
        except requests.RequestException as exc:
            findings.append(
                self.finding(profile, "GetUserRealm probe failed", Severity.INFO, str(exc))
            )
        return findings

    def _credential_type_risk(
        self, http: requests.Session, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        """Probe GetCredentialType with a non-existent user to assess enumeration API availability."""
        url = "https://login.microsoftonline.com/common/GetCredentialType"
        payload = {
            "username": f"m365redteam-does-not-exist-{abs(hash(domain)) % 10_000_000}@{domain}",
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": "",
            "flowToken": "",
        }
        try:
            r = http.post(url, json=payload, timeout=20)
            if not r.ok:
                return [
                    self.finding(
                        profile,
                        "GetCredentialType not reachable",
                        Severity.PASS,
                        f"HTTP {r.status_code} — enumeration API less available from this network.",
                        evidence={"status": r.status_code},
                    )
                ]
            data = r.json()
            fp["get_credential_type"] = {
                "IfExistsResult": data.get("IfExistsResult"),
                "ThrottleStatus": data.get("ThrottleStatus"),
                "PrefCredential": data.get("PrefCredential"),
            }
            # IfExistsResult semantics: 0 exists, 1 not, 5 throttled / different, etc.
            return [
                self.finding(
                    profile,
                    "GetCredentialType user-existence API is reachable",
                    Severity.MEDIUM,
                    "Microsoft login GetCredentialType responds for this domain. Attackers commonly use it to validate emails before password spray or phishing.",
                    evidence={"response_keys": list(data.keys())[:20], "IfExistsResult": data.get("IfExistsResult"), "ThrottleStatus": data.get("ThrottleStatus")},
                    barrier="Smart Lockout, CAPTCHA, Conditional Access, banned password lists.",
                    attack_path="Validate users → spray or MFA fatigue → initial access.",
                    remediation="Enable Smart Lockout; monitor GetCredentialType / failed sign-in bursts; prefer passwordless.",
                )
            ]
        except requests.RequestException as exc:
            return [
                self.finding(profile, "GetCredentialType probe failed", Severity.INFO, str(exc))
            ]

    def _federation_metadata(
        self, http: requests.Session, domain: str, profile: AttackProfile
    ) -> list[Finding]:
        url = f"https://login.microsoftonline.com/{quote(domain)}/federationmetadata/2007-06/federationmetadata.xml"
        try:
            r = http.get(url, timeout=20)
            if not r.ok:
                return []
            entity_id = None
            try:
                root = ET.fromstring(r.content)
                entity_id = root.attrib.get("entityID")
            except ET.ParseError:
                pass
            return [
                self.finding(
                    profile,
                    "WS-Federation metadata document is public",
                    Severity.INFO,
                    "Federation metadata XML is downloadable without authentication.",
                    evidence={"url": url, "bytes": len(r.content), "entityID": entity_id},
                    barrier="Metadata alone is not credential access.",
                    attack_path="Study claims / endpoints for federation misconfiguration.",
                    remediation="Expected for federated scenarios; audit relying parties and signing keys.",
                )
            ]
        except requests.RequestException:
            return []

    def _login_branding(
        self, http: requests.Session, domain: str, profile: AttackProfile
    ) -> list[Finding]:
        # Company branding CSS / background often public via login CDN patterns
        url = f"https://login.microsoftonline.com/{quote(domain)}/oauth2/authorize"
        try:
            r = http.get(url, params={"client_id": "00000000-0000-0000-0000-000000000000", "response_type": "code", "redirect_uri": "https://localhost/"}, timeout=20, allow_redirects=True)
            snippet = r.text[:500] if r.text else ""
            branded = "BackgroundImage" in r.text or "bannerLogo" in r.text or "companyDisplayName" in r.text
            return [
                self.finding(
                    profile,
                    "Login page / branding surface reachable",
                    Severity.LOW if branded else Severity.INFO,
                    "Authorize endpoint responds — custom branding (if configured) can aid convincing phishing pages.",
                    evidence={"final_url": str(r.url), "status": r.status_code, "branding_hints": branded, "snippet_len": len(snippet)},
                    barrier="User education + phishing-resistant MFA reduce success of lookalike pages.",
                    attack_path="Clone branding → spear-phish credentials or MFA codes.",
                    remediation="Prefer FIDO2/passkeys; monitor for lookalike domains.",
                )
            ]
        except requests.RequestException as exc:
            return [self.finding(profile, "Login branding probe failed", Severity.INFO, str(exc))]

    def _dns_mail_posture(
        self, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Prefer custom domain if user passed one; for onmicrosoft, DNS mail is limited
        mail_domain = domain
        fp["mail_domain"] = mail_domain

        mx = _dns_texts(mail_domain, "MX")
        txt = _dns_texts(mail_domain, "TXT")
        if mx:
            findings.append(
                self.finding(
                    profile,
                    "MX records published",
                    Severity.INFO,
                    f"Found {len(mx)} MX record(s) for `{mail_domain}`.",
                    evidence={"mx": mx[:15]},
                    attack_path="Map mail flow → phishing / spoofing planning.",
                    remediation="Keep MX accurate; protect with SPF/DKIM/DMARC.",
                )
            )
            if any("mail.protection.outlook.com" in m.lower() for m in mx):
                findings.append(
                    self.finding(
                        profile,
                        "Exchange Online mail hosting indicated",
                        Severity.INFO,
                        "MX points at Outlook protection — M365 mail stack is in play.",
                        evidence={"mx": mx[:10]},
                        barrier="EXO anti-phish / Defender for Office 365.",
                        attack_path="Target OWA / legacy protocols / BEC.",
                        remediation="Disable legacy auth; enable anti-phish policies.",
                    )
                )

        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        dmarc = _dns_texts(f"_dmarc.{mail_domain}", "TXT")
        if txt or domain.endswith(".onmicrosoft.com"):
            if not spf and not domain.endswith(".onmicrosoft.com"):
                findings.append(
                    self.finding(
                        profile,
                        "SPF record missing",
                        Severity.MEDIUM,
                        f"No SPF TXT found for `{mail_domain}` — spoofing is easier.",
                        evidence={"txt_sample": txt[:10]},
                        barrier="Downstream DMARC can still help if present.",
                        attack_path="Spoof employee mail → credential harvest.",
                        remediation="Publish SPF aligned to sending services.",
                    )
                )
            elif spf:
                findings.append(
                    self.finding(
                        profile,
                        "SPF record present",
                        Severity.PASS if "-all" in spf[0] else Severity.LOW,
                        f"SPF: `{spf[0][:180]}`",
                        evidence={"spf": spf},
                        remediation="Use `-all` (fail) when ready; avoid overly broad includes.",
                    )
                )

            if not dmarc and not domain.endswith(".onmicrosoft.com"):
                findings.append(
                    self.finding(
                        profile,
                        "DMARC record missing",
                        Severity.HIGH,
                        f"No DMARC policy at `_dmarc.{mail_domain}` — attackers can spoof the domain more easily.",
                        evidence={"dmarc": dmarc},
                        barrier="Provider-side anti-spoof may still apply for some receivers.",
                        attack_path="Spoof CEO/finance → BEC / credential phishing.",
                        remediation="Publish DMARC `p=quarantine` or `p=reject` with monitoring.",
                    )
                )
            elif dmarc:
                policy = dmarc[0]
                weak = "p=none" in policy.lower()
                findings.append(
                    self.finding(
                        profile,
                        "DMARC policy present" + (" but monitoring-only (p=none)" if weak else ""),
                        Severity.MEDIUM if weak else Severity.PASS,
                        f"DMARC: `{policy[:200]}`",
                        evidence={"dmarc": dmarc},
                        remediation="Move from p=none to quarantine/reject once reports look clean.",
                    )
                )

        if not findings and domain.endswith(".onmicrosoft.com"):
            findings.append(
                self.finding(
                    profile,
                    "Mail DNS limited on onmicrosoft.com",
                    Severity.INFO,
                    "For deeper SPF/DKIM/DMARC review, re-run against the organization's vanity domain (e.g. contoso.com).",
                    evidence={"domain": domain},
                )
            )
        return findings

    def _autodiscover(self, http: requests.Session, domain: str, profile: AttackProfile) -> list[Finding]:
        try:
            # Lightweight GET — Outlook web entry; full Autodiscover SOAP is out of scope.
            r = http.get(f"https://outlook.office365.com/mail/{quote(domain)}", timeout=15, allow_redirects=False)
            findings = [
                self.finding(
                    profile,
                    "Outlook / Office 365 web endpoints respond",
                    Severity.INFO,
                    "Office 365 web entry points are reachable — expected for M365 tenants.",
                    evidence={"outlook_probe_status": r.status_code, "autodiscover_host": "autodiscover-s.outlook.com"},
                    attack_path="Password spray against legacy protocols if enabled.",
                    remediation="Block basic auth; enable CA for Office 365.",
                )
            ]
            return findings
        except requests.RequestException:
            return []

    def _sharepoint_onedrive(
        self, http: requests.Session, domain: str, profile: AttackProfile, fp: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        base = domain
        if base.endswith(".onmicrosoft.com"):
            slug = base[: -len(".onmicrosoft.com")]
        else:
            slug = base.split(".")[0]

        hosts = [
            f"https://{slug}.sharepoint.com/",
            f"https://{slug}-my.sharepoint.com/",
            f"https://{slug}-admin.sharepoint.com/",
        ]
        alive = []
        for h in hosts:
            try:
                r = http.get(h, timeout=15, allow_redirects=False)
                if r.status_code < 500:
                    alive.append({"url": h, "status": r.status_code})
            except requests.RequestException:
                continue
        fp["sharepoint_hosts"] = alive
        if alive:
            findings.append(
                self.finding(
                    profile,
                    "SharePoint / OneDrive hostnames resolve",
                    Severity.INFO,
                    f"Detected {len(alive)} SharePoint-related host response(s) for slug `{slug}`.",
                    evidence={"hosts": alive},
                    barrier="SharePoint sharing controls + Conditional Access.",
                    attack_path="Hunt anonymous links / guess site names / phish for OAuth to Files.",
                    remediation="Disable anonymous sharing; review external sharing defaults.",
                )
            )
        else:
            findings.append(
                self.finding(
                    profile,
                    "SharePoint hostnames not confirmed",
                    Severity.INFO,
                    f"No HTTP response for common `{slug}.sharepoint.com` patterns — tenant slug may differ from domain label.",
                    evidence={"tried": hosts},
                )
            )
        return findings

    def _device_code_surface(self, profile: AttackProfile) -> list[Finding]:
        return [
            self.finding(
                profile,
                "Device code / OAuth phishing surface (Microsoft-native)",
                Severity.MEDIUM,
                "Microsoft device code flow is a common phishing technique against Entra users. No tenant-specific exploit is run; this flags the universal risk.",
                evidence={"flows": ["device_code", "OAuth consent"]},
                barrier="Conditional Access authentication strengths; block legacy; user reporting.",
                attack_path="Send device-code instructions → victim authenticates → attacker obtains token.",
                remediation="Prefer phishing-resistant MFA; educate users; alert on unusual device-code grants.",
            )
        ]

    def _b2c_external_id_hints(
        self, http: requests.Session, domain: str, profile: AttackProfile
    ) -> list[Finding]:
        findings: list[Finding] = []
        if domain.endswith(".onmicrosoft.com"):
            slug = domain[: -len(".onmicrosoft.com")]
            for host in (f"https://{slug}.b2clogin.com/", f"https://{slug}.ciamlogin.com/"):
                try:
                    r = http.get(host, timeout=12, allow_redirects=False)
                    if r.status_code < 500:
                        findings.append(
                            self.finding(
                                profile,
                                f"Possible External ID / B2C host: {host}",
                                Severity.LOW,
                                "Host responded — may indicate B2C or External ID configuration to review.",
                                evidence={"url": host, "status": r.status_code},
                                remediation="Inventory customer-facing IdPs; lock down user flows.",
                            )
                        )
                except requests.RequestException:
                    continue
        return findings