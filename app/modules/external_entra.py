"""External Entra / M365 reconnaissance (unauthenticated, read-only).

Coverage aligned with the same problem space as comprehensive Entra recon tools
(tenant, federation, user enum, M365 apps, DNS/mail, MFA gaps, OAuth, Azure edge)
implemented as our own product — not a code copy.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests

from app.core.models import AssessmentCategory, AttackProfile, Finding, Likelihood, Severity
from app.modules.base import AssessmentModule

USER_AGENT = "M365RedTeam/0.3 (+authorized-assessment; read-only)"

DKIM_SELECTORS = [
    "selector1", "selector2", "google", "k1", "k2", "s1", "s2", "default",
    "mail", "smtp", "dkim", "cm", "mandrill", "mx", "everlytickey1", "ctct1",
]

M365_APP_HINTS = [
    ("forms", "https://forms.office.com/Pages/ResponsePage.aspx"),
    ("stream", "https://web.microsoftstream.com"),
    ("loop", "https://loop.microsoft.com"),
    ("whiteboard", "https://whiteboard.microsoft.com"),
    ("sway", "https://sway.office.com"),
    ("bookings", "https://outlook.office.com/bookwithme/"),
]

TAKEOVER_SUFFIXES = [
    "azurewebsites.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "azurefd.net",
    "azurestaticapps.net",
    "blob.core.windows.net",
    "azure-api.net",
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    return s


def _dns_texts(name: str, rtype: str) -> list[str]:
    try:
        return [str(r).strip('"') for r in dns.resolver.resolve(name, rtype)]
    except Exception:  # noqa: BLE001
        return []


def _slug(domain: str) -> str:
    d = domain.lower().strip().rstrip(".")
    if d.endswith(".onmicrosoft.com"):
        return d[: -len(".onmicrosoft.com")]
    return d.split(".")[0]


class ExternalEntraModule(AssessmentModule):
    category = AssessmentCategory.ATTACK_SURFACE
    supported_profiles = {AttackProfile.EXTERNAL}

    def run(self, profile: AttackProfile) -> list[Finding]:
        domain = self.tenant.strip()
        http = _session()
        fp: dict[str, Any] = {"input_domain": domain, "slug": _slug(domain)}
        findings: list[Finding] = []

        findings += self._phase_tenant(http, domain, profile, fp)
        findings += self._phase_federation(http, domain, profile, fp)
        findings += self._phase_user_enum(http, domain, profile, fp)
        findings += self._phase_dns_mail(domain, profile, fp)
        findings += self._phase_m365_services(http, domain, profile, fp)
        findings += self._phase_auth_mfa_gaps(http, domain, profile, fp)
        findings += self._phase_oauth(profile)
        findings += self._phase_azure_edge(http, domain, profile, fp)
        findings += self._phase_power_dynamics(http, domain, profile, fp)

        findings.insert(
            0,
            self.finding(
                profile,
                "External scan complete — verify on the authorized tenant",
                Severity.INFO,
                self._summary(fp),
                evidence={"fingerprint": fp},
                likelihood=Likelihood.LESS_LIKELY,
                why="Summary only. Individual High/Medium items below drive risk.",
                phase="summary",
                remediation="Notify stakeholders, verify each finding, then remediate highest-likelihood paths first.",
            ),
        )

        for f in findings:
            f.evidence.setdefault("module", "external_entra")
            f.evidence.setdefault("read_only", True)
        return findings

    def _summary(self, fp: dict[str, Any]) -> str:
        parts = [f"Target `{fp.get('input_domain')}`."]
        for key, label in (
            ("tenant_id", "Tenant ID"),
            ("region", "Region"),
            ("namespace_type", "Namespace"),
            ("auth_url", "AuthURL"),
        ):
            if fp.get(key):
                parts.append(f"{label}: `{fp[key]}`.")
        parts.append("Attackers can query the same public endpoints.")
        return " ".join(parts)

    # --- phases -------------------------------------------------------------

    def _phase_tenant(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        try:
            r = http.get(url, timeout=20)
            if r.ok:
                data = r.json()
                issuer = data.get("issuer", "")
                m = re.search(r"/([0-9a-fA-F-]{36})/", issuer)
                if m:
                    fp["tenant_id"] = m.group(1)
                fp["region"] = data.get("tenant_region_scope") or data.get("cloud_instance_name")
                fp["issuer"] = issuer
                out.append(
                    self.finding(
                        profile,
                        "Tenant fingerprint confirmed (OpenID)",
                        Severity.INFO,
                        f"Public OIDC metadata is reachable for `{domain}`.",
                        evidence={"url": url, "issuer": issuer, "region": fp.get("region"), "tenant_id": fp.get("tenant_id")},
                        phase="tenant",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Expected cloud behavior — not a bypass by itself, but required recon for every attacker.",
                        attack_path="Fingerprint tenant → plan phishing / spray / federation follow-ups.",
                        remediation="Monitor anomalous sign-ins; assume metadata is public.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )
            else:
                out.append(
                    self.finding(
                        profile,
                        "Domain may not resolve as an Entra tenant",
                        Severity.LOW,
                        f"OpenID returned HTTP {r.status_code}. Confirm you entered the correct authorized domain.",
                        evidence={"url": url, "status": r.status_code},
                        phase="tenant",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Without a valid tenant fingerprint, later checks are less reliable.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )
        except requests.RequestException as exc:
            out.append(
                self.finding(
                    profile, "OpenID probe failed", Severity.INFO, str(exc),
                    phase="tenant", likelihood=Likelihood.LESS_LIKELY, why="Network error during fingerprint.",
                )
            )
        return out

    def _phase_federation(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = http.get(
                "https://login.microsoftonline.com/getuserrealm.srf",
                params={"login": f"probe@{domain}", "json": "1"},
                timeout=20,
            )
            if not r.ok:
                return out
            data = r.json()
            ns = data.get("NameSpaceType") or data.get("NamespaceType")
            fp["namespace_type"] = ns
            fp["federation_brand"] = data.get("FederationBrandName")
            fp["auth_url"] = data.get("AuthURL")
            auth = (data.get("AuthURL") or "").lower()

            if ns == "Federated":
                out.append(
                    self.finding(
                        profile,
                        "Tenant is Federated (not cloud-managed auth)",
                        Severity.HIGH if "adfs" in auth else Severity.MEDIUM,
                        f"Realm discovery reports Federated. AuthURL: `{data.get('AuthURL') or 'n/a'}`.",
                        evidence={"getuserrealm": data},
                        phase="federation",
                        likelihood=Likelihood.MOST_LIKELY if "adfs" in auth else Likelihood.POSSIBLE,
                        why=(
                            "Federated tenants move risk to the IdP. ADFS endpoints are a common high-value target "
                            "and can enable paths that skip cloud MFA if misconfigured."
                        ),
                        attack_path="Locate ADFS → probe MEX / IdP-initiated → RP exposure → Golden SAML prep.",
                        barrier="ADFS hardening, MFA at IdP, remove debug RPs.",
                        remediation="Inventory ADFS relying parties; enforce MFA on IdP; prefer cloud auth where possible.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )
                if data.get("AuthURL"):
                    out.extend(self._probe_adfs(http, data["AuthURL"], profile))
            elif ns == "Managed":
                out.append(
                    self.finding(
                        profile,
                        "Tenant uses Managed (cloud) authentication",
                        Severity.INFO,
                        "NamespaceType=Managed — password spray, legacy auth, and device-code phishing are the usual next steps.",
                        evidence={"getuserrealm": data},
                        phase="federation",
                        likelihood=Likelihood.POSSIBLE,
                        why="Cloud-managed auth is normal. Risk depends on MFA, Smart Lockout, and legacy protocol posture.",
                        attack_path="Enumerate users → spray or phish → mailbox / Graph.",
                        remediation="Phishing-resistant MFA + Smart Lockout + block legacy auth.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )
            else:
                out.append(
                    self.finding(
                        profile,
                        f"Namespace type: {ns or 'Unknown'}",
                        Severity.LOW,
                        "Realm discovery did not clearly classify Managed vs Federated.",
                        evidence={"getuserrealm": data},
                        phase="federation",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Ambiguous classification reduces confidence in federation-specific paths.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )

            # Federation metadata
            meta = http.get(
                f"https://login.microsoftonline.com/{quote(domain)}/federationmetadata/2007-06/federationmetadata.xml",
                timeout=15,
            )
            if meta.ok:
                entity = None
                try:
                    entity = ET.fromstring(meta.content).attrib.get("entityID")
                except ET.ParseError:
                    pass
                out.append(
                    self.finding(
                        profile,
                        "WS-Federation metadata is public",
                        Severity.LOW,
                        "Federation metadata XML downloads without authentication.",
                        evidence={"bytes": len(meta.content), "entityID": entity},
                        phase="federation",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Metadata alone is not access, but helps attackers study claims and endpoints.",
                        remediation="Expected for many tenants; audit signing keys and RPs.",
                        category=AssessmentCategory.ATTACK_SURFACE,
                    )
                )
        except requests.RequestException as exc:
            out.append(
                self.finding(profile, "Federation probe failed", Severity.INFO, str(exc), phase="federation")
            )

        # B2C / External ID hosts
        slug = fp.get("slug") or _slug(domain)
        for host, label in (
            (f"https://{slug}.b2clogin.com/", "B2C"),
            (f"https://{slug}.ciamlogin.com/", "External ID / CIAM"),
        ):
            try:
                r = http.get(host, timeout=10, allow_redirects=False)
                if r.status_code < 500:
                    out.append(
                        self.finding(
                            profile,
                            f"{label} host responds ({host})",
                            Severity.LOW,
                            f"Public {label} endpoint answered HTTP {r.status_code}.",
                            evidence={"url": host, "status": r.status_code},
                            phase="federation",
                            likelihood=Likelihood.POSSIBLE,
                            why=f"Customer-facing {label} flows expand identity attack surface if user flows are weak.",
                            remediation="Review user flows, MFA, and exposed APIs on customer IdPs.",
                            category=AssessmentCategory.ATTACK_SURFACE,
                        )
                    )
            except requests.RequestException:
                pass
        return out

    def _probe_adfs(self, http, auth_url: str, profile) -> list[Finding]:
        out: list[Finding] = []
        base = auth_url.split("/adfs/")[0] if "/adfs/" in auth_url.lower() else auth_url.rstrip("/")
        probes = [
            ("/adfs/services/trust/mex", "ADFS MEX endpoint"),
            ("/adfs/ls/IdpInitiatedSignOn.aspx", "ADFS IdP-initiated sign-on page"),
            ("/FederationMetadata/2007-06/FederationMetadata.xml", "ADFS federation metadata"),
        ]
        for path, title in probes:
            url = base.rstrip("/") + path
            try:
                r = http.get(url, timeout=12, allow_redirects=True)
                if r.status_code < 500:
                    sev = Severity.HIGH if "mex" in path.lower() or "IdpInitiated" in path else Severity.MEDIUM
                    out.append(
                        self.finding(
                            profile,
                            f"{title} reachable",
                            sev,
                            f"`{url}` returned HTTP {r.status_code} ({len(r.content)} bytes).",
                            evidence={"url": url, "status": r.status_code, "bytes": len(r.content)},
                            phase="federation",
                            likelihood=Likelihood.MOST_LIKELY if sev == Severity.HIGH else Likelihood.POSSIBLE,
                            why=(
                                "Exposed ADFS discovery/sign-on surfaces are classic external footholds. "
                                "IdP-initiated pages and MEX help map relying parties."
                            ),
                            attack_path="Enumerate RPs → find weak trusts → forge/abuse federation.",
                            remediation="Restrict ADFS endpoints; disable unused IdP-initiated; remove debug RPs.",
                            category=AssessmentCategory.ATTACK_SURFACE,
                        )
                    )
            except requests.RequestException:
                continue
        return out

    def _phase_user_enum(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        url = "https://login.microsoftonline.com/common/GetCredentialType"
        payload = {
            "username": f"m365rt-nexists-{abs(hash(domain)) % 10_000_000}@{domain}",
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isFidoSupported": True,
            "originalRequest": "",
            "flowToken": "",
        }
        try:
            r = http.post(url, json=payload, timeout=20)
            if r.ok:
                data = r.json()
                fp["get_credential_type"] = {
                    "IfExistsResult": data.get("IfExistsResult"),
                    "ThrottleStatus": data.get("ThrottleStatus"),
                }
                out.append(
                    self.finding(
                        profile,
                        "GetCredentialType user-validation API is reachable",
                        Severity.HIGH,
                        "Login GetCredentialType responds for this domain — commonly used to validate emails before spray/phish.",
                        evidence={"IfExistsResult": data.get("IfExistsResult"), "ThrottleStatus": data.get("ThrottleStatus")},
                        phase="user_enum",
                        likelihood=Likelihood.MOST_LIKELY,
                        why=(
                            "This is usually the most practical external bypass helper: attackers confirm which users exist, "
                            "then spray or phish only valid accounts. Throttling reduces but does not eliminate abuse."
                        ),
                        attack_path="Validate users → password spray / MFA fatigue → initial access.",
                        barrier="Smart Lockout, CAPTCHA, banned passwords, CA.",
                        remediation="Enable Smart Lockout; alert on GetCredentialType / failed-signin bursts; prefer passwordless.",
                        category=AssessmentCategory.IDENTITY_SECURITY,
                    )
                )
            else:
                out.append(
                    self.finding(
                        profile,
                        "GetCredentialType not freely reachable",
                        Severity.PASS,
                        f"HTTP {r.status_code} — enumeration API less available from this network.",
                        phase="user_enum",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Harder silent user validation from this vantage point.",
                        category=AssessmentCategory.IDENTITY_SECURITY,
                    )
                )
        except requests.RequestException as exc:
            out.append(
                self.finding(profile, "GetCredentialType failed", Severity.INFO, str(exc), phase="user_enum")
            )

        # OneDrive user path probe (timing/existence channel) — single probe user only
        slug = fp.get("slug") or _slug(domain)
        od = f"https://{slug}-my.sharepoint.com/personal/probe_user_{slug}_onmicrosoft_com/_layouts/15/onedrive.aspx"
        try:
            r = http.get(od, timeout=12, allow_redirects=False)
            out.append(
                self.finding(
                    profile,
                    "OneDrive personal URL pattern responds",
                    Severity.MEDIUM if r.status_code in {200, 302, 401, 403} else Severity.LOW,
                    f"OneDrive-style path returned HTTP {r.status_code}. Attackers sometimes use personal URL differences for user clues.",
                    evidence={"url": od, "status": r.status_code},
                    phase="user_enum",
                    likelihood=Likelihood.POSSIBLE,
                    why="Not always reliable alone, but pairs with GetCredentialType for cross-checks.",
                    remediation="Do not expose predictable personal URL schemes publicly more than necessary; monitor enum traffic.",
                    category=AssessmentCategory.IDENTITY_SECURITY,
                )
            )
        except requests.RequestException:
            pass

        # Graph metadata
        try:
            r = http.get("https://graph.microsoft.com/v1.0/$metadata", timeout=12)
            out.append(
                self.finding(
                    profile,
                    "Microsoft Graph metadata is public",
                    Severity.INFO,
                    f"Graph $metadata HTTP {r.status_code} — expected; confirms Graph surface for later auth abuse.",
                    evidence={"status": r.status_code},
                    phase="user_enum",
                    likelihood=Likelihood.LESS_LIKELY,
                    why="Public API docs/metadata are normal; risk appears after token theft.",
                    category=AssessmentCategory.IDENTITY_SECURITY,
                )
            )
        except requests.RequestException:
            pass
        return out

    def _phase_dns_mail(self, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        mail_domain = domain
        fp["mail_domain"] = mail_domain
        mx = _dns_texts(mail_domain, "MX")
        txt = _dns_texts(mail_domain, "TXT")
        dmarc = _dns_texts(f"_dmarc.{mail_domain}", "TXT")

        if mx:
            out.append(
                self.finding(
                    profile, "MX records published", Severity.INFO,
                    f"{len(mx)} MX record(s) for `{mail_domain}`.",
                    evidence={"mx": mx[:15]}, phase="dns_mail", likelihood=Likelihood.LESS_LIKELY,
                    why="Shows where mail is hosted — targeting input, not a bypass alone.",
                    category=AssessmentCategory.DNS_MAIL,
                )
            )
            if any("mail.protection.outlook.com" in m.lower() for m in mx):
                out.append(
                    self.finding(
                        profile, "Exchange Online indicated by MX", Severity.INFO,
                        "MX points at Outlook protection.",
                        evidence={"mx": mx[:10]}, phase="dns_mail", likelihood=Likelihood.POSSIBLE,
                        why="Confirms EXO as a phishing / BEC / legacy-auth target.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )

        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not domain.endswith(".onmicrosoft.com"):
            if not spf:
                out.append(
                    self.finding(
                        profile, "SPF missing", Severity.MEDIUM,
                        f"No SPF TXT for `{mail_domain}`.",
                        phase="dns_mail", likelihood=Likelihood.MOST_LIKELY,
                        why="Missing SPF makes spoofed-from mail easier, which feeds phishing that bypasses technical auth.",
                        attack_path="Spoof trusted sender → harvest credentials / device-code.",
                        remediation="Publish SPF aligned to real senders.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )
            else:
                soft = "+all" in spf[0] or "?all" in spf[0]
                out.append(
                    self.finding(
                        profile, "SPF present" + (" but permissive" if soft else ""),
                        Severity.MEDIUM if soft else Severity.PASS,
                        spf[0][:200],
                        evidence={"spf": spf}, phase="dns_mail",
                        likelihood=Likelihood.POSSIBLE if soft else Likelihood.LESS_LIKELY,
                        why="Permissive SPF (+all/?all) weakens spoofing defenses.",
                        remediation="Tighten SPF toward `-all` when ready.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )

            if not dmarc:
                out.append(
                    self.finding(
                        profile, "DMARC missing", Severity.HIGH,
                        f"No DMARC at `_dmarc.{mail_domain}`.",
                        phase="dns_mail", likelihood=Likelihood.MOST_LIKELY,
                        why=(
                            "This is one of the most likely external bypass enablers: spoofed executive/finance mail "
                            "that users trust, leading to credential or invoice fraud without cracking Entra."
                        ),
                        attack_path="Spoof domain → BEC / phishing → account or payment fraud.",
                        remediation="Publish DMARC p=quarantine or p=reject after monitoring.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )
            else:
                weak = "p=none" in dmarc[0].lower()
                out.append(
                    self.finding(
                        profile, "DMARC present" + (" (p=none monitoring only)" if weak else ""),
                        Severity.MEDIUM if weak else Severity.PASS,
                        dmarc[0][:200],
                        evidence={"dmarc": dmarc}, phase="dns_mail",
                        likelihood=Likelihood.POSSIBLE if weak else Likelihood.LESS_LIKELY,
                        why="p=none does not block spoofing — it only reports.",
                        remediation="Move to quarantine/reject.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )

            # DKIM selectors
            found_dkim = []
            for sel in DKIM_SELECTORS:
                recs = _dns_texts(f"{sel}._domainkey.{mail_domain}", "TXT")
                if recs:
                    found_dkim.append(sel)
            if found_dkim:
                out.append(
                    self.finding(
                        profile, f"DKIM selectors found ({len(found_dkim)})",
                        Severity.INFO,
                        "Selectors: " + ", ".join(found_dkim),
                        evidence={"selectors": found_dkim}, phase="dns_mail",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Reveals mail architecture / ESP partners — useful targeting intel.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )
            else:
                out.append(
                    self.finding(
                        profile, "No common DKIM selectors found",
                        Severity.MEDIUM,
                        "Bruted common selectors returned nothing — mail may be unsigned or use uncommon selectors.",
                        phase="dns_mail", likelihood=Likelihood.POSSIBLE,
                        why="Missing DKIM weakens DMARC alignment and spoof resistance.",
                        remediation="Enable DKIM for all sending services.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )

            # TXT SaaS verification mining (simple patterns)
            saas_hits = []
            patterns = {
                "atlassian": "atlassian",
                "google": "google-site-verification",
                "ms": "ms=",
                "spf": "v=spf1",
                "apple": "apple-domain",
                "facebook": "facebook-domain",
                "zoom": "zoom_",
            }
            for label, needle in patterns.items():
                if any(needle in t.lower() for t in txt):
                    saas_hits.append(label)
            if saas_hits:
                out.append(
                    self.finding(
                        profile, "DNS TXT reveals SaaS verification tokens",
                        Severity.LOW,
                        "Observed markers: " + ", ".join(saas_hits),
                        evidence={"txt_sample": txt[:20], "markers": saas_hits},
                        phase="dns_mail", likelihood=Likelihood.POSSIBLE,
                        why="Shows connected SaaS supply chain that can be used for secondary phishing pivots.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )
        else:
            out.append(
                self.finding(
                    profile, "Use vanity domain for full mail DNS review",
                    Severity.INFO,
                    "You scanned an onmicrosoft.com name — re-run against contoso.com (or similar) for SPF/DKIM/DMARC depth.",
                    phase="dns_mail", likelihood=Likelihood.LESS_LIKELY,
                    why="Mail auth posture usually lives on the public brand domain.",
                    category=AssessmentCategory.DNS_MAIL,
                )
            )

        # Autodiscover / SRV
        for srv in (f"_autodiscover._tcp.{mail_domain}", f"_sip._tls.{mail_domain}"):
            vals = _dns_texts(srv, "SRV")
            if vals:
                out.append(
                    self.finding(
                        profile, f"SRV record {srv}",
                        Severity.INFO, "; ".join(vals[:5]),
                        evidence={"srv": vals[:8]}, phase="dns_mail",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Service discovery aids targeting of mail/UC endpoints.",
                        category=AssessmentCategory.DNS_MAIL,
                    )
                )
        return out

    def _phase_m365_services(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        slug = fp.get("slug") or _slug(domain)
        hosts = [
            (f"https://{slug}.sharepoint.com/", "SharePoint"),
            (f"https://{slug}-my.sharepoint.com/", "OneDrive"),
            (f"https://{slug}-admin.sharepoint.com/", "SharePoint admin"),
        ]

        def probe(item):
            url, label = item
            try:
                r = http.get(url, timeout=12, allow_redirects=False)
                return label, url, r.status_code, len(r.content)
            except requests.RequestException as exc:
                return label, url, None, str(exc)

        with ThreadPoolExecutor(max_workers=6) as pool:
            for label, url, status, extra in pool.map(probe, hosts):
                if status is None:
                    continue
                if status < 500:
                    out.append(
                        self.finding(
                            profile, f"{label} host responds",
                            Severity.MEDIUM if "admin" in label.lower() else Severity.LOW,
                            f"`{url}` → HTTP {status}",
                            evidence={"url": url, "status": status},
                            phase="m365_services",
                            likelihood=Likelihood.POSSIBLE,
                            why="Confirms collaboration footprint. Admin host exposure increases recon value.",
                            attack_path="Hunt anonymous links / guest sharing / OAuth to Files.",
                            remediation="Tighten external sharing; CA on SharePoint.",
                            category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                        )
                    )

        # SharePoint anonymous API hint on root
        sp = f"https://{slug}.sharepoint.com/_api/web"
        try:
            r = http.get(sp, timeout=12, headers={"Accept": "application/json"})
            if r.status_code == 200:
                out.append(
                    self.finding(
                        profile, "SharePoint REST /_api/web returned 200 anonymously",
                        Severity.HIGH,
                        "Anonymous read of site web API succeeded — potential data exposure.",
                        evidence={"url": sp, "status": r.status_code},
                        phase="m365_services",
                        likelihood=Likelihood.MOST_LIKELY,
                        why="Unauthenticated SharePoint API access is a direct content/config leak path.",
                        remediation="Lock anonymous access; review sharing and site permissions.",
                        category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                    )
                )
            elif r.status_code in {401, 403}:
                out.append(
                    self.finding(
                        profile, "SharePoint REST requires auth (good)",
                        Severity.PASS,
                        f"`/_api/web` → HTTP {r.status_code}",
                        phase="m365_services", likelihood=Likelihood.LESS_LIKELY,
                        why="Anonymous API read blocked.",
                        category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                    )
                )
        except requests.RequestException:
            pass

        # Exchange endpoints
        for label, url in (
            ("OWA", "https://outlook.office365.com/owa/"),
            ("EWS", "https://outlook.office365.com/EWS/Exchange.asmx"),
            ("Autodiscover", "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"),
        ):
            try:
                r = http.get(url, timeout=12, allow_redirects=False)
                out.append(
                    self.finding(
                        profile, f"Exchange Online {label} endpoint responds",
                        Severity.INFO,
                        f"`{url}` → HTTP {r.status_code}",
                        evidence={"url": url, "status": r.status_code},
                        phase="m365_services", likelihood=Likelihood.POSSIBLE,
                        why="Expected for EXO tenants; becomes high risk if basic auth / legacy is enabled.",
                        category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                    )
                )
            except requests.RequestException:
                pass

        # Office app portals (existence)
        for name, url in M365_APP_HINTS:
            try:
                r = http.get(url, timeout=10, allow_redirects=False)
                if r.status_code < 500:
                    out.append(
                        self.finding(
                            profile, f"Microsoft {name} portal reachable",
                            Severity.LOW,
                            f"`{url}` → HTTP {r.status_code}",
                            phase="m365_services", likelihood=Likelihood.LESS_LIKELY,
                            why="Broad M365 app surface; useful for phishing lures and token scopes later.",
                            category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                        )
                    )
            except requests.RequestException:
                continue
        return out

    def _phase_auth_mfa_gaps(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        # ROPC is always MFA-skip by design when allowed — flag as conceptual + probe token endpoint acceptance shape
        out.append(
            self.finding(
                profile,
                "ROPC (resource owner password credential) is an MFA-bypass class flow",
                Severity.HIGH,
                "If the tenant still allows ROPC for any public client, passwords can authenticate without interactive MFA.",
                phase="mfa_gaps",
                likelihood=Likelihood.MOST_LIKELY,
                why=(
                    "Most likely technical bypass class on managed tenants that still permit legacy/ROPC: "
                    "no interactive MFA challenge. Confirm in Entra auth policies — this check flags the risk class."
                ),
                attack_path="Spray valid users via ROPC-capable client → token without MFA prompt.",
                barrier="Block ROPC / legacy auth; require authentication strengths.",
                remediation="Disable ROPC and legacy authentication tenant-wide; enforce phishing-resistant MFA.",
                category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
                evidence={"note": "policy confirmation requires admin; flagged from public knowledge + tenant type"},
            )
        )

        # Device code
        out.append(
            self.finding(
                profile,
                "Device code phishing remains a high-success social bypass",
                Severity.HIGH,
                "Microsoft device code flow is frequently abused; users approve attacker-generated codes.",
                phase="mfa_gaps",
                likelihood=Likelihood.MOST_LIKELY,
                why=(
                    "Often more likely than cracking MFA: the user performs a real login. "
                    "Works even when passwords are strong."
                ),
                attack_path="Send device-code instructions → victim authenticates → attacker receives tokens.",
                remediation="User education; alert on unusual device-code grants; prefer authentication strengths that resist phishing.",
                category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
            )
        )

        # Autodiscover basic auth banner / endpoint
        try:
            r = http.get(
                "https://outlook.office365.com/EWS/Exchange.asmx",
                timeout=12,
                headers={"Authorization": "Basic dGVzdDp0ZXN0"},
            )
            www = r.headers.get("WWW-Authenticate", "")
            if "Basic" in www:
                out.append(
                    self.finding(
                        profile,
                        "EWS advertises Basic authentication",
                        Severity.HIGH,
                        f"WWW-Authenticate includes Basic (HTTP {r.status_code}).",
                        evidence={"www_authenticate": www, "status": r.status_code},
                        phase="mfa_gaps",
                        likelihood=Likelihood.MOST_LIKELY,
                        why="Basic/legacy auth paths historically bypass modern MFA prompts.",
                        remediation="Block basic auth / legacy protocols in EXO and Entra.",
                        category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
                    )
                )
            else:
                out.append(
                    self.finding(
                        profile,
                        "EWS did not advertise Basic in this probe",
                        Severity.PASS,
                        f"HTTP {r.status_code}; WWW-Authenticate={www or 'n/a'}",
                        phase="mfa_gaps",
                        likelihood=Likelihood.LESS_LIKELY,
                        why="Good signal for this vantage point — still verify EXO auth policies.",
                        category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
                    )
                )
        except requests.RequestException as exc:
            out.append(
                self.finding(profile, "EWS auth probe failed", Severity.INFO, str(exc), phase="mfa_gaps")
            )

        # ADFS usernamemixed if federated
        auth = (fp.get("auth_url") or "")
        if "adfs" in auth.lower():
            base = auth.split("/adfs/")[0]
            for path in (
                "/adfs/services/trust/2005/usernamemixed",
                "/adfs/services/trust/13/usernamemixed",
                "/adfs/services/trust/2005/windowstransport",
            ):
                url = base.rstrip("/") + path
                try:
                    r = http.get(url, timeout=10, allow_redirects=False)
                    if r.status_code < 500:
                        out.append(
                            self.finding(
                                profile,
                                f"ADFS WS-Trust endpoint reachable ({path.split('/')[-1]})",
                                Severity.HIGH,
                                f"`{url}` → HTTP {r.status_code}",
                                evidence={"url": url, "status": r.status_code},
                                phase="mfa_gaps",
                                likelihood=Likelihood.MOST_LIKELY,
                                why="WS-Trust username mixed / Windows transport endpoints are classic MFA-gap surfaces on ADFS.",
                                remediation="Disable unused WS-Trust endpoints; enforce MFA at IdP.",
                                category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
                            )
                        )
                except requests.RequestException:
                    continue
        return out

    def _phase_oauth(self, profile) -> list[Finding]:
        return [
            self.finding(
                profile,
                "OAuth consent phishing (illicit consent grant) remains viable when user consent is broad",
                Severity.MEDIUM,
                "If users can consent to Graph scopes, a malicious app can retain access after password reset.",
                phase="oauth",
                likelihood=Likelihood.POSSIBLE,
                why="Less noisy than spray when consent policies are loose; depends on tenant consent configuration (confirm in Entra).",
                attack_path="Phish consent → app tokens → mail/files persistence.",
                remediation="Disable user consent for high-risk scopes; review enterprise apps monthly.",
                category=AssessmentCategory.OAUTH_ENTERPRISE_APPS,
            ),
            self.finding(
                profile,
                "FOCI / multi-resource refresh token family is a known token-broker risk class",
                Severity.MEDIUM,
                "Family of Client IDs patterns can widen blast radius after one successful OAuth phishing.",
                phase="oauth",
                likelihood=Likelihood.POSSIBLE,
                why="Secondary to initial phishing success — increases impact after device-code/consent abuse.",
                remediation="Monitor refresh token anomalies; prefer CAE and continuous access evaluation.",
                category=AssessmentCategory.OAUTH_ENTERPRISE_APPS,
            ),
        ]

    def _phase_azure_edge(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        # CNAME takeover hints for common hostnames
        candidates = [
            f"www.{domain}",
            f"vpn.{domain}",
            f"dev.{domain}",
            f"staging.{domain}",
            f"api.{domain}",
            f"cdn.{domain}",
            f"apps.{domain}",
        ]
        if domain.endswith(".onmicrosoft.com"):
            return [
                self.finding(
                    profile,
                    "Azure takeover DNS checks skipped for onmicrosoft.com",
                    Severity.INFO,
                    "Re-run against the public brand domain to hunt dangling CNAMEs.",
                    phase="azure_edge",
                    likelihood=Likelihood.LESS_LIKELY,
                    why="Takeover hunting needs the organization's public DNS zone.",
                    category=AssessmentCategory.AZURE_EDGE,
                )
            ]

        for host in candidates:
            try:
                answers = dns.resolver.resolve(host, "CNAME")
                cnames = [str(r.target).rstrip(".").lower() for r in answers]
            except Exception:  # noqa: BLE001
                continue
            for cn in cnames:
                for suf in TAKEOVER_SUFFIXES:
                    if cn.endswith(suf):
                        # Check if target looks dangling (NXDOMAIN on CNAME target)
                        dangling = False
                        try:
                            dns.resolver.resolve(cn, "A")
                        except Exception:  # noqa: BLE001
                            dangling = True
                        out.append(
                            self.finding(
                                profile,
                                f"Possible Azure dangling CNAME: {host} → {cn}",
                                Severity.HIGH if dangling else Severity.MEDIUM,
                                f"`{host}` CNAME to `{cn}` ({'NXDOMAIN/no A' if dangling else 'resolves'}).",
                                evidence={"host": host, "cname": cn, "dangling_hint": dangling},
                                phase="azure_edge",
                                likelihood=Likelihood.MOST_LIKELY if dangling else Likelihood.POSSIBLE,
                                why="Dangling Microsoft-platform CNAMEs are a classic subdomain takeover path.",
                                remediation="Remove or claim the Azure resource; clean DNS.",
                                category=AssessmentCategory.AZURE_EDGE,
                            )
                        )
        if not out:
            out.append(
                self.finding(
                    profile,
                    "No obvious Azure dangling CNAMEs in common host set",
                    Severity.PASS,
                    "Checked www/vpn/dev/staging/api/cdn/apps — expand wordlists for deeper coverage.",
                    phase="azure_edge",
                    likelihood=Likelihood.LESS_LIKELY,
                    why="Good for the sampled names; not proof the whole zone is clean.",
                    category=AssessmentCategory.AZURE_EDGE,
                )
            )
        return out

    def _phase_power_dynamics(self, http, domain, profile, fp) -> list[Finding]:
        out: list[Finding] = []
        slug = fp.get("slug") or _slug(domain)
        # Power Pages / common portal host patterns
        portals = [
            f"https://{slug}.powerappsportals.com/",
            f"https://{slug}.microsoftcrmportals.com/",
        ]
        for url in portals:
            try:
                r = http.get(url, timeout=12, allow_redirects=False)
                if r.status_code < 500:
                    out.append(
                        self.finding(
                            profile,
                            f"Power Apps portal host responds ({url})",
                            Severity.MEDIUM,
                            f"HTTP {r.status_code}",
                            evidence={"url": url, "status": r.status_code},
                            phase="power_platform",
                            likelihood=Likelihood.POSSIBLE,
                            why="Portals sometimes expose OData entities anonymously — verify /_odata/ carefully with authorization.",
                            remediation="Review Power Pages permissions; disable anonymous tables.",
                            category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                        )
                    )
                    # Light OData probe
                    odata = url.rstrip("/") + "/_odata/contacts"
                    try:
                        o = http.get(odata, timeout=10)
                        if o.status_code == 200:
                            out.append(
                                self.finding(
                                    profile,
                                    "Power Pages OData /contacts returned 200 anonymously",
                                    Severity.HIGH,
                                    f"`{odata}` accessible without auth.",
                                    evidence={"url": odata, "status": o.status_code},
                                    phase="power_platform",
                                    likelihood=Likelihood.MOST_LIKELY,
                                    why="Direct anonymous business-data API access.",
                                    remediation="Lock down table permissions immediately.",
                                    category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                                )
                            )
                    except requests.RequestException:
                        pass
            except requests.RequestException:
                continue
        return out