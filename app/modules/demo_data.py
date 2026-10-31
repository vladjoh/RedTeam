"""Realistic demo findings for offline / no-tenant runs."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Finding, Severity


def demo_findings(profile: AttackProfile, categories: list[AssessmentCategory], tenant: str) -> list[Finding]:
    catalog: list[Finding] = []

    if AssessmentCategory.ATTACK_SURFACE in categories:
        catalog.extend(
            [
                Finding(
                    category=AssessmentCategory.ATTACK_SURFACE,
                    profile=AttackProfile.EXTERNAL,
                    title="Tenant discovery via OpenID configuration",
                    severity=Severity.INFO,
                    description=f"OpenID metadata for {tenant} is publicly reachable and confirms cloud instance & issuer.",
                    evidence={"endpoint": f"https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"},
                    barrier="Expected public metadata — not a vulnerability by itself.",
                    attack_path="Enumerate tenant → fingerprint IdP → plan credential stuffing / phishing.",
                    remediation="Monitor anomalous auth traffic; do not expose custom vanity domains unnecessarily.",
                ),
                Finding(
                    category=AssessmentCategory.ATTACK_SURFACE,
                    profile=AttackProfile.EXTERNAL,
                    title="Autodiscover / GetUserRealm user enumeration risk",
                    severity=Severity.MEDIUM,
                    description="GetUserRealm-style endpoints can reveal Managed vs Federated user existence patterns.",
                    evidence={"technique": "GetUserRealm", "demo": True},
                    barrier="Smart Lockout / custom banned password lists reduce spray success.",
                    attack_path="Validate emails → password spray → initial access.",
                    remediation="Enable Smart Lockout, CAPTCHA, and review federation endpoints.",
                ),
            ]
        )

    if AssessmentCategory.IDENTITY_SECURITY in categories:
        catalog.append(
            Finding(
                category=AssessmentCategory.IDENTITY_SECURITY,
                profile=profile,
                title="Legacy authentication protocols may still be permitted",
                severity=Severity.HIGH if profile != AttackProfile.EXTERNAL else Severity.MEDIUM,
                description="Demo signal: legacy auth (IMAP/POP/SMTP AUTH) often bypasses modern MFA prompts.",
                evidence={"demo": True, "protocols": ["IMAP", "POP", "SMTP AUTH"]},
                barrier="Conditional Access block legacy authentication.",
                attack_path="Spray against legacy endpoints → mailbox access without MFA.",
                remediation="Block legacy authentication tenant-wide via Conditional Access.",
            )
        )

    if AssessmentCategory.MFA_CONDITIONAL_ACCESS in categories:
        catalog.append(
            Finding(
                category=AssessmentCategory.MFA_CONDITIONAL_ACCESS,
                profile=profile,
                title="Conditional Access coverage gaps (demo)",
                severity=Severity.HIGH if profile == AttackProfile.USER else Severity.MEDIUM,
                description="Demo: some break-glass accounts or guest users may be excluded from MFA policies.",
                evidence={"demo": True, "excluded_roles": ["break-glass"]},
                barrier="Require MFA for all users + report-only CA insights.",
                attack_path="Compromise excluded identity → skip MFA → Graph/mailbox access.",
                remediation="Minimize CA exclusions; protect break-glass with FIDO2 and monitoring.",
            )
        )

    if AssessmentCategory.OAUTH_ENTERPRISE_APPS in categories:
        catalog.append(
            Finding(
                category=AssessmentCategory.OAUTH_ENTERPRISE_APPS,
                profile=profile if profile != AttackProfile.EXTERNAL else AttackProfile.USER,
                title="High-privilege OAuth consent possible for users",
                severity=Severity.HIGH,
                description="Demo: user consent for Graph Mail.ReadWrite / Files.ReadWrite.All may be allowed.",
                evidence={"demo": True, "risky_scopes": ["Mail.ReadWrite", "Files.ReadWrite.All"]},
                barrier="Admin consent workflow; disable user consent for high-risk scopes.",
                attack_path="Phish OAuth consent → app retains tokens after password reset.",
                remediation="Restrict user consent; review enterprise app permissions monthly.",
            )
        )

    if AssessmentCategory.PRIVILEGE_ESCALATION in categories:
        if profile in {AttackProfile.USER, AttackProfile.ADMIN}:
            catalog.append(
                Finding(
                    category=AssessmentCategory.PRIVILEGE_ESCALATION,
                    profile=profile,
                    title="Group ownership / AppRoleAssignment paths (demo)",
                    severity=Severity.CRITICAL if profile == AttackProfile.ADMIN else Severity.HIGH,
                    description="Demo: owning a group that feeds privileged roles or app assignments can escalate privileges.",
                    evidence={"demo": True},
                    barrier="Privileged Identity Management (PIM); least-privilege ownership.",
                    attack_path="Own security group → assign privileged app role → Graph admin APIs.",
                    remediation="Audit group owners; require PIM for privileged roles.",
                )
            )

    if AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS in categories:
        if profile != AttackProfile.EXTERNAL:
            catalog.append(
                Finding(
                    category=AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS,
                    profile=profile,
                    title="Broad SharePoint / Teams sharing surface (demo)",
                    severity=Severity.MEDIUM,
                    description="Demo: anyone-links and guest access can expose sensitive libraries.",
                    evidence={"demo": True},
                    barrier="Sensitivity labels; disable anonymous links.",
                    attack_path="Enumerate sites → download via shared links → exfiltrate.",
                    remediation="Set sharing to Specific people; label confidential libraries.",
                )
            )

    if AssessmentCategory.LATERAL_MOVEMENT in categories:
        if profile != AttackProfile.EXTERNAL:
            catalog.append(
                Finding(
                    category=AssessmentCategory.LATERAL_MOVEMENT,
                    profile=profile,
                    title="Mailbox / Teams chat as pivot into other users (demo)",
                    severity=Severity.MEDIUM,
                    description="Demo: shared mailboxes and Teams membership reveal peer identities and secrets in chat history.",
                    evidence={"demo": True},
                    barrier="DLP policies; restrict shared mailbox membership.",
                    attack_path="Read shared mailbox → harvest credentials/links → pivot.",
                    remediation="Monitor shared mailbox access; educate against secrets in chat.",
                )
            )

    if AssessmentCategory.PERSISTENCE_RISK in categories:
        if profile == AttackProfile.ADMIN:
            catalog.append(
                Finding(
                    category=AssessmentCategory.PERSISTENCE_RISK,
                    profile=AttackProfile.ADMIN,
                    title="Admin can create malicious enterprise apps & credentials",
                    severity=Severity.CRITICAL,
                    description="A compromised Global Admin can register apps with client secrets for durable Graph access.",
                    evidence={"demo": True},
                    barrier="Privileged Role Admin approvals; App Governance; workload identity governance.",
                    attack_path="Create app → grant Directory.ReadWrite.All → plant secret → retain access after admin password reset.",
                    remediation="Alert on new app credentials; require PIM + approval for app permission grants.",
                )
            )
        elif profile == AttackProfile.USER:
            catalog.append(
                Finding(
                    category=AssessmentCategory.PERSISTENCE_RISK,
                    profile=AttackProfile.USER,
                    title="Inbox rules / OAuth apps as user-level persistence (demo)",
                    severity=Severity.MEDIUM,
                    description="Demo: hidden inbox rules and consented apps survive password changes.",
                    evidence={"demo": True},
                    barrier="Mailbox auditing; revoke user OAuth grants on incident response.",
                    attack_path="Create forwarding rule → silent exfiltration.",
                    remediation="Alert on new forwarding rules; periodic OAuth grant reviews.",
                )
            )

    # Filter: only return findings whose profile matches requested, or external findings for external profile
    filtered = [f for f in catalog if f.profile == profile or (profile == AttackProfile.EXTERNAL and f.profile == AttackProfile.EXTERNAL)]
    # Also include cross-listed findings that were tagged with requested profile
    if not filtered:
        filtered = [f for f in catalog if f.category in categories][:3]
    return filtered