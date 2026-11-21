"""Built-in interpretation rules for common Windows policy values.

Rules only describe what a value means.  They do not decide which evidence or
role it belongs to - that binding is done by the engine, so every conclusion
can point back to an explicit evidence item and an explicit role context.
"""

from typing import Optional

from regipy.policy.models import (
    ALL_SCOPES_REQUIRED,
    ANY_SCOPE,
    MACHINE_SCOPE,
    PER_SCOPE,
    PolicyRule,
)


def _binary_rule(
    rule_id: str,
    value_name: str,
    zero_conclusion: str,
    one_conclusion: str,
    description: str,
    *,
    scope: str = ANY_SCOPE,
    combination: str = PER_SCOPE,
    key_path_contains: Optional[str] = None,
    applies_to_login_contexts: Optional[list[str]] = None,
    applies_to_role_kinds: Optional[list[str]] = None,
    reference: Optional[str] = None,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        value_name=value_name,
        key_path_contains=key_path_contains,
        scope=scope,
        conclusion_by_value={0: zero_conclusion, 1: one_conclusion},
        description=description,
        combination=combination,
        applies_to_login_contexts=applies_to_login_contexts,
        applies_to_role_kinds=applies_to_role_kinds,
        reference=reference,
    )


def default_rules() -> list[PolicyRule]:
    """Return the built-in rule set.

    These are intentionally conservative: each rule is tied to a well-known
    policy value name and the conclusion is qualified by the engine with the
    evidence scope and the delegated role.  They replace the need for callers
    to remember every registry path, while custom rules can still be supplied.
    """

    return [
        _binary_rule(
            "task_manager",
            "DisableTaskMgr",
            "Task Manager is allowed",
            "Task Manager is disabled",
            "User/machine policy for Task Manager availability",
            key_path_contains="policies",
        ),
        _binary_rule(
            "registry_tools",
            "DisableRegistryTools",
            "Registry Editor is allowed",
            "Registry Editor is disabled",
            "User/machine policy for Registry Editor availability",
            key_path_contains="policies",
        ),
        _binary_rule(
            "command_prompt",
            "DisableCMD",
            "Command Prompt is allowed",
            "Command Prompt is disabled",
            "User/machine policy for Command Prompt availability",
            key_path_contains="policies",
        ),
        _binary_rule(
            "run_dialog",
            "NoRun",
            "The Run dialog is available",
            "The Run dialog is removed",
            "User policy for the Start menu Run dialog",
            key_path_contains="policies",
        ),
        _binary_rule(
            "control_panel",
            "NoControlPanel",
            "Control Panel is available",
            "Control Panel is disabled",
            "User policy for Control Panel availability",
            key_path_contains="policies",
        ),
        _binary_rule(
            "uac_enabled",
            "EnableLUA",
            "User Account Control is disabled",
            "User Account Control is enabled",
            "Machine policy for User Account Control",
            scope=MACHINE_SCOPE,
            key_path_contains=r"policies\system",
        ),
        PolicyRule(
            rule_id="uac_admin_prompt",
            value_name="ConsentPromptBehaviorAdmin",
            scope=MACHINE_SCOPE,
            key_path_contains=r"policies\system",
            conclusion_by_value={
                0: "Administrators are elevated without prompting",
                1: "Administrators are prompted for credentials on the secure desktop",
                2: "Administrators are prompted for consent on the secure desktop",
                3: "Administrators are prompted for credentials",
                4: "Administrators are prompted for consent",
                5: "Administrators are prompted for consent for non-Windows binaries",
            },
            description="Machine policy for the UAC administrator prompt behavior",
        ),
        PolicyRule(
            rule_id="telemetry",
            value_name="AllowTelemetry",
            scope=MACHINE_SCOPE,
            key_path_contains="policies",
            conclusion_by_value={
                0: "Telemetry is disabled (Security/off level)",
                1: "Telemetry is set to Basic",
                2: "Telemetry is set to Enhanced",
                3: "Telemetry is set to Full",
            },
            description="Machine policy for Windows diagnostic telemetry",
        ),
        _binary_rule(
            "defender_antispyware",
            "DisableAntiSpyware",
            "Windows Defender antispyware is enabled",
            "Windows Defender antispyware is disabled",
            "Machine policy for Windows Defender antispyware",
            scope=MACHINE_SCOPE,
        ),
        _binary_rule(
            "defender_antivirus",
            "DisableAntiVirus",
            "Windows Defender antivirus is enabled",
            "Windows Defender antivirus is disabled",
            "Machine policy for Windows Defender antivirus",
            scope=MACHINE_SCOPE,
        ),
        _binary_rule(
            "script_block_logging",
            "EnableScriptBlockLogging",
            "PowerShell script block logging is disabled",
            "PowerShell script block logging is enabled",
            "Machine policy for PowerShell script block logging",
            scope=MACHINE_SCOPE,
        ),
        _binary_rule(
            "hide_last_user",
            "DontDisplayLastUserName",
            "The last logged-on user name is shown at interactive logon",
            "The last logged-on user name is hidden at interactive logon",
            "Machine policy evaluated only for interactive logon contexts",
            scope=MACHINE_SCOPE,
            applies_to_login_contexts=["interactive", "remote_interactive"],
        ),
        _binary_rule(
            "shutdown_without_logon",
            "ShutdownWithoutLogon",
            "The shutdown button is hidden at the logon screen",
            "The shutdown button is available at the logon screen",
            "Machine policy evaluated only for interactive logon contexts",
            scope=MACHINE_SCOPE,
            applies_to_login_contexts=["interactive", "remote_interactive"],
        ),
        PolicyRule(
            rule_id="always_install_elevated",
            value_name="AlwaysInstallElevated",
            scope=ANY_SCOPE,
            conclusion_by_value={
                0: "The policy value is set to 0 in this scope",
                1: "The policy value is set to 1 in this scope",
            },
            combination=ALL_SCOPES_REQUIRED,
            required_scopes=[MACHINE_SCOPE, "user"],
            in_effect_values=[1],
            conclusion_when_combined=(
                "AlwaysInstallElevated is in effect: MSI packages may run with elevated privileges "
                "because both machine and user policy values are 1"
            ),
            conclusion_when_not_combined=(
                "AlwaysInstallElevated is not in effect: the policy requires the value 1 in both machine and user scope"
            ),
            description="Combined machine+user policy for elevated MSI installation",
            reference="https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated",
        ),
        PolicyRule(
            rule_id="powershell_execution_policy",
            value_name="ExecutionPolicy",
            scope=MACHINE_SCOPE,
            conclusion_by_value={
                "Restricted": "PowerShell execution policy is Restricted",
                "AllSigned": "PowerShell execution policy is AllSigned",
                "RemoteSigned": "PowerShell execution policy is RemoteSigned",
                "Unrestricted": "PowerShell execution policy is Unrestricted",
                "Bypass": "PowerShell execution policy is Bypass",
                "Undefined": "PowerShell execution policy is Undefined",
            },
            default_conclusion="PowerShell execution policy is set to a custom value",
            description="Machine policy for PowerShell execution policy",
        ),
        PolicyRule(
            rule_id="auto_enrollment_policy",
            value_name="AEPolicy",
            scope=MACHINE_SCOPE,
            key_path_contains="policies",
            default_conclusion="Certificate auto-enrollment policy flags are configured",
            description="Machine policy for certificate auto-enrollment flags",
        ),
    ]


# Backwards-friendly constant for callers that only want to inspect the rules.
DEFAULT_RULES = default_rules()
