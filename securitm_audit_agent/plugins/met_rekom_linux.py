from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from securitm_audit_agent.checks.builtin import SshRootLoginCheck
from securitm_audit_agent.core.base import BaseCheck, CheckMeta, Status
from securitm_audit_agent.core.report import AuditResult


@dataclass
class CmdlineParams:
    params: Dict[str, str]
    flags: List[str]


class MetCheck(BaseCheck):
    def _result(self, status: Status, message: str, evidence: Optional[str]) -> AuditResult:
        return AuditResult(
            check_id=self.meta.check_id,
            status=status,
            message=message,
            evidence=evidence,
            severity=self.meta.severity,
            remediation=self.meta.remediation,
        )


def _read_sysctl(ctx, key: str) -> Optional[str]:
    path = "/proc/sys/" + key.replace(".", "/")
    content = ctx.read_file(path)
    if content is None:
        return None
    return content.strip()


def _read_cmdline(ctx) -> Optional[CmdlineParams]:
    content = ctx.read_file("/proc/cmdline")
    if content is None:
        return None
    params: Dict[str, str] = {}
    flags: List[str] = []
    for token in content.strip().split():
        if "=" in token:
            key, value = token.split("=", 1)
            params[key] = value
        else:
            flags.append(token)
    return CmdlineParams(params=params, flags=flags)


def _mode(ctx, path: str) -> Optional[int]:
    stat = ctx.stat(path)
    if stat is None:
        return None
    return stat.st_mode & 0o777


def _parse_group_members(line: str) -> List[str]:
    parts = line.strip().split(":")
    if len(parts) < 4:
        return []
    members = parts[3].strip()
    if not members:
        return []
    return [item for item in members.split(",") if item]


def _read_passwd(ctx) -> List[Tuple[str, str, str]]:
    content = ctx.read_file("/etc/passwd")
    if content is None:
        return []
    users: List[Tuple[str, str, str]] = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        users.append((parts[0], parts[5], parts[6]))
    return users


def _iter_sudoers_lines(ctx) -> Iterable[Tuple[str, str]]:
    paths = ["/etc/sudoers"]
    paths.extend(_glob_paths(ctx, "/etc/sudoers.d"))

    for path in paths:
        content = ctx.read_file(path)
        if content is None:
            continue
        for line in content.splitlines():
            yield path, line


def _glob_paths(ctx, base: str) -> List[str]:
    result: List[str] = []
    listing = ctx.run_cmd(["/bin/sh", "-c", f"ls -1 {base} 2>/dev/null"])  # noqa: S602
    if listing.returncode != 0:
        return result
    for item in listing.stdout.splitlines():
        item = item.strip()
        if item:
            result.append(f"{base}/{item}")
    return result


def _collect_paths(ctx, base_paths: Iterable[str]) -> List[str]:
    result: List[str] = []
    for base in base_paths:
        listing = ctx.run_cmd(["/bin/sh", "-c", f"ls -1 {base} 2>/dev/null"])  # noqa: S602
        if listing.returncode != 0:
            continue
        for item in listing.stdout.splitlines():
            item = item.strip()
            if item:
                result.append(f"{base}/{item}")
    return result


class MetNoEmptyPasswordsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_1_1_no_empty_passwords",
        title="2.1.1 Нет пустых паролей",
        description="Учетные записи не должны иметь пустые пароли",
        severity="high",
        remediation="Настроить пароли или заблокировать учетные записи в /etc/shadow",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        content = ctx.read_file("/etc/shadow")
        if content is None:
            return self._result(Status.SKIP, "/etc/shadow not readable", None)

        bad_users: List[str] = []
        for line in content.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            if parts[1] == "":
                bad_users.append(parts[0])

        if bad_users:
            return self._result(Status.FAIL, "Empty password field", ",".join(bad_users))
        return self._result(Status.OK, "No empty password fields", None)


class MetSshRootLoginCheck(SshRootLoginCheck):
    meta = CheckMeta(
        check_id="met_2_1_2_ssh_root_login",
        title="2.1.2 Запрет root по SSH",
        description="PermitRootLogin должен быть установлен в no",
        severity="high",
        remediation="Set PermitRootLogin to no in /etc/ssh/sshd_config",
    )


class MetSuWheelCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_2_1_su_wheel_restriction",
        title="2.2.1 Ограничение su через pam_wheel",
        description="Добавить pam_wheel.so use_uid и группу wheel",
        severity="high",
        remediation="Добавить auth required pam_wheel.so use_uid в /etc/pam.d/su",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        content = ctx.read_file("/etc/pam.d/su")
        if content is None:
            return self._result(Status.SKIP, "/etc/pam.d/su not readable", None)

        pam_ok = False
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "pam_wheel.so" in stripped and "use_uid" in stripped:
                pam_ok = True
                break

        group_content = ctx.read_file("/etc/group")
        if group_content is None:
            return self._result(Status.SKIP, "/etc/group not readable", None)

        wheel_members: List[str] = []
        for line in group_content.splitlines():
            if line.startswith("wheel:"):
                wheel_members = _parse_group_members(line)
                break

        if not pam_ok:
            return self._result(Status.FAIL, "pam_wheel.so use_uid not configured", None)
        if not wheel_members:
            return self._result(Status.FAIL, "wheel group has no members", None)
        return self._result(Status.OK, "pam_wheel configured", ",".join(wheel_members))


class MetSudoRestrictionsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_2_2_sudo_restrictions",
        title="2.2.2 Ограничение sudo",
        description="Список пользователей и команд в sudoers должен быть ограничен",
        severity="high",
        remediation="Ограничить правила в /etc/sudoers и /etc/sudoers.d",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        offenders: List[str] = []
        for path, line in _iter_sudoers_lines(ctx):
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("Defaults"):
                continue
            if "ALL=(ALL" in stripped and stripped.endswith("ALL"):
                offenders.append(f"{path}: {stripped}")
            if "NOPASSWD:ALL" in stripped:
                offenders.append(f"{path}: {stripped}")

        if offenders:
            evidence = "; ".join(offenders[:5])
            if len(offenders) > 5:
                evidence += " ..."
            return self._result(Status.FAIL, "Overly permissive sudo rules", evidence)
        return self._result(Status.OK, "No overly permissive sudo rules found", None)


class MetPasswdGroupShadowPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_1_passwd_group_shadow_perms",
        title="2.3.1 Права доступа /etc/passwd, /etc/group, /etc/shadow",
        description="Проверка корректных прав доступа на системные файлы учетных записей",
        severity="high",
        remediation="Установить chmod 644 /etc/passwd /etc/group и chmod go-rwx /etc/shadow",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        issues: List[str] = []
        passwd_mode = _mode(ctx, "/etc/passwd")
        group_mode = _mode(ctx, "/etc/group")
        shadow_mode = _mode(ctx, "/etc/shadow")

        if passwd_mode is None or group_mode is None or shadow_mode is None:
            return self._result(Status.SKIP, "Required files not readable", None)

        if passwd_mode & 0o022:
            issues.append(f"/etc/passwd mode {oct(passwd_mode)}")
        if group_mode & 0o022:
            issues.append(f"/etc/group mode {oct(group_mode)}")
        if shadow_mode & 0o077:
            issues.append(f"/etc/shadow mode {oct(shadow_mode)}")

        if issues:
            return self._result(Status.FAIL, "Incorrect permissions", "; ".join(issues))
        return self._result(Status.OK, "Permissions are within required limits", None)


class MetRunningProcessPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_2_running_process_file_perms",
        title="2.3.2 Права доступа к файлам запущенных процессов",
        description="Проверка прав доступа к исполняемым файлам и каталогам запущенных процессов",
        severity="medium",
        remediation="Провести аудит прав доступа к исполняемым файлам и директориям",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        return self._result(Status.SKIP, "Manual audit required for running process files", None)


class MetCronJobsPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_3_cron_jobs_file_perms",
        title="2.3.3 Права доступа к файлам cron пользователей",
        description="Проверка прав доступа к файлам, вызываемым из cron",
        severity="medium",
        remediation="Провести аудит файлов, выполняемых из cron",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        return self._result(Status.SKIP, "Manual audit required for cron job files", None)


class MetSudoExecPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_4_sudo_exec_file_perms",
        title="2.3.4 Права доступа к файлам, запускаемым через sudo",
        description="Проверка владельца и прав доступа к sudo-исполняемым файлам",
        severity="medium",
        remediation="Установить владельца root и chmod go-w для sudo-исполняемых файлов",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        return self._result(Status.SKIP, "Manual audit required for sudo-executed files", None)


class MetRcServicePermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_5_rc_service_perms",
        title="2.3.5 Права доступа к rc.d и .service",
        description="Проверка отсутствия прав записи для других пользователей",
        severity="medium",
        remediation="chmod o-w для файлов /etc/rc#.d и .service",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        base_paths = []
        for idx in range(0, 7):
            base_paths.append(f"/etc/rc{idx}.d")
        service_paths = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]

        files = _collect_paths(ctx, base_paths)
        for base in service_paths:
            files.extend(_collect_paths(ctx, [base]))

        if not files:
            return self._result(Status.SKIP, "No rc.d or .service files found", None)

        bad: List[str] = []
        for path in files:
            if not path.endswith(".service") and "/rc" not in path:
                continue
            mode = _mode(ctx, path)
            if mode is None:
                continue
            if mode & 0o002:
                bad.append(f"{path} ({oct(mode)})")

        if bad:
            evidence = "; ".join(bad[:5])
            if len(bad) > 5:
                evidence += " ..."
            return self._result(Status.FAIL, "Other-writable files detected", evidence)
        return self._result(Status.OK, "No other-writable rc/service files", None)


class MetSystemCronPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_6_system_cron_perms",
        title="2.3.6 Права доступа к системным cron файлам",
        description="Проверка chmod go-wx для системных cron файлов и директорий",
        severity="medium",
        remediation="chmod go-wx для /etc/crontab и /etc/cron.*",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        targets = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ]
        bad: List[str] = []
        found = False
        for path in targets:
            mode = _mode(ctx, path)
            if mode is None:
                continue
            found = True
            if mode & 0o033:
                bad.append(f"{path} ({oct(mode)})")

        if not found:
            return self._result(Status.SKIP, "No system cron files found", None)
        if bad:
            return self._result(Status.FAIL, "Invalid cron permissions", "; ".join(bad))
        return self._result(Status.OK, "System cron permissions OK", None)


class MetUserCronPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_7_user_cron_perms",
        title="2.3.7 Права доступа к пользовательским cron файлам",
        description="Проверка chmod go-w для пользовательских cron файлов",
        severity="medium",
        remediation="chmod go-w для файлов в /var/spool/cron",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        targets = ["/var/spool/cron", "/var/spool/cron/crontabs"]
        files = _collect_paths(ctx, targets)
        if not files:
            return self._result(Status.SKIP, "No user cron files found", None)

        bad: List[str] = []
        for path in files:
            mode = _mode(ctx, path)
            if mode is None:
                continue
            if mode & 0o022:
                bad.append(f"{path} ({oct(mode)})")

        if bad:
            return self._result(Status.FAIL, "User cron files are writable", "; ".join(bad))
        return self._result(Status.OK, "User cron permissions OK", None)


class MetSystemBinsPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_8_system_bins_libs_perms",
        title="2.3.8 Права доступа к системным бинарям и библиотекам",
        description="Проверка прав доступа к /bin, /usr/bin, /lib и модулям ядра",
        severity="medium",
        remediation="Провести аудит прав доступа к системным бинарям и библиотекам",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        return self._result(Status.SKIP, "Manual audit required for system binaries", None)


class MetSuidSgidPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_9_suid_sgid_perms",
        title="2.3.9 Права доступа к SUID/SGID",
        description="Проверка отсутствия записи для группы/прочих на SUID/SGID файлах",
        severity="high",
        remediation="chmod go-w для SUID/SGID файлов",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        cmd = ["/bin/sh", "-c", "find / -xdev -type f -perm /6000 -perm /0022 -print 2>/dev/null"]
        result = ctx.run_cmd(cmd)
        if result.returncode != 0:
            return self._result(Status.SKIP, "find failed for SUID/SGID scan", None)

        bad = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if bad:
            evidence = "; ".join(bad[:5])
            if len(bad) > 5:
                evidence += " ..."
            return self._result(Status.FAIL, "Writable SUID/SGID files found", evidence)
        return self._result(Status.OK, "No writable SUID/SGID files", None)


class MetHomeFilesPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_10_home_files_perms",
        title="2.3.10 Права доступа к файлам в домашнем каталоге",
        description="Проверка go-rwx для файлов истории и профилей оболочки",
        severity="medium",
        remediation="chmod go-rwx для файлов в домашних каталогах",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        targets = [
            ".bash_history",
            ".history",
            ".sh_history",
            ".bash_profile",
            ".bashrc",
            ".profile",
            ".bash_logout",
            ".rhosts",
        ]

        users = _read_passwd(ctx)
        bad: List[str] = []
        for user, home, _shell in users:
            if not home or home == "/":
                continue
            for name in targets:
                path = f"{home}/{name}"
                mode = _mode(ctx, path)
                if mode is None:
                    continue
                if mode & 0o077:
                    bad.append(f"{user}:{path} ({oct(mode)})")

        if bad:
            evidence = "; ".join(bad[:5])
            if len(bad) > 5:
                evidence += " ..."
            return self._result(Status.FAIL, "Home files have wide permissions", evidence)
        return self._result(Status.OK, "Home file permissions OK", None)


class MetHomeDirsPermsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_3_11_home_dirs_perms",
        title="2.3.11 Права доступа к домашним каталогам",
        description="Проверка chmod 700 для домашних директорий",
        severity="medium",
        remediation="chmod 700 для домашних директорий пользователей",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        users = _read_passwd(ctx)
        bad: List[str] = []
        for user, home, _shell in users:
            if not home or home == "/":
                continue
            mode = _mode(ctx, home)
            if mode is None:
                continue
            if mode & 0o077:
                bad.append(f"{user}:{home} ({oct(mode)})")

        if bad:
            evidence = "; ".join(bad[:5])
            if len(bad) > 5:
                evidence += " ..."
            return self._result(Status.FAIL, "Home directories are too permissive", evidence)
        return self._result(Status.OK, "Home directory permissions OK", None)


class MetSysctlCheck(MetCheck):
    def __init__(self, check_id: str, title: str, description: str, key: str, expected: str) -> None:
        self.meta = CheckMeta(
            check_id=check_id,
            title=title,
            description=description,
            severity="medium",
            remediation=f"Set {key} to {expected}",
        )
        self._key = key
        self._expected = expected

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        value = _read_sysctl(ctx, self._key)
        if value is None:
            return self._result(Status.SKIP, f"{self._key} not readable", None)
        if value == self._expected:
            return self._result(Status.OK, f"{self._key}={value}", value)
        return self._result(Status.FAIL, f"{self._key}={value}", value)


class MetSysctlMinCheck(MetCheck):
    def __init__(self, check_id: str, title: str, description: str, key: str, min_value: int) -> None:
        self.meta = CheckMeta(
            check_id=check_id,
            title=title,
            description=description,
            severity="medium",
            remediation=f"Set {key} to {min_value} or higher",
        )
        self._key = key
        self._min = min_value

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        value = _read_sysctl(ctx, self._key)
        if value is None:
            return self._result(Status.SKIP, f"{self._key} not readable", None)
        try:
            current = int(value)
        except ValueError:
            return self._result(Status.FAIL, f"{self._key} not an integer", value)
        if current >= self._min:
            return self._result(Status.OK, f"{self._key}={current}", value)
        return self._result(Status.FAIL, f"{self._key}={current}", value)


class MetCmdlineCheck(MetCheck):
    def __init__(
        self,
        check_id: str,
        title: str,
        description: str,
        key: str,
        expected: Optional[str] = None,
    ) -> None:
        self.meta = CheckMeta(
            check_id=check_id,
            title=title,
            description=description,
            severity="medium",
            remediation=f"Set {key}={expected} in kernel cmdline" if expected else f"Set {key} in kernel cmdline",
        )
        self._key = key
        self._expected = expected

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        cmdline = _read_cmdline(ctx)
        if cmdline is None:
            return self._result(Status.SKIP, "/proc/cmdline not readable", None)

        if self._expected is None:
            if self._key in cmdline.flags:
                return self._result(Status.OK, f"{self._key} enabled", None)
            return self._result(Status.FAIL, f"{self._key} not set", None)

        value = cmdline.params.get(self._key)
        if value == self._expected:
            return self._result(Status.OK, f"{self._key}={value}", value)
        return self._result(Status.FAIL, f"{self._key}={value}", value)


class MetCmdlineMultiCheck(MetCheck):
    def __init__(
        self,
        check_id: str,
        title: str,
        description: str,
        expected: Dict[str, str],
    ) -> None:
        self.meta = CheckMeta(
            check_id=check_id,
            title=title,
            description=description,
            severity="medium",
            remediation="Set required kernel cmdline parameters",
        )
        self._expected = expected

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        cmdline = _read_cmdline(ctx)
        if cmdline is None:
            return self._result(Status.SKIP, "/proc/cmdline not readable", None)

        missing: List[str] = []
        for key, expected in self._expected.items():
            value = cmdline.params.get(key)
            if value != expected:
                missing.append(f"{key}={expected}")

        if missing:
            return self._result(Status.FAIL, "Missing kernel params", ", ".join(missing))
        return self._result(Status.OK, "Kernel params configured", None)


class MetDebugfsCheck(MetCheck):
    meta = CheckMeta(
        check_id="met_2_5_3_debugfs",
        title="2.5.3 Отключение debugfs",
        description="debugfs должен быть отключен через cmdline",
        severity="medium",
        remediation="Set debugfs=off or debugfs=no-mount in kernel cmdline",
    )

    def check(self, ctx, params: Dict[str, object]) -> AuditResult:
        cmdline = _read_cmdline(ctx)
        if cmdline is None:
            return self._result(Status.SKIP, "/proc/cmdline not readable", None)
        value = cmdline.params.get("debugfs")
        if value in {"off", "no-mount", "nomount"}:
            return self._result(Status.OK, f"debugfs={value}", value)
        return self._result(Status.FAIL, f"debugfs={value}", value)


def register(registry) -> None:
    registry.register(MetNoEmptyPasswordsCheck())
    registry.register(MetSshRootLoginCheck())
    registry.register(MetSuWheelCheck())
    registry.register(MetSudoRestrictionsCheck())
    registry.register(MetPasswdGroupShadowPermsCheck())
    registry.register(MetRunningProcessPermsCheck())
    registry.register(MetCronJobsPermsCheck())
    registry.register(MetSudoExecPermsCheck())
    registry.register(MetRcServicePermsCheck())
    registry.register(MetSystemCronPermsCheck())
    registry.register(MetUserCronPermsCheck())
    registry.register(MetSystemBinsPermsCheck())
    registry.register(MetSuidSgidPermsCheck())
    registry.register(MetHomeFilesPermsCheck())
    registry.register(MetHomeDirsPermsCheck())

    registry.register(
        MetSysctlCheck(
            "met_2_4_1_kernel_dmesg_restrict",
            "2.4.1 Ограничение dmesg",
            "kernel.dmesg_restrict=1",
            "kernel.dmesg_restrict",
            "1",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_4_2_kernel_kptr_restrict",
            "2.4.2 Ограничение kptr",
            "kernel.kptr_restrict=2",
            "kernel.kptr_restrict",
            "2",
        )
    )
    registry.register(
        MetCmdlineCheck(
            "met_2_4_3_init_on_alloc",
            "2.4.3 init_on_alloc",
            "init_on_alloc=1",
            "init_on_alloc",
            "1",
        )
    )
    registry.register(
        MetCmdlineCheck(
            "met_2_4_4_slab_nomerge",
            "2.4.4 slab_nomerge",
            "slab_nomerge",
            "slab_nomerge",
            None,
        )
    )
    registry.register(
        MetCmdlineMultiCheck(
            "met_2_4_5_iommu",
            "2.4.5 IOMMU",
            "iommu=force, iommu.strict=1, iommu.passthrough=0",
            {
                "iommu": "force",
                "iommu.strict": "1",
                "iommu.passthrough": "0",
            },
        )
    )
    registry.register(
        MetCmdlineCheck(
            "met_2_4_6_randomize_kstack_offset",
            "2.4.6 randomize_kstack_offset",
            "randomize_kstack_offset=1",
            "randomize_kstack_offset",
            "1",
        )
    )
    registry.register(
        MetCmdlineCheck(
            "met_2_4_7_mitigations",
            "2.4.7 mitigations",
            "mitigations=auto,nosmt",
            "mitigations",
            "auto,nosmt",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_4_8_bpf_jit_harden",
            "2.4.8 bpf_jit_harden",
            "net.core.bpf_jit_harden=2",
            "net.core.bpf_jit_harden",
            "2",
        )
    )

    registry.register(
        MetCmdlineCheck(
            "met_2_5_1_vsyscall",
            "2.5.1 vsyscall",
            "vsyscall=none",
            "vsyscall",
            "none",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_2_perf_event_paranoid",
            "2.5.2 perf_event_paranoid",
            "kernel.perf_event_paranoid=3",
            "kernel.perf_event_paranoid",
            "3",
        )
    )
    registry.register(MetDebugfsCheck())
    registry.register(
        MetSysctlCheck(
            "met_2_5_4_kexec_disabled",
            "2.5.4 kexec_load_disabled",
            "kernel.kexec_load_disabled=1",
            "kernel.kexec_load_disabled",
            "1",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_5_user_namespaces",
            "2.5.5 user namespaces",
            "user.max_user_namespaces=0",
            "user.max_user_namespaces",
            "0",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_6_unpriv_bpf",
            "2.5.6 unprivileged bpf",
            "kernel.unprivileged_bpf_disabled=1",
            "kernel.unprivileged_bpf_disabled",
            "1",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_7_userfaultfd",
            "2.5.7 userfaultfd",
            "vm.unprivileged_userfaultfd=0",
            "vm.unprivileged_userfaultfd",
            "0",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_8_tty_ldisc_autoload",
            "2.5.8 tty ldisc autoload",
            "dev.tty.ldisc_autoload=0",
            "dev.tty.ldisc_autoload",
            "0",
        )
    )
    registry.register(
        MetCmdlineCheck(
            "met_2_5_9_tsx",
            "2.5.9 tsx=off",
            "tsx=off",
            "tsx",
            "off",
        )
    )
    registry.register(
        MetSysctlMinCheck(
            "met_2_5_10_mmap_min_addr",
            "2.5.10 mmap_min_addr",
            "vm.mmap_min_addr >= 4096",
            "vm.mmap_min_addr",
            4096,
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_5_11_randomize_va_space",
            "2.5.11 randomize_va_space",
            "kernel.randomize_va_space=2",
            "kernel.randomize_va_space",
            "2",
        )
    )

    registry.register(
        MetSysctlCheck(
            "met_2_6_1_ptrace_scope",
            "2.6.1 ptrace_scope",
            "kernel.yama.ptrace_scope=3",
            "kernel.yama.ptrace_scope",
            "3",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_6_2_protected_symlinks",
            "2.6.2 protected_symlinks",
            "fs.protected_symlinks=1",
            "fs.protected_symlinks",
            "1",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_6_3_protected_hardlinks",
            "2.6.3 protected_hardlinks",
            "fs.protected_hardlinks=1",
            "fs.protected_hardlinks",
            "1",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_6_4_protected_fifos",
            "2.6.4 protected_fifos",
            "fs.protected_fifos=2",
            "fs.protected_fifos",
            "2",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_6_5_protected_regular",
            "2.6.5 protected_regular",
            "fs.protected_regular=2",
            "fs.protected_regular",
            "2",
        )
    )
    registry.register(
        MetSysctlCheck(
            "met_2_6_6_suid_dumpable",
            "2.6.6 suid_dumpable",
            "fs.suid_dumpable=0",
            "fs.suid_dumpable",
            "0",
        )
    )
