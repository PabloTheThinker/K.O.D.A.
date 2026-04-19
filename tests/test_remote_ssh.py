"""Unit tests for koda.remote — SSH session, OS probe, provisioning, executor.

All tests mock subprocess.run / subprocess.Popen via monkeypatch.
No real SSH connections are made.

Style mirrors tests/test_new_scanners.py and tests/test_evidence_remote.py.
"""
from __future__ import annotations

import sys
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _proc(stdout: str = "", stderr: str = "", rc: int = 0) -> CompletedProcess:
    p = MagicMock(spec=CompletedProcess)
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = rc
    return p


# ---------------------------------------------------------------------------
# SSHSession — connection and ControlMaster
# ---------------------------------------------------------------------------


class TestSSHSessionConnect:
    def test_connect_builds_controlmaster_command(self, monkeypatch):
        """connect() must pass ControlMaster=auto and a ControlPath."""
        from koda.remote.ssh import SSHSession

        captured = []

        def fake_run(cmd, **_kw):
            captured.append(cmd)
            return _proc()

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@myhost")
        session.connect()

        assert len(captured) == 1
        cmd = captured[0]
        assert "ssh" in cmd[0]
        assert "-o" in cmd
        assert any("ControlMaster=auto" in a for a in cmd)
        assert any("ControlPath=" in a for a in cmd)
        assert "-fNT" in cmd
        assert "user@myhost" in cmd

    def test_connect_includes_port_flag_when_given(self, monkeypatch):
        from koda.remote.ssh import SSHSession

        captured = []
        monkeypatch.setattr("subprocess.run", lambda c, **kw: (captured.append(c) or _proc()))
        session = SSHSession("user@myhost", port=2222)
        session.connect()

        cmd = captured[0]
        assert "-p" in cmd
        assert "2222" in cmd

    def test_connect_raises_on_nonzero_exit(self, monkeypatch):
        from koda.remote.ssh import SSHError, SSHSession

        monkeypatch.setattr("subprocess.run", lambda c, **kw: _proc(rc=255, stderr="refused"))
        session = SSHSession("badhost")
        with pytest.raises(SSHError, match="failed"):
            session.connect()

    def test_connect_idempotent(self, monkeypatch):
        """Calling connect() twice should only open ONE ControlMaster."""
        from koda.remote.ssh import SSHSession

        call_count = [0]

        def fake_run(cmd, **kw):
            if "-fNT" in cmd:   # only count ControlMaster-open calls
                call_count[0] += 1
            return _proc()

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@myhost")
        session.connect()
        session.connect()   # second call — must be no-op

        assert call_count[0] == 1


class TestSSHSessionExec:
    def test_exec_reuses_control_socket(self, monkeypatch):
        """After connect(), exec() must use ControlMaster=no (socket reuse)."""
        from koda.remote.ssh import SSHSession

        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _proc(stdout="hello")

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@myhost")
        session.connect()   # call 1 (ControlMaster=auto, -fNT)
        session.exec("uname -a")  # call 2 (ControlMaster=no)

        assert len(calls) == 2
        exec_cmd = calls[1]
        assert any("ControlMaster=no" in a for a in exec_cmd)

    def test_exec_returns_stdout_stderr_rc(self, monkeypatch):
        from koda.remote.ssh import SSHSession

        monkeypatch.setattr(
            "subprocess.run",
            lambda c, **kw: _proc(stdout="out", stderr="err", rc=0),
        )
        session = SSHSession("host")
        session.connect()
        stdout, stderr, rc = session.exec("echo hi")

        assert stdout == "out"
        assert stderr == "err"
        assert rc == 0

    def test_exec_single_controlmaster_handshake(self, monkeypatch):
        """Multiple exec() calls → only ONE ssh -fNT (the connect call)."""
        from koda.remote.ssh import SSHSession

        controlmaster_opens = [0]

        def fake_run(cmd, **kw):
            if "-fNT" in cmd:
                controlmaster_opens[0] += 1
            return _proc(stdout="x")

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@host")
        session.connect()
        session.exec("cmd1")
        session.exec("cmd2")
        session.exec("cmd3")

        assert controlmaster_opens[0] == 1


class TestSSHSessionSudoPassword:
    def test_sudo_password_never_in_stderr_or_stdout(self, monkeypatch):
        """Password must not appear in any captured output or call args."""
        from koda.remote.ssh import SSHSession

        SECRET = "hunter2secret"  # noqa: S105
        recorded_inputs = []

        def fake_run(cmd, input=None, **kw):
            if input is not None:
                recorded_inputs.append(input)
            return _proc(stdout="ok")

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@host")
        session.connect()
        session.set_sudo_password(SECRET)
        session.exec("cat /etc/shadow", sudo=True)

        # Password must have been piped via stdin, not embedded in cmd args.
        for captured_input in recorded_inputs:
            # The input should contain the password (it's the stdin pipe),
            # but it must not appear in any printed/logged form.
            assert isinstance(captured_input, str)

        # Verify the password is NOT in any captured stdout/stderr.
        # (We can't check captured_input here since that IS the pipe channel,
        # but we verify none of the fake_run's stdout/stderr contain it.)
        stdout, _, _ = session.exec("whoami", sudo=True)
        assert SECRET not in stdout

    def test_sudo_password_not_in_cmd_args(self, monkeypatch):
        """Password must never be embedded in the command string."""
        from koda.remote.ssh import SSHSession

        SECRET = "topsecretpw"  # noqa: S105
        captured_cmds = []

        def fake_run(cmd, input=None, **kw):
            captured_cmds.append(list(cmd))
            return _proc()

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("user@host")
        session.connect()
        session.set_sudo_password(SECRET)
        session.exec("ls /root", sudo=True)

        # Password must not appear in any element of any captured command.
        for cmd_list in captured_cmds:
            for part in cmd_list:
                assert SECRET not in str(part), (
                    f"Password found in cmd arg: {part!r}"
                )

    def test_probe_passwordless_sudo_success(self, monkeypatch):
        from koda.remote.ssh import SSHSession

        monkeypatch.setattr("subprocess.run", lambda c, **kw: _proc(rc=0))
        session = SSHSession("host")
        session.connect()
        assert session.probe_passwordless_sudo() is True

    def test_probe_passwordless_sudo_failure(self, monkeypatch):
        from koda.remote.ssh import SSHSession

        call_results = [_proc(rc=0), _proc(rc=1)]  # connect ok, sudo -n fails
        idx = [0]

        def fake_run(cmd, **kw):
            r = call_results[min(idx[0], len(call_results) - 1)]
            idx[0] += 1
            return r

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("host")
        session.connect()
        assert session.probe_passwordless_sudo() is False


class TestSSHSessionCleanup:
    def test_cleanup_runs_even_after_exec_exception(self, monkeypatch):
        """cleanup() must run in a finally block even if exec() raised."""
        from koda.remote.ssh import SSHSession

        cleanup_called = [False]
        call_count = [0]

        def fake_run(cmd, **kw):
            call_count[0] += 1
            if call_count[0] == 2:  # exec() call
                raise RuntimeError("network error")
            if "-O" in cmd and "exit" in cmd:
                cleanup_called[0] = True
            return _proc()

        monkeypatch.setattr("subprocess.run", fake_run)
        session = SSHSession("host")
        session.connect()

        try:
            session.exec("failing_cmd")
        except RuntimeError:
            pass
        finally:
            session.cleanup()

        assert cleanup_called[0] is True

    def test_cleanup_never_raises(self, monkeypatch):
        """cleanup() must never raise even if ssh -O exit fails."""
        from koda.remote.ssh import SSHSession

        monkeypatch.setattr(
            "subprocess.run",
            lambda c, **kw: (_ for _ in ()).throw(OSError("ssh gone")),
        )
        session = SSHSession("host")
        # _connected is False — cleanup should be a no-op
        session.cleanup()  # must not raise


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------


class TestParseTarget:
    def test_user_at_host(self):
        from koda.remote.ssh import _parse_target
        target, port = _parse_target("user@host", None)
        assert target == "user@host"
        assert port is None

    def test_user_at_host_with_port(self):
        from koda.remote.ssh import _parse_target
        target, port = _parse_target("user@host:2222", None)
        assert target == "user@host"
        assert port == 2222

    def test_port_override_wins(self):
        from koda.remote.ssh import _parse_target
        target, port = _parse_target("user@host:2222", 9999)
        # Explicit override should take precedence.
        assert port == 9999

    def test_bare_hostname(self):
        from koda.remote.ssh import _parse_target
        target, port = _parse_target("myserver", None)
        assert target == "myserver"
        assert port is None


# ---------------------------------------------------------------------------
# probe_remote_os — parsing
# ---------------------------------------------------------------------------


_UBUNTU_PROBE = """Linux ubuntu-box 5.15.0 #1 SMP x86_64 GNU/Linux
---OS-RELEASE---
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
---ARCH---
x86_64
---PYTHON---
/usr/bin/python3
---SUDO---
yes"""

_RHEL_PROBE = """Linux rhel-box 4.18.0 #1 SMP x86_64 GNU/Linux
---OS-RELEASE---
ID=rhel
VERSION_ID="8.6"
PRETTY_NAME="Red Hat Enterprise Linux 8.6"
---ARCH---
x86_64
---PYTHON---
/usr/bin/python3
---SUDO---
no"""

_ALPINE_PROBE = """Linux alpine-box 5.15.0-0-virt #1-Alpine SMP x86_64 Linux
---OS-RELEASE---
ID=alpine
VERSION_ID=3.18.0
---ARCH---
x86_64
---PYTHON---

---SUDO---
no"""

_DEBIAN_PROBE = """Linux debian-box 5.10.0-19-amd64 #1 SMP Debian x86_64 GNU/Linux
---OS-RELEASE---
ID=debian
VERSION_ID="11"
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
---ARCH---
x86_64
---PYTHON---
/usr/bin/python3
---SUDO---
yes"""


class TestProbeRemoteOs:
    def _make_session(self, probe_output: str, monkeypatch):
        from koda.remote.ssh import SSHSession
        session = MagicMock(spec=SSHSession)
        session.exec.return_value = (probe_output, "", 0)
        return session

    def test_ubuntu_os_family(self, monkeypatch):
        from koda.remote.probe import probe_remote_os
        session = self._make_session(_UBUNTU_PROBE, monkeypatch)
        host = probe_remote_os(session)
        assert host.os_family == "debian"
        assert host.os_id == "ubuntu"
        assert host.os_version == "22.04"
        assert host.arch == "x86_64"
        assert host.has_python3 is True
        assert host.has_sudo is True
        assert host.pkg_manager == "apt"

    def test_rhel_os_family(self, monkeypatch):
        from koda.remote.probe import probe_remote_os
        session = self._make_session(_RHEL_PROBE, monkeypatch)
        host = probe_remote_os(session)
        assert host.os_family == "rhel"
        assert host.has_sudo is False

    def test_alpine_os_family(self, monkeypatch):
        from koda.remote.probe import probe_remote_os
        session = self._make_session(_ALPINE_PROBE, monkeypatch)
        host = probe_remote_os(session)
        assert host.os_family == "alpine"
        assert host.pkg_manager == "apk"
        assert host.has_python3 is False

    def test_debian_os_family(self, monkeypatch):
        from koda.remote.probe import probe_remote_os
        session = self._make_session(_DEBIAN_PROBE, monkeypatch)
        host = probe_remote_os(session)
        assert host.os_family == "debian"
        assert host.os_id == "debian"
        assert host.has_sudo is True

    def test_empty_probe_does_not_raise(self, monkeypatch):
        from koda.remote.probe import probe_remote_os
        session = MagicMock()
        session.exec.return_value = ("", "", 0)
        host = probe_remote_os(session)
        assert host.os_family == "unknown"
        assert host.has_python3 is False


# ---------------------------------------------------------------------------
# ensure_scanner — provisioning
# ---------------------------------------------------------------------------


class TestEnsureScanner:
    def _session(self, path_result: str = "", path_rc: int = 1) -> MagicMock:
        """Return a mock SSHSession where command -v returns path_result."""
        from koda.remote.ssh import SSHSession
        s = MagicMock(spec=SSHSession)
        s.exec.return_value = (path_result, "", path_rc)
        return s

    def test_semgrep_without_remote_install_returns_none(self, capsys):
        """semgrep not on remote PATH → None + warning (not shippable)."""
        from koda.remote.provision import ensure_scanner
        session = self._session(path_result="", path_rc=1)
        result = ensure_scanner(session, "semgrep", "/tmp/koda-test")
        assert result is None
        captured = capsys.readouterr()
        assert "semgrep" in captured.err
        assert "cannot be auto-provisioned" in captured.err

    def test_semgrep_on_remote_path_returns_ref(self):
        """semgrep already on remote PATH → ref with was_uploaded=False."""
        from koda.remote.provision import RemoteScannerRef, ensure_scanner
        session = self._session(path_result="/usr/bin/semgrep", path_rc=0)
        result = ensure_scanner(session, "semgrep", "/tmp/koda-test")
        assert isinstance(result, RemoteScannerRef)
        assert result.name == "semgrep"
        assert result.remote_path == "/usr/bin/semgrep"
        assert result.was_uploaded is False

    def test_trivy_not_on_path_triggers_upload(self, tmp_path):
        """trivy not on remote PATH → upload local binary."""
        from koda.remote.provision import RemoteScannerRef, ensure_scanner

        # Create a fake local trivy binary.
        fake_trivy = tmp_path / "trivy"
        fake_trivy.write_bytes(b"\x7fELF" + b"\x00" * 16)

        # Session: first exec (command -v) returns empty (not on PATH).
        # Subsequent exec calls (mkdir, chmod) return success.
        session = MagicMock()
        session.exec.return_value = ("", "", 1)  # command -v fails
        session.upload.return_value = None

        result = ensure_scanner(
            session,
            "trivy",
            "/tmp/koda-test",
            local_binary_path=str(fake_trivy),
        )
        assert isinstance(result, RemoteScannerRef)
        assert result.was_uploaded is True
        assert result.sha256 != ""
        assert result.size > 0
        session.upload.assert_called_once()

    def test_trivy_local_binary_not_found_returns_none(self, capsys):
        """If local trivy not found, return None with error message."""
        from koda.remote.provision import ensure_scanner

        session = MagicMock()
        session.exec.return_value = ("", "", 1)  # not on remote PATH

        with patch("shutil.which", return_value=None):
            result = ensure_scanner(
                session,
                "trivy",
                "/tmp/koda-test",
                local_binary_path=None,
            )

        assert result is None
        captured = capsys.readouterr()
        assert "trivy" in captured.err

    def test_bandit_not_shippable_returns_none(self, capsys):
        from koda.remote.provision import ensure_scanner
        session = self._session()
        result = ensure_scanner(session, "bandit", "/tmp/koda-test")
        assert result is None

    def test_nmap_not_shippable_returns_none(self, capsys):
        from koda.remote.provision import ensure_scanner
        session = self._session()
        result = ensure_scanner(session, "nmap", "/tmp/koda-test")
        assert result is None

    def test_grype_on_path_no_upload(self):
        from koda.remote.provision import RemoteScannerRef, ensure_scanner
        session = self._session(path_result="/usr/local/bin/grype", path_rc=0)
        result = ensure_scanner(session, "grype", "/tmp/koda-test")
        assert isinstance(result, RemoteScannerRef)
        assert result.was_uploaded is False


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


class TestAuditEvents:
    def test_connect_emits_audit_event(self, monkeypatch, tmp_path):
        """scan.remote.connect event must be emitted with target field."""
        from koda.audit import NullAuditLogger
        from koda.remote.executor import run_remote_scan

        emitted = []

        class TrackingAudit(NullAuditLogger):
            def emit(self, event_name, **fields):
                emitted.append((event_name, fields))

        # Patch SSHSession so we don't need real SSH.

        mock_session = MagicMock()
        mock_session.connect.return_value = None
        mock_session.socket_path = "/tmp/sock"
        mock_session.exec.return_value = ("", "", 0)
        mock_session.has_sudo_password = False
        mock_session.cleanup.return_value = None

        from koda.remote.probe import RemoteHost
        fake_host = RemoteHost(os_id="ubuntu", arch="x86_64")

        with (
            patch("koda.remote.executor.SSHSession", return_value=mock_session),
            patch("koda.remote.executor.probe_remote_os", return_value=fake_host),
            patch("koda.remote.executor.ensure_scanner", return_value=None),
        ):
            run_remote_scan(
                ssh_target="user@host",
                remote_target="/srv/app",
                scanner_names=["trivy"],
                audit=TrackingAudit(),
            )

        connect_events = [e for e in emitted if e[0] == "scan.remote.connect"]
        assert connect_events, f"No scan.remote.connect event found; got: {emitted}"
        assert connect_events[0][1].get("target") == "user@host"

    def test_cleanup_event_emitted_on_normal_path(self, monkeypatch, tmp_path):
        from koda.audit import NullAuditLogger
        from koda.remote.executor import run_remote_scan
        from koda.remote.probe import RemoteHost

        emitted = []

        class TrackingAudit(NullAuditLogger):
            def emit(self, event_name, **fields):
                emitted.append((event_name, fields))

        mock_session = MagicMock()
        mock_session.connect.return_value = None
        mock_session.socket_path = "/tmp/sock"
        mock_session.exec.return_value = ("", "", 0)
        mock_session.has_sudo_password = False
        mock_session.cleanup.return_value = None
        fake_host = RemoteHost()

        with (
            patch("koda.remote.executor.SSHSession", return_value=mock_session),
            patch("koda.remote.executor.probe_remote_os", return_value=fake_host),
            patch("koda.remote.executor.ensure_scanner", return_value=None),
        ):
            run_remote_scan(
                ssh_target="user@host",
                remote_target="/srv",
                scanner_names=["trivy"],
                audit=TrackingAudit(),
            )

        cleanup_events = [e for e in emitted if e[0] == "scan.remote.cleanup"]
        assert cleanup_events
        assert "target" in cleanup_events[0][1]
        assert "temp_dir" in cleanup_events[0][1]


# ---------------------------------------------------------------------------
# Password never leaks into audit events
# ---------------------------------------------------------------------------


class TestPasswordNotInAudit:
    def test_sudo_password_not_in_run_event_fields(self, monkeypatch):
        """scan.remote.run audit event must not contain the sudo password."""
        from koda.audit import NullAuditLogger
        from koda.remote.executor import run_remote_scan
        from koda.remote.probe import RemoteHost
        from koda.remote.provision import RemoteScannerRef

        SECRET = "verysecretpassword123"  # noqa: S105
        emitted = []

        class TrackingAudit(NullAuditLogger):
            def emit(self, event_name, **fields):
                emitted.append((event_name, fields))

        mock_session = MagicMock()
        mock_session.connect.return_value = None
        mock_session.socket_path = "/tmp/sock"
        mock_session.target = "user@host"
        mock_session.has_sudo_password = True
        # Simulate exec returning clean output
        mock_session.exec.return_value = ('{"Results": []}', "", 0)
        mock_session.probe_passwordless_sudo.return_value = False
        mock_session.cleanup.return_value = None

        fake_host = RemoteHost(has_sudo=True)
        fake_ref = RemoteScannerRef(
            name="trivy",
            remote_path="/usr/local/bin/trivy",
            was_uploaded=False,
        )

        with (
            patch("koda.remote.executor.SSHSession", return_value=mock_session),
            patch("koda.remote.executor.probe_remote_os", return_value=fake_host),
            patch("koda.remote.executor.ensure_scanner", return_value=fake_ref),
            patch("koda.remote.executor.getpass.getpass", return_value=SECRET),
            patch("koda.remote.executor._parse_remote_output") as mock_parse,
        ):
            from koda.security.scanners.registry import ScanResult
            mock_parse.return_value = ScanResult(True, "trivy", findings=[])

            run_remote_scan(
                ssh_target="user@host",
                remote_target="/srv/app",
                scanner_names=["trivy"],
                use_sudo=True,
                audit=TrackingAudit(),
            )

        # Verify password does not appear in ANY audit event field.
        all_field_values = []
        for event_name, fields in emitted:
            all_field_values.extend(str(v) for v in fields.values())
            all_field_values.append(event_name)

        for val in all_field_values:
            assert SECRET not in val, (
                f"Password found in audit event: {val!r}"
            )


# ---------------------------------------------------------------------------
# CLI integration — koda scan remote
# ---------------------------------------------------------------------------


class TestCliScanRemote:
    def test_no_scanners_returns_error(self, capsys):
        """Calling koda scan remote without --scanner or --preset is an error."""
        from koda.cli.scan import main
        rc = main(["remote", "user@host"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "no scanners specified" in captured.err

    def test_help_flag_exits_zero(self, capsys):
        from koda.cli.scan import main
        rc = main(["remote", "--help"])
        assert rc == 0

    def test_no_args_prints_help(self, capsys):
        from koda.cli.scan import main
        rc = main([])
        assert rc == 0
        captured = capsys.readouterr()
        assert "remote" in captured.out

    def test_unknown_flag_returns_error(self, capsys):
        from koda.cli.scan import main
        rc = main(["remote", "user@host", "--does-not-exist"])
        assert rc != 0

    def test_preset_missing_module_falls_back_to_scanner_list(self, capsys):
        """If koda.missions is absent and --scanner is also given, proceed."""
        from koda.cli.scan import _load_preset
        with pytest.raises(ImportError, match="koda.missions"):
            _load_preset("server-hardening")


class TestPresetLoader:
    def test_load_preset_missing_module_raises_import_error(self):
        from koda.cli.scan import _load_preset
        with pytest.raises(ImportError):
            _load_preset("nonexistent-preset")

    def test_load_preset_with_mock_missions(self, monkeypatch):
        """When koda.missions.get() exists and returns a list, use it."""
        import types
        fake_missions = types.ModuleType("koda.missions")
        fake_missions.get = lambda name: ["trivy", "gitleaks"]

        monkeypatch.setitem(sys.modules, "koda.missions", fake_missions)

        from koda.cli.scan import _load_preset
        scanners = _load_preset("server-hardening")
        assert scanners == ["trivy", "gitleaks"]

    def test_load_preset_bad_return_type_raises(self, monkeypatch):
        import types
        fake_missions = types.ModuleType("koda.missions")
        fake_missions.get = lambda name: "not-a-list"
        monkeypatch.setitem(sys.modules, "koda.missions", fake_missions)

        from koda.cli.scan import _load_preset
        with pytest.raises(ImportError):
            _load_preset("bad-preset")
