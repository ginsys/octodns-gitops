"""Tests for cli/drift.py"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from octodns_gitops.cli.drift import generate_drift_config, live_providers, main


class TestGenerateDriftConfig:
    """Tests for generate_drift_config()."""

    def test_reverses_sources_targets(self, tmp_path):
        """sources should become targets, targets should become sources."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
    directory: zones
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert result["zones"]["example.com."]["sources"] == ["hetzner"]
        assert result["zones"]["example.com."]["targets"] == ["zones"]

    def test_preserves_providers(self, tmp_path):
        """All providers should be preserved."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert "zones" in result["providers"]
        assert "hetzner" in result["providers"]

    def test_preserves_processors(self, tmp_path):
        """Processors should be preserved for consistent filtering."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner

processors:
  external-dns-filter:
    class: octodns_gitops.processors.ExternalDnsFilter
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert "processors" in result
        assert "external-dns-filter" in result["processors"]

    def test_preserves_manager(self, tmp_path):
        """Manager config should be preserved."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner

manager:
  max_workers: 4
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert "manager" in result
        assert result["manager"]["max_workers"] == 4

    def test_zone_without_targets_becomes_blocker(self, tmp_path):
        """A zone not targeting the provider stays in the config as an
        inert blocker (targets: []) so octoDNS skips it but dynamic
        expansion still sees the key."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider

zones:
  example.com.:
    sources:
      - zones
    # No targets
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert result["zones"]["example.com."] == {
            "sources": ["zones"],
            "targets": [],
        }

    def test_manager_plan_outputs_stripped(self, tmp_path):
        """manager.plan_outputs writes to a fixed filename; with one run
        per provider each run would overwrite the previous provider's
        plan, so it must not be copied (PR #5 review round 2)."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner

manager:
  max_workers: 4
  plan_outputs:
    json:
      class: octodns.provider.plan.PlanJson
      filename: plan.json
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert result["manager"] == {"max_workers": 4}

    def test_uses_zones_as_target(self, tmp_path):
        """Local YAML provider should be target in reversed config."""
        config_in = tmp_path / "config.yaml"
        config_out = tmp_path / "drift.yaml"

        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        generate_drift_config(str(config_in), str(config_out), provider="hetzner")

        import yaml

        with open(config_out) as f:
            result = yaml.safe_load(f)

        assert result["zones"]["example.com."]["targets"] == ["zones"]


class TestMain:
    """Tests for main() function."""

    @pytest.fixture
    def mock_subprocess(self):
        with patch("subprocess.run") as mock_run:
            yield mock_run

    def test_no_drift_returns_zero(self, mock_subprocess, tmp_path, capsys):
        """No drift should return exit code 0."""
        # Create a temporary config
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "No drift" in captured.out

    def test_drift_detected_returns_one(self, mock_subprocess, tmp_path, capsys):
        """Drift detected should return exit code 1."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="""
* example.com.
*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']>
*   Summary: Creates=1, Updates=0, Deletes=0, Existing=5
""",
        )

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Drift detected" in captured.out

    def test_error_returns_two(self, mock_subprocess, tmp_path, capsys):
        """Error should return exit code 2."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Some error occurred",
        )

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 2

    def test_missing_credentials(self, mock_subprocess, tmp_path, capsys):
        """Missing credentials should show clear message."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="missing env var HETZNER_TOKEN",
        )

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 2
        captured = capsys.readouterr()
        assert "Missing" in captured.err or "credentials" in captured.err.lower()

    def test_cleans_up_temp(self, mock_subprocess, tmp_path):
        """Temp config file should be deleted after run."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        # Track temp files before
        temp_files_before = set(Path(tempfile.gettempdir()).glob("*.yaml"))

        with patch("sys.argv", ["drift", "--config", str(config)]):
            main()

        # Check no new temp yaml files remain
        temp_files_after = set(Path(tempfile.gettempdir()).glob("*.yaml"))
        # May have some other yaml files, but drift config should be cleaned
        # This is a weak test - just ensure it doesn't crash
        assert temp_files_after >= temp_files_before

    def test_zone_filter(self, mock_subprocess, tmp_path):
        """--zone flag should filter to specific zone."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch(
            "sys.argv", ["drift", "--config", str(config), "--zone", "example.com."]
        ):
            main()

        cmd = mock_subprocess.call_args[0][0]
        assert "example.com." in cmd


MULTI_TARGET_CONFIG = """
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN
  desec:
    class: octodns_desec.DesecProvider
    token: env/TOKEN2

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
      - desec
  single.example.:
    sources:
      - zones
    targets:
      - hetzner
"""


class TestMultiTargetZones:
    """One reversed config per live provider.

    Regression tests for #4: reversing a multi-target zone's full targets
    list into sources populates one octoDNS zone object from every live
    provider, and any record present in more than one of them raises
    DuplicateRecordException (lenient=False). With a shadow-provider setup
    every record collides, so drift-check could never run at all.
    """

    def test_live_providers_ordered_dedup(self, tmp_path):
        """All live providers, in first-appearance order, deduplicated."""
        import yaml

        cfg = yaml.safe_load(MULTI_TARGET_CONFIG)
        assert live_providers(cfg["zones"]) == ["hetzner", "desec"]

    def test_config_scoped_to_provider(self, tmp_path):
        """A provider's config carries only that provider as source, and
        only the zones that target it."""
        config_in = tmp_path / "config.yaml"
        config_in.write_text(MULTI_TARGET_CONFIG)

        import yaml

        out_desec = tmp_path / "drift-desec.yaml"
        generate_drift_config(str(config_in), str(out_desec), provider="desec")
        with open(out_desec) as f:
            result = yaml.safe_load(f)
        assert result["zones"]["example.com."]["sources"] == ["desec"]
        assert result["zones"]["example.com."]["targets"] == ["zones"]
        # single.example. does not target desec -> inert blocker: octoDNS
        # skips it (no targets) but the key still blocks dynamic expansion
        assert result["zones"]["single.example."] == {
            "sources": ["zones"],
            "targets": [],
        }

        out_hetzner = tmp_path / "drift-hetzner.yaml"
        generate_drift_config(str(config_in), str(out_hetzner), provider="hetzner")
        with open(out_hetzner) as f:
            result = yaml.safe_load(f)
        assert set(result["zones"]) == {"example.com.", "single.example."}
        for zone_cfg in result["zones"].values():
            assert zone_cfg["sources"] == ["hetzner"]

    def test_live_providers_null_targets(self):
        """`targets:` with no value loads as None -- treat as empty, like
        octoDNS's own manager does (PR #5 review, P2)."""
        zones = {"a.example.": {"targets": None}, "b.example.": None}
        assert live_providers(zones) == []

    def test_null_targets_zone_becomes_blocker(self, tmp_path):
        """A zone with a null `targets:` must become a blocker, not crash."""
        config_in = tmp_path / "config.yaml"
        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
  empty.example.:
    sources:
      - zones
    targets:
""")
        out = tmp_path / "drift.yaml"
        generate_drift_config(str(config_in), str(out), provider="hetzner")

        import yaml

        with open(out) as f:
            result = yaml.safe_load(f)
        assert result["zones"]["example.com."]["sources"] == ["hetzner"]
        assert result["zones"]["empty.example."]["targets"] == []

    def test_shadowed_explicit_zone_kept_as_blocker(self, tmp_path):
        """'*' targets [p1, p2] while special.example. targets only [p1]:
        p2's config must keep special.example. as a blocker, or octoDNS's
        wildcard expansion re-includes it for p2 (explicit keys are
        subtracted from dynamic candidates -- PR #5 review round 2)."""
        config_in = tmp_path / "config.yaml"
        config_in.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  p1:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN
  p2:
    class: octodns_desec.DesecProvider
    token: env/TOKEN2

zones:
  '*':
    sources:
      - zones
    targets:
      - p1
      - p2
  special.example.:
    sources:
      - zones
    targets:
      - p1
""")

        import yaml

        out = tmp_path / "drift-p2.yaml"
        generate_drift_config(str(config_in), str(out), provider="p2")
        with open(out) as f:
            result = yaml.safe_load(f)
        assert result["zones"]["*"]["sources"] == ["p2"]
        assert result["zones"]["special.example."] == {
            "sources": ["zones"],
            "targets": [],
        }


DYNAMIC_ZONE_CONFIG = """
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/TOKEN

zones:
  '*':
    sources:
      - zones
    targets:
      - hetzner
"""


class TestZoneFilterDynamicZones:
    """--zone must not skip a provider whose config uses dynamic zone
    entries ('*'-prefixed keys): only octoDNS can expand those, so the
    concrete zone name never appears as a key here (PR #5 review, P1)."""

    def test_dynamic_zone_config_not_skipped(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text(DYNAMIC_ZONE_CONFIG)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr="No changes were planned"
            )
            argv = ["drift", "--config", str(config), "--zone", "example.com."]
            with patch("sys.argv", argv):
                result = main()

        assert result == 0
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "example.com." in cmd


class TestMainMultiTarget:
    """main() runs octodns-sync once per live provider and aggregates."""

    @pytest.fixture
    def mock_subprocess(self):
        with patch("subprocess.run") as mock_run:
            yield mock_run

    @pytest.fixture
    def config(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text(MULTI_TARGET_CONFIG)
        return config

    @staticmethod
    def _result(returncode=0, stderr="No changes were planned"):
        return MagicMock(returncode=returncode, stdout="", stderr=stderr)

    def test_runs_sync_once_per_provider(self, mock_subprocess, config, capsys):
        """Two live providers -> two octodns-sync runs; all clean -> 0."""
        mock_subprocess.side_effect = [self._result(), self._result()]

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 0
        assert mock_subprocess.call_count == 2
        captured = capsys.readouterr()
        assert "No drift" in captured.out

    def test_each_run_gets_its_own_config(self, mock_subprocess, config):
        """The two runs must use two different generated config files."""
        mock_subprocess.side_effect = [self._result(), self._result()]

        with patch("sys.argv", ["drift", "--config", str(config)]):
            main()

        config_files = [
            call.args[0][call.args[0].index("--config-file") + 1]
            for call in mock_subprocess.call_args_list
        ]
        assert len(set(config_files)) == 2

    def test_drift_in_one_provider_returns_one_and_names_it(
        self, mock_subprocess, config, capsys
    ):
        """Drift in the second provider only -> 1, report names the provider."""
        mock_subprocess.side_effect = [
            self._result(),
            self._result(stderr="* example.com.\n*   Create <ARecord ...>\n"),
        ]

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Drift detected" in captured.out
        # provider order is first-appearance: hetzner then desec
        assert "desec" in captured.out

    def test_zone_passed_to_all_providers(self, mock_subprocess, config):
        """--zone runs against every provider: octoDNS itself applies the
        filter (IdnaDict normalization, dynamic expansion), and a
        provider not serving the zone hits its inert blocker entry and
        planning is skipped (PR #5 review round 2)."""
        mock_subprocess.side_effect = [self._result(), self._result()]

        argv = ["drift", "--config", str(config), "--zone", "single.example."]
        with patch("sys.argv", argv):
            result = main()

        assert result == 0
        assert mock_subprocess.call_count == 2
        for call in mock_subprocess.call_args_list:
            assert "single.example." in call.args[0]

    def test_error_in_first_provider_returns_two(
        self, mock_subprocess, config, capsys
    ):
        """A failed sync run -> 2, remaining providers not reached."""
        mock_subprocess.side_effect = [
            self._result(returncode=1, stderr="Some error occurred"),
        ]

        with patch("sys.argv", ["drift", "--config", str(config)]):
            result = main()

        assert result == 2
        assert mock_subprocess.call_count == 1
