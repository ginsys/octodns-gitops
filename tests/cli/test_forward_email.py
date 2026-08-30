"""Tests for cli/forward_email.py — plan/apply/export/drift against a fake API client."""

import copy
import io
import textwrap
from pathlib import Path

import pytest
from octodns_gitops.cli.forward_email import (
    AmbiguousZoneDirectory,
    ZoneLookup,
    main,
    run,
    zone_lookup,
)
from octodns_gitops.forward_email.config import (
    DEFAULT_ALIAS,
    DEFAULT_EXPECT,
    DEFAULT_SETTINGS,
    ForwardEmailConfig,
)

GIB = 1024**3
DKIM = "v=DKIM1; k=rsa; p=MIIBIjANBg;"


def _live_domain(name, **over):
    d = {k: v for k, v in DEFAULT_SETTINGS.items() if k != "max_quota_per_alias"}
    d.update(DEFAULT_EXPECT)
    d.update(
        {
            "name": name,
            "id": f"dom-{name}",
            "has_strict_dmarc": False,
            "verification_record": "TOKEN",
            "smtp_dns_records": {
                "dkim": {"name": "fe-1._domainkey", "value": DKIM},
                "return_path": {"name": "fe-bounces", "value": "forwardemail.net"},
                "dmarc": {"name": "_dmarc", "value": "v=DMARC1; p=reject; rua=mailto:dmarc-1@forwardemail.net;"},
            },
        }
    )
    d.update(over)
    return d


def _live_alias(name, **over):
    a = {
        "id": f"id-{name}",
        "name": name,
        "recipients": ["serge@ginsys.eu"],
        "is_enabled": True,
        "error_code_if_disabled": 250,
        "has_imap": False,
        "has_pgp": False,
        "has_recipient_verification": False,
        "labels": [],
        "storage_used": 0,
        "vacation_responder": {"is_enabled": False},
    }
    a.update(over)
    return a


class FakeClient:
    def __init__(self, domains, aliases):
        self.domains = {d["name"]: d for d in domains}
        self.aliases = {k: list(v) for k, v in aliases.items()}
        self.calls = []
        # Set to simulate a concurrent change between the first and second listing.
        self.mutate_on_relist = None

    def list_domains(self):
        return list(self.domains.values())

    def get_domain(self, name):
        return copy.deepcopy(self.domains[name])

    def list_aliases(self, domain):
        self.calls.append(("list_aliases", domain))
        if self.mutate_on_relist and self.calls.count(("list_aliases", domain)) == 2:
            self.mutate_on_relist(self)
        return copy.deepcopy(self.aliases.get(domain, []))

    def update_domain(self, name, body):
        self.calls.append(("update_domain", name, body))
        return {}

    def create_alias(self, domain, body):
        self.calls.append(("create_alias", domain, body))
        # A real create changes the id set the prune guard re-lists.
        self.aliases.setdefault(domain, []).append(_live_alias(**body))
        return {}

    def update_alias(self, domain, alias_id, body):
        self.calls.append(("update_alias", domain, alias_id, body))
        return {}

    def delete_alias(self, domain, alias_id):
        self.calls.append(("delete_alias", domain, alias_id))
        self.aliases[domain] = [a for a in self.aliases.get(domain, []) if a["id"] != alias_id]

    def writes(self):
        return [c for c in self.calls if c[0] != "list_aliases"]


def _cfg(tmp_path, domains=("x.be",)):
    return ForwardEmailConfig(
        token_env="T",
        directory=tmp_path / "mail",
        domains=list(domains),
        settings=dict(DEFAULT_SETTINGS),
        expect=dict(DEFAULT_EXPECT),
        alias=dict(DEFAULT_ALIAS),
    )


def _write_domain_file(tmp_path, domain, body):
    (tmp_path / "mail").mkdir(exist_ok=True)
    (tmp_path / "mail" / f"{domain}.yaml").write_text(textwrap.dedent(body))


def _run(cfg, client, **kw):
    out = io.StringIO()
    kw.setdefault("domains", None)
    kw.setdefault("doit", False)
    kw.setdefault("prune", False)
    kw.setdefault("mode", "plan")
    kw.setdefault("zones", None)
    rc = run(cfg, client, out=out, **kw)
    return rc, out.getvalue()


class TestPlan:
    def test_zero_diff_exits_0_and_writes_nothing(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases:\n  - {name: a, recipients: [serge@ginsys.eu]}\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("a")]})
        rc, out = _run(_cfg(tmp_path), client)
        assert rc == 0
        assert "no changes" in out
        assert client.writes() == []

    def test_changes_are_printed_but_not_applied_without_doit(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases:\n  - {name: a, recipients: [serge@ginsys.eu]}\n")
        client = FakeClient([_live_domain("x.be", retention_days=0)], {"x.be": [_live_alias("a")]})
        rc, out = _run(_cfg(tmp_path), client)
        assert rc == 0
        assert "retention_days" in out and "0 -> 30" in out
        assert "DRY-RUN" in out
        assert client.writes() == []

    def test_claimed_domain_missing_from_account_is_an_error_never_a_create(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([], {})
        rc, out = _run(_cfg(tmp_path), client)
        assert rc == 1
        assert "x.be" in out and "not in the account" in out
        assert client.writes() == []

    def test_missing_domain_file_is_an_error(self, tmp_path):
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client)
        assert rc == 1
        assert "x.be.yaml" in out

    def test_domain_filter_limits_scope(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path, ["x.be", "y.be"]), client, domains=["x.be"])
        assert rc == 0
        assert "y.be" not in out

    def test_unclaimed_domain_filter_is_rejected(self, tmp_path):
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, domains=["other.be"])
        assert rc == 2
        assert "other.be" in out


class TestApply:
    def test_doit_sends_settings_and_alias_writes(self, tmp_path):
        _write_domain_file(
            tmp_path,
            "x.be",
            """
            aliases:
              - {name: a, recipients: [new@y.z]}
              - {name: b, recipients: [serge@ginsys.eu]}
            """,
        )
        client = FakeClient([_live_domain("x.be", retention_days=0)], {"x.be": [_live_alias("a")]})
        rc, _out = _run(_cfg(tmp_path), client, doit=True)
        assert rc == 0
        assert ("update_domain", "x.be", {"retention_days": 30, "max_quota_per_alias": "1 GB"}) in client.calls
        updates = {c[2]: c[3] for c in client.calls if c[0] == "update_alias"}
        assert updates["id-a"]["recipients"] == ["new@y.z"]
        creates = [c[2] for c in client.calls if c[0] == "create_alias"]
        assert [(c["name"], c["recipients"]) for c in creates] == [("b", ["serge@ginsys.eu"])]
        assert not any(c[0] == "delete_alias" for c in client.calls)

    def test_prune_deletes_after_a_second_listing_agrees(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        rc, _out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 0
        assert client.calls.count(("list_aliases", "x.be")) == 2
        assert ("delete_alias", "x.be", "id-stray") in client.calls

    def test_create_and_prune_in_one_plan_relists_before_creating(self, tmp_path):
        # A create changes the id set; re-listing after it would always abort the prune.
        _write_domain_file(tmp_path, "x.be", "aliases:\n  - {name: b, recipients: [serge@ginsys.eu]}\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        rc, out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 0, out
        assert [c[0] for c in client.calls] == ["list_aliases", "list_aliases", "create_alias", "delete_alias"]
        assert ("delete_alias", "x.be", "id-stray") in client.calls

    def test_prune_aborts_when_the_second_listing_differs(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        client.mutate_on_relist = lambda c: c.aliases["x.be"].append(_live_alias("late"))
        rc, out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 1
        assert "changed between listings" in out
        assert not any(c[0] == "delete_alias" for c in client.calls)

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda a: a.update(has_imap=True),
            lambda a: a.update(storage_used=1),
            lambda a: a.update(name="renamed"),
        ],
        ids=["became-mailbox", "gained-mail", "renamed"],
    )
    def test_prune_aborts_when_a_planned_alias_changed_under_the_same_id(self, tmp_path, mutation):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        client.mutate_on_relist = lambda c: mutation(c.aliases["x.be"][0])
        rc, out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 1
        assert "changed between listings" in out
        assert not any(c[0] == "delete_alias" for c in client.calls)

    def test_mailbox_guard_blocks_the_whole_domain_apply(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be", retention_days=0)], {"x.be": [_live_alias("box", has_imap=True)]})
        rc, out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 1
        assert "mailbox" in out
        assert client.writes() == []

    def test_unmanaged_alias_without_prune_is_reported_only(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        rc, out = _run(_cfg(tmp_path), client, doit=True)
        assert rc == 0
        assert "unmanaged" in out and "stray" in out
        assert client.writes() == []


class TestUnexpectedErrors:
    def test_transport_failure_listing_domains_is_rc_1_not_a_traceback(self, tmp_path):
        class Broken(FakeClient):
            def list_domains(self):
                raise OSError("connection refused")

        rc, out = _run(_cfg(tmp_path), Broken([], {}))
        assert rc == 1
        assert "connection refused" in out

    def test_per_domain_unexpected_error_is_reported_and_the_run_continues(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        _write_domain_file(tmp_path, "y.be", "aliases: []\n")

        class Broken(FakeClient):
            def list_aliases(self, domain):
                if domain == "x.be":
                    raise KeyError("id")
                return super().list_aliases(domain)

        client = Broken([_live_domain("x.be"), _live_domain("y.be")], {"y.be": []})
        rc, out = _run(_cfg(tmp_path, ["x.be", "y.be"]), client)
        assert rc == 1
        assert "x.be" in out and "KeyError" in out
        assert "y.be                         no changes" in out


class TestExport:
    def test_export_writes_one_file_per_claimed_domain(self, tmp_path):
        client = FakeClient(
            [_live_domain("x.be", retention_days=0), _live_domain("y.be")],
            {"x.be": [_live_alias("a")], "y.be": []},
        )
        rc, _out = _run(_cfg(tmp_path, ["x.be", "y.be"]), client, mode="export")
        assert rc == 0
        x = (tmp_path / "mail" / "x.be.yaml").read_text()
        assert x.startswith("domain: x.be\nsettings:\n  retention_days: 0\n")
        assert (tmp_path / "mail" / "y.be.yaml").read_text() == "domain: y.be\naliases: []\n"
        assert client.writes() == []

    def test_export_preserves_write_only_settings_from_the_existing_file(self, tmp_path):
        # bounce_webhook / max_quota_per_alias cannot be read back; an overwrite would drop them
        # and the next unrelated domain PUT would silently send the repo default instead.
        _write_domain_file(
            tmp_path,
            "x.be",
            """
            settings:
              bounce_webhook: https://hooks.example/fe
              max_quota_per_alias: 10 GB
              retention_days: 5
            aliases: []
            """,
        )
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, mode="export")
        assert rc == 0
        text = (tmp_path / "mail" / "x.be.yaml").read_text()
        assert "bounce_webhook: 'https://hooks.example/fe'" in text
        assert "max_quota_per_alias: '10 GB'" in text
        assert "retention_days" not in text  # readable fields come from live state, not the old file
        assert "preserved write-only" in out and "bounce_webhook" in out


class TestDrift:
    ZONE = textwrap.dedent(
        """
        '':
          - type: MX
            values:
              - {exchange: mx1.forwardemail.net., preference: 10}
              - {exchange: mx2.forwardemail.net., preference: 10}
          - type: TXT
            values:
              - forward-email-site-verification=TOKEN
        _dmarc:
          type: TXT
          value: v=DMARC1\\; p=quarantine\\; rua=mailto:dmarc-1@forwardemail.net\\;
        fe-1._domainkey:
          type: TXT
          value: v=DKIM1\\; k=rsa\\; p=MIIBIjANBg\\;
        fe-bounces:
          type: CNAME
          value: forwardemail.net.
        """
    )

    def _zones(self, tmp_path, text=None):
        zd = tmp_path / "zones"
        zd.mkdir()
        (zd / "x.be.yaml").write_text(text or self.ZONE)
        return ZoneLookup.single(zd)

    def test_clean_zone_and_matching_expectations_exit_0(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zones=self._zones(tmp_path))
        assert rc == 0
        assert "clean" in out

    def test_stale_dkim_in_zone_file_is_reported(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        zones = self._zones(tmp_path, self.ZONE.replace("p=MIIBIjANBg", "p=OLD"))
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zones=zones)
        assert rc == 1
        assert "dkim" in out

    def test_expectation_mismatch_is_drift(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be", has_smtp=False)], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zones=self._zones(tmp_path))
        assert rc == 1
        assert "has_smtp" in out

    def test_domain_without_zone_file_is_informational(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        zd = tmp_path / "zones"
        zd.mkdir()
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zones=ZoneLookup.single(zd))
        assert rc == 0
        assert "no zone file" in out

    def test_ambiguous_zone_directory_is_a_finding_not_unchecked(self, tmp_path):
        # Two YamlProviders and nothing naming which one holds x.be: silently checking the
        # first (or none) would report rc 0 for a zone file that was never compared.
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        zones = ZoneLookup({"a": tmp_path / "a", "b": tmp_path / "b"}, {})
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zones=zones)
        assert rc == 1
        assert "ambiguous" in out and "2 YamlProviders" in out and "zones.x.be.sources" in out
        assert "not checked" not in out.split("ambiguous")[0]


class TestConfigPlumbing:
    CONFIG = textwrap.dedent(
        """
        providers:
          zones:
            class: octodns.provider.yaml.YamlProvider
            directory: ./zones
          legacy:
            class: octodns.provider.yaml.YamlProvider
            directory: /abs/legacy
          other:
            class: octodns_hetzner.HetznerProvider
        zones:
          x.be.:
            sources: [zones]
            targets: [other]
          old.be.:
            sources: [legacy]
          cloud.be.:
            sources: [other]
        """
    )

    def test_zone_directory_is_resolved_per_domain_from_the_zone_sources(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(self.CONFIG)
        zones = zone_lookup(str(cfg))
        assert zones.directory("x.be") == tmp_path / "zones"
        assert zones.directory("old.be") == Path("/abs/legacy")
        # sourced from a non-YAML provider only: there is no zone file to compare
        assert zones.directory("cloud.be") is None

    def test_zone_directory_falls_back_to_the_only_yaml_provider(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("providers:\n  zones:\n    class: octodns.provider.yaml.YamlProvider\n    directory: ./zones\n")
        assert zone_lookup(str(cfg)).directory("anything.be") == tmp_path / "zones"
        cfg.write_text("providers:\n  other:\n    class: octodns_hetzner.HetznerProvider\n")
        assert zone_lookup(str(cfg)).directory("anything.be") is None

    def test_zone_directory_with_several_yaml_providers_and_no_source_is_ambiguous(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(self.CONFIG)
        with pytest.raises(AmbiguousZoneDirectory, match="2 YamlProviders"):
            zone_lookup(str(cfg)).directory("unlisted.be")
        # a wildcard zone entry names the source for every unlisted zone
        cfg.write_text(self.CONFIG + "  '*':\n    sources: [legacy]\n")
        assert zone_lookup(str(cfg)).directory("unlisted.be") == Path("/abs/legacy")

    def test_main_without_opt_in_block_is_a_noop(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("providers: {}\n")
        monkeypatch.setattr("sys.argv", ["x", "--config", str(cfg)])
        assert main() == 0
        assert "not configured" in capsys.readouterr().out

    def test_main_rejects_doit_together_with_dry_run(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("forward_email:\n  domains: [x.be]\n")
        monkeypatch.setattr("sys.argv", ["x", "--config", str(cfg), "--doit", "--dry-run", "--prune"])
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2
        assert "not allowed with" in capsys.readouterr().err

    @pytest.mark.parametrize("text", ["forward_email: [\n", "forward_email:\n  domains: [x.be]\n  directory: 5\n"])
    def test_main_reports_malformed_config_as_rc_2_not_a_traceback(self, tmp_path, monkeypatch, capsys, text):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(text)
        monkeypatch.setattr("sys.argv", ["x", "--config", str(cfg)])
        assert main() == 2
        assert "config error" in capsys.readouterr().err

    def test_main_refuses_without_token_env(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("forward_email:\n  token: env/FE_TEST_TOKEN\n  domains: [x.be]\n")
        monkeypatch.delenv("FE_TEST_TOKEN", raising=False)
        monkeypatch.setattr("sys.argv", ["x", "--config", str(cfg)])
        assert main() == 2
        assert "FE_TEST_TOKEN" in capsys.readouterr().err


def _refuse_network(*_args):
    raise AssertionError("test reached the real transport")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr("octodns_gitops.forward_email.api.urllib_transport", _refuse_network)
