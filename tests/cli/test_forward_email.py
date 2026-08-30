"""Tests for cli/forward_email.py — plan/apply/export/drift against a fake API client."""

import copy
import io
import textwrap

import pytest
from octodns_gitops.cli.forward_email import main, run, zone_directory
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
        return {}

    def update_alias(self, domain, alias_id, body):
        self.calls.append(("update_alias", domain, alias_id, body))
        return {}

    def delete_alias(self, domain, alias_id):
        self.calls.append(("delete_alias", domain, alias_id))

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
    kw.setdefault("zone_dir", None)
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
        assert ("update_alias", "x.be", "id-a", {"name": "a", "recipients": ["new@y.z"]}) in client.calls
        assert ("create_alias", "x.be", {"name": "b", "recipients": ["serge@ginsys.eu"]}) in client.calls
        assert not any(c[0] == "delete_alias" for c in client.calls)

    def test_prune_deletes_after_a_second_listing_agrees(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        rc, _out = _run(_cfg(tmp_path), client, doit=True, prune=True)
        assert rc == 0
        assert client.calls.count(("list_aliases", "x.be")) == 2
        assert ("delete_alias", "x.be", "id-stray") in client.calls

    def test_prune_aborts_when_the_second_listing_differs(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": [_live_alias("stray")]})
        client.mutate_on_relist = lambda c: c.aliases["x.be"].append(_live_alias("late"))
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
        return zd

    def test_clean_zone_and_matching_expectations_exit_0(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zone_dir=self._zones(tmp_path))
        assert rc == 0
        assert "clean" in out

    def test_stale_dkim_in_zone_file_is_reported(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        zd = self._zones(tmp_path, self.ZONE.replace("p=MIIBIjANBg", "p=OLD"))
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zone_dir=zd)
        assert rc == 1
        assert "dkim" in out

    def test_expectation_mismatch_is_drift(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be", has_smtp=False)], {"x.be": []})
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zone_dir=self._zones(tmp_path))
        assert rc == 1
        assert "has_smtp" in out

    def test_domain_without_zone_file_is_informational(self, tmp_path):
        _write_domain_file(tmp_path, "x.be", "aliases: []\n")
        client = FakeClient([_live_domain("x.be")], {"x.be": []})
        zd = tmp_path / "zones"
        zd.mkdir()
        rc, out = _run(_cfg(tmp_path), client, mode="drift", zone_dir=zd)
        assert rc == 0
        assert "no zone file" in out


class TestConfigPlumbing:
    def test_zone_directory_comes_from_the_yaml_provider(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            textwrap.dedent(
                """
                providers:
                  zones:
                    class: octodns.provider.yaml.YamlProvider
                    directory: ./zones
                  other:
                    class: octodns_hetzner.HetznerProvider
                """
            )
        )
        assert zone_directory(str(cfg)) == tmp_path / "zones"

    def test_main_without_opt_in_block_is_a_noop(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("providers: {}\n")
        monkeypatch.setattr("sys.argv", ["x", "--config", str(cfg)])
        assert main() == 0
        assert "not configured" in capsys.readouterr().out

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
