"""Tests for forward_email/export.py — live state to a per-domain file that round-trips."""

import textwrap

from octodns_gitops.forward_email.config import (
    DEFAULT_ALIAS,
    DEFAULT_EXPECT,
    DEFAULT_SETTINGS,
    ForwardEmailConfig,
    load_domain_file,
)
from octodns_gitops.forward_email.export import export_domain
from octodns_gitops.forward_email.reconcile import plan_domain

GIB = 1024**3


def _cfg():
    return ForwardEmailConfig(
        token_env="T",
        directory=None,
        domains=["x.be"],
        settings=dict(DEFAULT_SETTINGS),
        expect=dict(DEFAULT_EXPECT),
        alias=dict(DEFAULT_ALIAS),
    )


def _live_domain(**over):
    d = {k: v for k, v in DEFAULT_SETTINGS.items() if k != "max_quota_per_alias"}
    d.update(DEFAULT_EXPECT)
    d.update({"name": "x.be", "id": "dom1", "has_strict_dmarc": False, "has_catchall": True})
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


class TestExport:
    def test_all_defaults_yields_minimal_file(self):
        text = export_domain(_cfg(), _live_domain(), [_live_alias("a")])
        assert text == textwrap.dedent(
            """\
            domain: x.be
            aliases:
              - name: a
                recipients:
                  - serge@ginsys.eu
            """
        )

    def test_diverging_settings_and_expectations_are_written(self):
        text = export_domain(_cfg(), _live_domain(retention_days=0, has_smtp=False), [])
        assert "settings:\n  retention_days: 0\n" in text
        assert "expect:\n  has_smtp: false\n" in text
        # derived fields never leak into the file
        assert "has_catchall" not in text
        assert "has_strict_dmarc" not in text

    def test_regex_name_is_single_quoted(self):
        text = export_domain(_cfg(), _live_domain(), [_live_alias(r"/^([\w\-\.]+)$/", recipients=["$1@y.z"])])
        assert r"- name: '/^([\w\-\.]+)$/'" in text
        assert "recipients:\n      - $1@y.z" in text

    def test_catchall_name_is_quoted(self):
        text = export_domain(_cfg(), _live_domain(), [_live_alias("*")])
        assert "- name: '*'" in text

    def test_non_default_alias_fields_are_written_and_quota_as_human_string(self):
        alias = _live_alias(
            "box",
            recipients=[],
            description="an imap box",
            is_enabled=False,
            error_code_if_disabled=550,
            has_imap=True,
            max_quota=10 * GIB,
            storage_used=549_000,
            labels=["catch-all"],
            vacation_responder={"is_enabled": True, "subject": "away", "message": "back soon"},
        )
        text = export_domain(_cfg(), _live_domain(), [alias])
        assert "recipients: []" in text
        assert "description: an imap box" in text
        assert "is_enabled: false" in text
        assert "error_code_if_disabled: 550" in text
        assert "has_imap: true" in text
        assert "max_quota: 10 GB" in text
        assert "vacation_responder:\n      is_enabled: true\n      subject: away\n" in text
        assert "storage_used" not in text
        assert "labels" not in text
        assert "has_pgp" not in text

    def test_date_like_and_multiline_strings_survive_yaml_round_trip(self, tmp_path):
        aliases = [
            _live_alias("a", description="2026-08-30"),
            _live_alias("b", description="1e3"),
            _live_alias(
                "c",
                vacation_responder={"is_enabled": True, "subject": "away", "message": "line1\nline2"},
            ),
        ]
        p = tmp_path / "x.be.yaml"
        p.write_text(export_domain(_cfg(), _live_domain(), aliases))
        d = load_domain_file(p, "x.be")
        assert d.aliases[0].description == "2026-08-30"
        assert d.aliases[1].description == "1e3"
        assert d.aliases[2].vacation_responder["message"] == "line1\nline2"

    def test_blank_live_description_under_a_non_empty_default_is_written_explicitly(self, tmp_path):
        cfg = _cfg()
        cfg.alias["description"] = "managed in git"
        live_aliases = [_live_alias("a", description=""), _live_alias("b", description=None), _live_alias("c")]
        text = export_domain(cfg, _live_domain(), live_aliases)
        assert text.count("description: ''") == 3
        p = tmp_path / "x.be.yaml"
        p.write_text(text)
        plan = plan_domain(load_domain_file(p, "x.be"), cfg, _live_domain(), live_aliases, prune=True)
        assert plan.is_empty(), plan.aliases

    def test_every_vacation_responder_key_is_exported(self, tmp_path):
        vac = {"is_enabled": True, "subject": "away", "message": "back", "end_date": "2026-09-01", "extra": {"k": 1}}
        live_aliases = [_live_alias("a", vacation_responder=dict(vac))]
        text = export_domain(_cfg(), _live_domain(), live_aliases)
        assert "vacation_responder:\n      is_enabled: true\n      subject: away\n      message: back\n" in text
        assert "end_date: '2026-09-01'" in text
        p = tmp_path / "x.be.yaml"
        p.write_text(text)
        desired = load_domain_file(p, "x.be")
        assert desired.aliases[0].vacation_responder == vac
        assert plan_domain(desired, _cfg(), _live_domain(), live_aliases, prune=True).is_empty()

    def test_alias_quotas_are_compared_against_the_preserved_per_domain_default(self, tmp_path):
        # A preserved `max_quota_per_alias: 10 GB` is what the reloaded file resolves aliases against;
        # comparing exports against the repo default instead turned a live 1 GiB alias into a reset.
        live_aliases = [_live_alias("a", max_quota=GIB), _live_alias("b", max_quota=10 * GIB), _live_alias("c")]
        text = export_domain(_cfg(), _live_domain(), live_aliases, write_only={"max_quota_per_alias": "10 GB"})
        assert "max_quota_per_alias: '10 GB'" in text
        assert "  - name: a\n    recipients:\n      - serge@ginsys.eu\n    max_quota: 1 GB\n" in text
        assert text.count("max_quota:") == 1
        p = tmp_path / "x.be.yaml"
        p.write_text(text)
        plan = plan_domain(load_domain_file(p, "x.be"), _cfg(), _live_domain(), live_aliases, prune=True)
        assert plan.is_empty(), plan.aliases

    def test_export_then_plan_is_a_zero_diff(self, tmp_path):
        # The A4 acceptance test in miniature.
        live_dom = _live_domain(retention_days=0, ignore_mx_check=True, has_newsletter=True)
        live_aliases = [
            _live_alias("a"),
            _live_alias("*", labels=["catch-all"]),
            _live_alias(r"/^(.*)$/", is_enabled=False, recipients=["$1@y.z"]),
            _live_alias("box", has_imap=True, max_quota=10 * GIB, storage_used=5),
        ]
        p = tmp_path / "x.be.yaml"
        p.write_text(export_domain(_cfg(), live_dom, live_aliases))
        desired = load_domain_file(p, "x.be")
        plan = plan_domain(desired, _cfg(), live_dom, live_aliases, prune=True)
        assert plan.is_empty(), (plan.settings, plan.aliases, plan.expect_mismatch, plan.errors)
