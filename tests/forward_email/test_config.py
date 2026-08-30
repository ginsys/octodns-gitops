"""Tests for forward_email/config.py (opt-in block + per-domain desired-state files)."""

import textwrap

import pytest
from octodns_gitops.forward_email.config import (
    DEFAULT_ALIAS,
    DEFAULT_EXPECT,
    DEFAULT_SETTINGS,
    ForwardEmailConfigError,
    load_domain_file,
    load_forward_email,
)


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return p


class TestPackageDefaults:
    def test_smtp_port_is_a_string(self):
        # The API stores "25" as a string; an int would produce a permanent diff.
        assert DEFAULT_SETTINGS["smtp_port"] == "25"

    def test_decided_domain_defaults(self):
        assert DEFAULT_SETTINGS["retention_days"] == 30
        assert DEFAULT_SETTINGS["require_tls_inbound"] is True
        assert DEFAULT_SETTINGS["ignore_mx_check"] is False
        assert DEFAULT_SETTINGS["max_quota_per_alias"] == "1 GB"

    def test_decided_expectations(self):
        assert DEFAULT_EXPECT == {
            "has_smtp": True,
            "has_newsletter": False,
            "max_recipients_per_alias": 10,
            "plan": "team",
        }

    def test_alias_defaults(self):
        assert DEFAULT_ALIAS["error_code_if_disabled"] == 250
        assert DEFAULT_ALIAS["has_recipient_verification"] is False


class TestLoadForwardEmail:
    def test_absent_block_returns_none(self, tmp_path):
        cfg = _write(tmp_path, "config.yaml", "providers: {}\nzones: {}\n")
        assert load_forward_email(str(cfg)) is None

    @pytest.mark.parametrize("block", ["forward_email: {}\n", "forward_email:\n", "forward_email: []\n"])
    def test_present_but_empty_block_is_an_error_not_an_opt_out(self, tmp_path, block):
        # The key is the opt-in; an emptied block must not silently disable every mail command.
        cfg = _write(tmp_path, "config.yaml", f"providers: {{}}\n{block}")
        with pytest.raises(ForwardEmailConfigError, match="forward_email"):
            load_forward_email(str(cfg))

    def test_parses_block_with_defaults_and_domains(self, tmp_path):
        cfg = _write(
            tmp_path,
            "config.yaml",
            """
            providers: {}
            zones: {}
            forward_email:
              token: env/FORWARD_EMAIL_API_TOKEN
              directory: ./mail/forward-email
              defaults:
                settings:
                  retention_days: 0
              domains:
                - autops.be
                - autops.eu
            """,
        )
        fe = load_forward_email(str(cfg))
        assert fe.token_env == "FORWARD_EMAIL_API_TOKEN"
        assert fe.directory == tmp_path / "mail" / "forward-email"
        assert fe.domains == ["autops.be", "autops.eu"]
        # repo default overrides the package default; everything else stays
        assert fe.settings["retention_days"] == 0
        assert fe.settings["require_tls_inbound"] is True
        assert fe.expect == DEFAULT_EXPECT
        assert fe.alias == DEFAULT_ALIAS

    def test_directory_defaults_relative_to_config(self, tmp_path):
        cfg = _write(
            tmp_path,
            "config.yaml",
            """
            forward_email:
              domains: [autops.be]
            """,
        )
        fe = load_forward_email(str(cfg))
        assert fe.directory == tmp_path / "mail" / "forward-email"
        assert fe.token_env == "FORWARD_EMAIL_API_TOKEN"

    def test_token_must_be_env_ref(self, tmp_path):
        cfg = _write(
            tmp_path,
            "config.yaml",
            """
            forward_email:
              token: literal-secret
              domains: [autops.be]
            """,
        )
        with pytest.raises(ForwardEmailConfigError, match="env/"):
            load_forward_email(str(cfg))

    def test_domains_required_and_normalized(self, tmp_path):
        cfg = _write(tmp_path, "config.yaml", "forward_email:\n  domains: []\n")
        with pytest.raises(ForwardEmailConfigError, match="domains"):
            load_forward_email(str(cfg))
        cfg = _write(tmp_path, "config.yaml", "forward_email:\n  domains: [Autops.BE., autops.be]\n")
        with pytest.raises(ForwardEmailConfigError, match="duplicate"):
            load_forward_email(str(cfg))

    def test_unknown_setting_in_defaults_rejected(self, tmp_path):
        # Read-only fields (has_strict_dmarc) must never be declared as settings.
        cfg = _write(
            tmp_path,
            "config.yaml",
            """
            forward_email:
              defaults:
                settings:
                  has_strict_dmarc: true
              domains: [autops.be]
            """,
        )
        with pytest.raises(ForwardEmailConfigError, match="has_strict_dmarc"):
            load_forward_email(str(cfg))

    @pytest.mark.parametrize(
        "block, needle",
        [
            ("defualts:\n    settings:\n      retention_days: 0\n", "defualts"),
            ("defaults:\n    setings:\n      retention_days: 0\n", "setings"),
            ("tokn: env/X\n", "tokn"),
        ],
    )
    def test_unknown_keys_in_the_block_are_rejected_not_ignored(self, tmp_path, block, needle):
        # A misspelled `defaults` would silently enforce the package defaults instead of the
        # operator's override — the same present-but-wrong class as an empty block.
        cfg = _write(tmp_path, "config.yaml", f"forward_email:\n  domains: [x.be]\n  {block}")
        with pytest.raises(ForwardEmailConfigError, match=needle):
            load_forward_email(str(cfg))


class TestTypeValidation:
    @pytest.mark.parametrize(
        "block",
        [
            "defaults:\n    settings:\n      retention_days: forever\n",
            "defaults:\n    settings:\n      require_tls_inbound: 'true'\n",
            "defaults:\n    settings:\n      smtp_port: 25\n",  # int would diff forever
            "defaults:\n    alias:\n      is_enabled: 'false'\n",
            "defaults:\n    alias:\n      max_quota: 1 GB\n",  # only per-alias, never a default
        ],
    )
    def test_wrong_scalar_types_in_defaults_rejected(self, tmp_path, block):
        cfg = _write(tmp_path, "config.yaml", f"forward_email:\n  domains: [x.be]\n  {block}")
        with pytest.raises(ForwardEmailConfigError):
            load_forward_email(str(cfg))

    @pytest.mark.parametrize(
        "block",
        [
            "defaults: []\n",
            "defaults:\n    settings: []\n",
            "defaults:\n    expect: false\n",
            "defaults:\n    alias: []\n",
            "directory: 5\n",
        ],
    )
    def test_non_mapping_sections_in_the_block_are_rejected_not_treated_as_absent(self, tmp_path, block):
        # `settings: []` used to become `{}` and the package defaults were then enforced.
        cfg = _write(tmp_path, "config.yaml", f"forward_email:\n  domains: [x.be]\n  {block}")
        with pytest.raises(ForwardEmailConfigError):
            load_forward_email(str(cfg))

    @pytest.mark.parametrize("body", ["settings: []\naliases: []\n", "settings: false\n", "expect: x\n"])
    def test_non_mapping_sections_in_the_domain_file_are_rejected(self, tmp_path, body):
        p = _write(tmp_path, "x.be.yaml", body)
        with pytest.raises(ForwardEmailConfigError, match="mapping"):
            load_domain_file(p, "x.be")

    def test_unreadable_or_malformed_yaml_is_a_config_error(self, tmp_path):
        p = _write(tmp_path, "x.be.yaml", "aliases: [\n")
        with pytest.raises(ForwardEmailConfigError, match="x.be.yaml"):
            load_domain_file(p, "x.be")
        d = tmp_path / "dir.yaml"
        d.mkdir()
        with pytest.raises(ForwardEmailConfigError, match="dir.yaml"):
            load_domain_file(d, "x.be")

    def test_domains_must_be_strings(self, tmp_path):
        cfg = _write(tmp_path, "config.yaml", "forward_email:\n  domains: [123]\n")
        with pytest.raises(ForwardEmailConfigError, match="string"):
            load_forward_email(str(cfg))

    @pytest.mark.parametrize(
        ("body", "needle"),
        [
            ("settings:\n  retention_days: forever\naliases: []\n", "retention_days"),
            ("aliases:\n  - {name: a, recipients: [x@y.z], is_enabled: 'false'}\n", "is_enabled"),
            ("aliases:\n  - {name: a, recipients: [x@y.z], error_code_if_disabled: '250'}\n", "error_code"),
            ("aliases:\n  - {name: a, recipients: [1]}\n", "recipients"),
            ("aliases:\n  - {name: a, recipients: [x@y.z], vacation_responder: yes}\n", "vacation_responder"),
        ],
    )
    def test_wrong_scalar_types_in_domain_file_rejected(self, tmp_path, body, needle):
        p = _write(tmp_path, "x.be.yaml", body)
        with pytest.raises(ForwardEmailConfigError, match=needle):
            load_domain_file(p, "x.be")


class TestLoadDomainFile:
    def test_minimal_file(self, tmp_path):
        p = _write(
            tmp_path,
            "waarschoot.org.yaml",
            """
            aliases:
              - name: serge
                recipients: [serge@ginsys.eu]
              - name: wordpress
                recipients: serge@ginsys.eu
            """,
        )
        d = load_domain_file(p, "waarschoot.org")
        assert d.domain == "waarschoot.org"
        assert d.settings == {}
        assert d.expect == {}
        assert [a.name for a in d.aliases] == ["serge", "wordpress"]
        # scalar recipient normalized to a list
        assert d.aliases[1].recipients == ["serge@ginsys.eu"]

    def test_domain_key_must_match_filename(self, tmp_path):
        p = _write(tmp_path, "a.be.yaml", "domain: b.be\naliases: []\n")
        with pytest.raises(ForwardEmailConfigError, match="b.be"):
            load_domain_file(p, "a.be")

    def test_regex_and_catchall_alias_names_accepted(self, tmp_path):
        p = _write(
            tmp_path,
            "k8s.be.yaml",
            r"""
            aliases:
              - name: "*"
                recipients: [serge@ginsys.eu]
              # single quotes: a double-quoted YAML scalar would parse "\w" as an escape
              - name: '/^([\w\-\.]+)$/'
                recipients: ["$1@autops.eu"]
            """,
        )
        d = load_domain_file(p, "k8s.be")
        assert d.aliases[0].name == "*"
        assert d.aliases[1].name == r"/^([\w\-\.]+)$/"

    def test_alias_fields(self, tmp_path):
        p = _write(
            tmp_path,
            "ginsys.org.yaml",
            """
            settings:
              ignore_mx_check: true
            expect:
              has_smtp: false
            aliases:
              - name: box
                recipients: []
                description: an imap box
                is_enabled: false
                has_imap: true
                has_recipient_verification: true
                max_quota: 10 GB
                error_code_if_disabled: 550
            """,
        )
        d = load_domain_file(p, "ginsys.org")
        a = d.aliases[0]
        assert a.recipients == []
        assert a.description == "an imap box"
        assert a.is_enabled is False
        assert a.has_imap is True
        assert a.has_recipient_verification is True
        assert a.max_quota == "10 GB"
        assert a.error_code_if_disabled == 550
        assert d.settings == {"ignore_mx_check": True}
        assert d.expect == {"has_smtp": False}

    def test_duplicate_alias_name_rejected(self, tmp_path):
        p = _write(
            tmp_path,
            "x.be.yaml",
            """
            aliases:
              - {name: a, recipients: [x@y.z]}
              - {name: a, recipients: [x@y.z]}
            """,
        )
        with pytest.raises(ForwardEmailConfigError, match="duplicate alias"):
            load_domain_file(p, "x.be")

    def test_labels_are_server_managed_and_rejected(self, tmp_path):
        # Accepted-but-never-reconciled would plan as clean while doing nothing.
        p = _write(tmp_path, "x.be.yaml", "aliases:\n  - {name: a, recipients: [x@y.z], labels: [vip]}\n")
        with pytest.raises(ForwardEmailConfigError, match="server-managed"):
            load_domain_file(p, "x.be")
        cfg = _write(tmp_path, "config.yaml", "forward_email:\n  domains: [x.be]\n  defaults:\n    alias:\n      labels: [vip]\n")
        with pytest.raises(ForwardEmailConfigError, match="server-managed"):
            load_forward_email(str(cfg))

    def test_unknown_alias_key_rejected(self, tmp_path):
        p = _write(
            tmp_path,
            "x.be.yaml",
            """
            aliases:
              - {name: a, recipients: [x@y.z], storage_used: 5}
            """,
        )
        with pytest.raises(ForwardEmailConfigError, match="storage_used"):
            load_domain_file(p, "x.be")
