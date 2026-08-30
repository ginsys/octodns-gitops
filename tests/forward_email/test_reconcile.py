"""Tests for forward_email/reconcile.py — desired vs live diff, prune guard, quota handling."""

import pytest
from octodns_gitops.forward_email.config import (
    DEFAULT_ALIAS,
    DEFAULT_EXPECT,
    DEFAULT_SETTINGS,
    DesiredAlias,
    DesiredDomain,
    ForwardEmailConfig,
)
from octodns_gitops.forward_email.reconcile import parse_quota, plan_domain

GIB = 1024**3


def _cfg(**over):
    return ForwardEmailConfig(
        token_env="T",
        directory=None,
        domains=["x.be"],
        settings={**DEFAULT_SETTINGS, **over.get("settings", {})},
        expect={**DEFAULT_EXPECT, **over.get("expect", {})},
        alias={**DEFAULT_ALIAS, **over.get("alias", {})},
    )


def _live_domain(**over):
    """A GET /v1/domains/:d body already matching every package default."""
    d = {k: v for k, v in DEFAULT_SETTINGS.items() if k != "max_quota_per_alias"}
    d.update(DEFAULT_EXPECT)
    d.update({"name": "x.be", "id": "dom1", "has_strict_dmarc": False})
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


def _desired(aliases=(), settings=None, expect=None):
    return DesiredDomain("x.be", settings or {}, expect or {}, list(aliases))


class TestParseQuota:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [("1 GB", GIB), ("10 GB", 10 * GIB), ("512 MB", 512 * 1024**2), ("1GB", GIB), (GIB, GIB)],
    )
    def test_human_strings_are_1024_based(self, text, expected):
        assert parse_quota(text) == expected


class TestZeroDiff:
    def test_defaults_everywhere_is_an_empty_plan(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a")],
            prune=False,
        )
        assert plan.is_empty()
        assert plan.errors == []


class TestSettings:
    def test_diverging_setting_is_reported_with_both_values(self):
        plan = plan_domain(_desired(), _cfg(), _live_domain(retention_days=0), [], prune=False)
        assert [(c.field, c.live, c.desired) for c in plan.settings] == [("retention_days", 0, 30)]

    def test_per_domain_override_beats_repo_default(self):
        plan = plan_domain(
            _desired(settings={"ignore_mx_check": True}),
            _cfg(),
            _live_domain(ignore_mx_check=True),
            [],
            prune=False,
        )
        assert plan.settings == []

    def test_write_only_fields_ride_along_only_with_a_real_change(self):
        # max_quota_per_alias cannot be read back, so it never creates a diff on its own …
        quiet = plan_domain(_desired(), _cfg(), _live_domain(), [], prune=False)
        assert quiet.is_empty()
        # … but is part of the PUT body whenever one is sent.
        noisy = plan_domain(_desired(), _cfg(), _live_domain(retention_days=0), [], prune=False)
        assert noisy.settings_body() == {"retention_days": 30, "max_quota_per_alias": "1 GB"}


class TestAliases:
    def test_missing_alias_is_created_with_every_resolved_flag_explicit(self):
        # The server's own defaults are not ours: a create must pin every flag we resolve.
        plan = plan_domain(
            _desired([DesiredAlias("new", ["a@b.c"], description="hi")]),
            _cfg(),
            _live_domain(),
            [],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.action == "create"
        assert chg.body == {
            "name": "new",
            "recipients": ["a@b.c"],
            "description": "hi",
            "is_enabled": True,
            "error_code_if_disabled": 250,
            "has_imap": False,
            "has_pgp": False,
            "has_recipient_verification": False,
        }

    def test_repo_alias_default_override_reaches_the_create_body(self):
        plan = plan_domain(
            _desired([DesiredAlias("new", ["a@b.c"])]),
            _cfg(alias={"is_enabled": False, "error_code_if_disabled": 550}),
            _live_domain(),
            [],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.body["is_enabled"] is False
        assert chg.body["error_code_if_disabled"] == 550

    def test_repo_default_description_reaches_the_create_body(self):
        # The server's default is an empty description, not the repo's.
        plan = plan_domain(
            _desired([DesiredAlias("new", ["a@b.c"])]),
            _cfg(alias={"description": "managed in git"}),
            _live_domain(),
            [],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.body["description"] == "managed in git"

    def test_changed_recipients_is_an_update_naming_the_field(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["x@y.z", "serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a")],
            prune=False,
        )
        (chg,) = plan.aliases
        assert (chg.action, chg.alias_id) == ("update", "id-a")
        assert chg.changes == ["recipients"]
        assert chg.body["recipients"] == ["x@y.z", "serge@ginsys.eu"]

    def test_recipient_order_does_not_matter(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["b@b.b", "a@a.a"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a", recipients=["a@a.a", "b@b.b"])],
            prune=False,
        )
        assert plan.aliases == []

    def test_server_applied_labels_are_ignored(self):
        plan = plan_domain(
            _desired([DesiredAlias("*", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("*", labels=["catch-all"])],
            prune=False,
        )
        assert plan.aliases == []

    def test_disabled_alias_uses_repo_default_error_code(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"], is_enabled=False)]),
            _cfg(),
            _live_domain(),
            [_live_alias("a", is_enabled=False, error_code_if_disabled=550)],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.changes == ["error_code_if_disabled"]
        assert chg.body["error_code_if_disabled"] == 250


class TestVacationResponder:
    def test_live_keys_outside_the_fe_schema_do_not_produce_a_diff(self):
        # The loader only admits is_enabled/subject/message, so comparing the whole live mapping
        # would plan an update forever if FE ever returned an extra key.
        want = {"is_enabled": True, "subject": "away", "message": "back"}
        live = _live_alias("a", vacation_responder={**want, "end_date": "2026-09-01"})
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"], vacation_responder=want)]),
            _cfg(),
            _live_domain(),
            [live],
            prune=True,
        )
        assert plan.is_empty(), plan.aliases

    def test_changed_message_is_an_update_carrying_the_desired_mapping(self):
        want = {"is_enabled": True, "subject": "away", "message": "new"}
        live = _live_alias("a", vacation_responder={"is_enabled": True, "subject": "away", "message": "old"})
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"], vacation_responder=want)]),
            _cfg(),
            _live_domain(),
            [live],
            prune=True,
        )
        (chg,) = plan.aliases
        assert chg.changes == ["vacation_responder"]
        assert chg.body["vacation_responder"] == want


class TestQuota:
    def test_absent_live_quota_means_domain_default(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a")],
            prune=False,
        )
        assert plan.aliases == []

    def test_live_quota_differing_from_domain_default_is_reset_with_blank(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a", max_quota=10 * GIB)],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.changes == ["max_quota"]
        assert chg.body["max_quota"] == ""

    def test_live_quota_equal_to_domain_default_is_not_a_diff(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("a", max_quota=GIB)],
            prune=False,
        )
        assert plan.aliases == []

    def test_explicit_alias_quota_is_compared_in_bytes_and_sent_as_string(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"], max_quota="10 GB")]),
            _cfg(),
            _live_domain(),
            [_live_alias("a", max_quota=10 * GIB), _live_alias("b")],
            prune=False,
        )
        assert [c.name for c in plan.aliases] == []
        plan = plan_domain(
            _desired([DesiredAlias("a", ["serge@ginsys.eu"], max_quota="10 GB")]),
            _cfg(),
            _live_domain(),
            [_live_alias("a")],
            prune=False,
        )
        (chg,) = plan.aliases
        assert chg.body["max_quota"] == "10 GB"


class TestPrune:
    def test_unmanaged_alias_is_listed_but_not_deleted_without_prune(self):
        plan = plan_domain(_desired(), _cfg(), _live_domain(), [_live_alias("stray")], prune=False)
        assert plan.unmanaged == ["stray"]
        assert plan.aliases == []
        assert plan.is_empty()

    def test_prune_deletes_unmanaged_alias(self):
        plan = plan_domain(_desired(), _cfg(), _live_domain(), [_live_alias("stray")], prune=True)
        (chg,) = plan.aliases
        assert (chg.action, chg.name, chg.alias_id) == ("delete", "stray", "id-stray")

    @pytest.mark.parametrize("guard", [{"has_imap": True}, {"storage_used": 1}])
    def test_prune_never_touches_a_mailbox(self, guard):
        plan = plan_domain(
            _desired(), _cfg(), _live_domain(), [_live_alias("box", **guard)], prune=True
        )
        assert plan.aliases == []
        assert len(plan.errors) == 1
        assert "box" in plan.errors[0]


class TestMailboxUpdate:
    """The prune guard's own remedy ("add it to git") must not walk the operator into a PUT that
    turns IMAP off: an alias declared without `has_imap` resolves to the default `false`."""

    def test_omitted_has_imap_never_disables_imap_on_a_live_mailbox(self):
        plan = plan_domain(
            _desired([DesiredAlias("box", [])]),
            _cfg(),
            _live_domain(),
            [_live_alias("box", recipients=[], has_imap=True, storage_used=5_000_000)],
            prune=False,
        )
        assert plan.aliases == []
        assert len(plan.errors) == 1
        assert "box@x.be" in plan.errors[0] and "has_imap: true" in plan.errors[0]
        assert not plan.is_empty()

    def test_explicit_has_imap_false_is_intent_and_still_updates(self):
        # A mailbox that also forwards: turning IMAP off leaves a delivery target.
        plan = plan_domain(
            _desired([DesiredAlias("box", ["serge@ginsys.eu"], has_imap=False)]),
            _cfg(),
            _live_domain(),
            [_live_alias("box", has_imap=True, storage_used=5_000_000)],
            prune=False,
        )
        assert plan.errors == []
        (chg,) = plan.aliases
        assert (chg.action, chg.changes) == ("update", ["has_imap"])
        assert chg.body["has_imap"] is False

    def test_explicit_has_imap_true_keeps_the_mailbox_with_no_diff(self):
        plan = plan_domain(
            _desired([DesiredAlias("box", [], has_imap=True)]),
            _cfg(),
            _live_domain(),
            [_live_alias("box", recipients=[], has_imap=True, storage_used=5_000_000)],
            prune=True,
        )
        assert plan.is_empty(), (plan.aliases, plan.errors)

    def test_stored_mail_with_imap_already_off_is_neither_a_diff_nor_an_error(self):
        # Nothing to clear: the guard is about the has_imap True -> False PUT, not about storage.
        plan = plan_domain(
            _desired([DesiredAlias("box", ["serge@ginsys.eu"])]),
            _cfg(),
            _live_domain(),
            [_live_alias("box", has_imap=False, storage_used=5_000_000)],
            prune=True,
        )
        assert plan.is_empty(), (plan.aliases, plan.errors)


class TestNoDeliveryTarget:
    """`recipients: []` is only meaningful for a mailbox; with `has_imap` resolving to false the
    alias would accept mail and deliver it nowhere. Decidable only after defaults are resolved."""

    def test_create_without_recipients_or_mailbox_is_an_error_not_a_create(self):
        plan = plan_domain(_desired([DesiredAlias("a", [])]), _cfg(), _live_domain(), [], prune=False)
        assert plan.aliases == []
        assert len(plan.errors) == 1
        assert "a@x.be" in plan.errors[0] and "no recipients" in plan.errors[0] and "has_imap: true" in plan.errors[0]

    def test_update_emptying_recipients_on_a_non_mailbox_is_an_error(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", [], has_imap=False)]),
            _cfg(),
            _live_domain(),
            [_live_alias("a")],
            prune=False,
        )
        assert plan.aliases == []
        assert len(plan.errors) == 1 and "no recipients" in plan.errors[0]

    def test_mailbox_without_recipients_is_created_with_has_imap(self):
        plan = plan_domain(_desired([DesiredAlias("a", [], has_imap=True)]), _cfg(), _live_domain(), [], prune=False)
        assert plan.errors == []
        (chg,) = plan.aliases
        assert (chg.action, chg.body["recipients"], chg.body["has_imap"]) == ("create", [], True)

    def test_repo_default_has_imap_true_makes_recipientless_aliases_mailboxes(self):
        plan = plan_domain(
            _desired([DesiredAlias("a", [])]), _cfg(alias={"has_imap": True}), _live_domain(), [], prune=False
        )
        assert plan.errors == []
        assert plan.aliases[0].body["has_imap"] is True


class TestExpectations:
    def test_read_only_mismatch_is_reported_not_written(self):
        plan = plan_domain(_desired(), _cfg(), _live_domain(has_smtp=False), [], prune=False)
        assert plan.settings == []
        assert [(m.field, m.live, m.desired) for m in plan.expect_mismatch] == [
            ("has_smtp", False, True)
        ]
        assert not plan.is_empty()

    def test_per_domain_expectation_override(self):
        plan = plan_domain(
            _desired(expect={"has_newsletter": True}),
            _cfg(),
            _live_domain(has_newsletter=True),
            [],
            prune=False,
        )
        assert plan.expect_mismatch == []
