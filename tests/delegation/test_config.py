"""Tests for delegation/config.py (signer derivation + opt-in parsing)."""

import textwrap

import pytest

from octodns_gitops.delegation.config import (
    DelegationConfigError,
    default_nameservers,
    derive_signer_target,
    load_delegation,
)

# A config shaped like the real repos: one hetzner target + one deSEC target per
# zone, deSEC target name differs from "desec" to prove derivation isn't hard-coded.
BASE_CFG = {
    "providers": {
        "hcloud-ginsys-company": {"class": "octodns_hetzner.HetznerProvider"},
        "desec-ginsys": {"class": "octodns_desec.DesecProvider"},
    },
    "zones": {
        "ginsys.be.": {"targets": ["hcloud-ginsys-company", "desec-ginsys"]},
        "no-signer.be.": {"targets": ["hcloud-ginsys-company"]},
        "two-signers.be.": {"targets": ["desec-ginsys", "desec-other"]},
    },
}


class TestDeriveSignerTarget:
    def test_derives_by_provider_class(self):
        assert derive_signer_target(BASE_CFG, "ginsys.be.") == "desec-ginsys"

    def test_unknown_zone_errors(self):
        with pytest.raises(DelegationConfigError, match="not an octoDNS zone"):
            derive_signer_target(BASE_CFG, "absent.be.")

    def test_no_signer_target_errors(self):
        with pytest.raises(DelegationConfigError, match="no signing-provider"):
            derive_signer_target(BASE_CFG, "no-signer.be.")

    def test_multiple_signers_require_override(self):
        cfg = {
            "providers": {
                "desec-ginsys": {"class": "octodns_desec.DesecProvider"},
                "desec-other": {"class": "octodns_desec.DesecProvider"},
            },
            "zones": {"two-signers.be.": {"targets": ["desec-ginsys", "desec-other"]}},
        }
        with pytest.raises(DelegationConfigError, match="multiple signer targets"):
            derive_signer_target(cfg, "two-signers.be.")

    def test_override_must_be_a_signer_target(self):
        with pytest.raises(DelegationConfigError, match="not a signing provider"):
            derive_signer_target(BASE_CFG, "ginsys.be.", override="hcloud-ginsys-company")

    def test_override_must_be_a_target_of_zone(self):
        with pytest.raises(DelegationConfigError, match="not a target of the zone"):
            derive_signer_target(BASE_CFG, "ginsys.be.", override="desec-other")

    def test_override_selects(self):
        cfg = {
            "providers": {
                "desec-ginsys": {"class": "octodns_desec.DesecProvider"},
                "desec-other": {"class": "octodns_desec.DesecProvider"},
            },
            "zones": {"two-signers.be.": {"targets": ["desec-ginsys", "desec-other"]}},
        }
        assert (
            derive_signer_target(cfg, "two-signers.be.", override="desec-other")
            == "desec-other"
        )


class TestDefaultNameservers:
    def test_desec_defaults(self):
        assert default_nameservers(BASE_CFG, "desec-ginsys") == [
            "ns1.desec.io",
            "ns2.desec.org",
        ]

    def test_unknown_signer_class_errors(self):
        cfg = {"providers": {"x": {"class": "octodns_foo.FooProvider"}}}
        with pytest.raises(DelegationConfigError, match="no default nameservers"):
            default_nameservers(cfg, "x")


class TestLoadDelegation:
    def _write(self, tmp_path, body: str) -> str:
        p = tmp_path / "config.yaml"
        p.write_text(textwrap.dedent(body))
        return str(p)

    def test_no_block_returns_empty(self, tmp_path):
        path = self._write(tmp_path, "providers: {}\nzones: {}\n")
        assert load_delegation(path) == []

    def test_parses_opt_in_zone(self, tmp_path):
        path = self._write(
            tmp_path,
            """
            providers:
              hcloud: {class: octodns_hetzner.HetznerProvider}
              desec: {class: octodns_desec.DesecProvider}
            zones:
              autops.be.: {targets: [hcloud, desec]}
              autops.eu.: {targets: [hcloud, desec]}
            delegation:
              registrar: ovh
              zones:
                autops.be.: {}
            """,
        )
        zones = load_delegation(path)
        assert len(zones) == 1  # only the opted-in zone
        z = zones[0]
        assert z.zone == "autops.be." and z.domain == "autops.be"
        assert z.registrar == "ovh"
        assert z.signer_target == "desec"
        assert z.target_nameservers == ["ns1.desec.io", "ns2.desec.org"]

    def test_registrar_config_env_prefix_and_manual(self, tmp_path):
        path = self._write(
            tmp_path,
            """
            providers:
              desec: {class: octodns_desec.DesecProvider}
            zones:
              autops.be.: {targets: [desec]}
              autops.eu.: {targets: [desec]}
            delegation:
              registrar: ovh
              registrar_config:
                ovh: {env_prefix: OVH_AUTOPS}
              zones:
                autops.be.: {}
                autops.eu.: {registrar: manual}
            """,
        )
        by_zone = {z.zone: z for z in load_delegation(path)}
        assert by_zone["autops.be."].registrar == "ovh"
        assert by_zone["autops.be."].registrar_options == {"env_prefix": "OVH_AUTOPS"}
        # manual zone doesn't get the ovh registrar_config
        assert by_zone["autops.eu."].registrar == "manual"
        assert by_zone["autops.eu."].registrar_options == {}

    def test_dnssec_opt_in_defaults_false(self, tmp_path):
        path = self._write(
            tmp_path,
            """
            providers:
              desec: {class: octodns_desec.DesecProvider}
            zones:
              a.be.: {targets: [desec]}
              b.be.: {targets: [desec]}
            delegation:
              registrar: ovh
              zones:
                a.be.: {}
                b.be.: {dnssec: true}
            """,
        )
        by_zone = {z.zone: z for z in load_delegation(path)}
        assert by_zone["a.be."].dnssec is False  # default: NS-only
        assert by_zone["b.be."].dnssec is True  # opt-in

    def test_per_zone_overrides(self, tmp_path):
        path = self._write(
            tmp_path,
            """
            providers:
              desec: {class: octodns_desec.DesecProvider}
            zones:
              autops.be.: {targets: [desec]}
            delegation:
              registrar: ovh
              zones:
                autops.be.:
                  registrar: gandi
                  target_nameservers: [a.example., b.example]
                  allow_extra_ds: true
            """,
        )
        (z,) = load_delegation(path)
        assert z.registrar == "gandi"
        assert z.target_nameservers == ["a.example", "b.example"]  # normalized
        assert z.allow_extra_ds is True
