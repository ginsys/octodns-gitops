# octodns-gitops

GitOps tooling for OctoDNS: processors, CLI wrappers, and workflow automation.

## Installation

```bash
pip install "octodns-gitops @ git+https://github.com/ginsys/octodns-gitops@main"
```

Or pin to a specific commit:

```bash
pip install "octodns-gitops @ git+https://github.com/ginsys/octodns-gitops@COMMIT_HASH"
```

## Features

### Processors

Use in your `config.yaml`:

```yaml
processors:
  acme-filter:
    class: octodns_gitops.processors.AcmeFilter

  external-dns-filter:
    class: octodns_gitops.processors.ExternalDnsFilter
    txt_prefix: 'extdns'
    owner_id: 'my-cluster'
```

- **AcmeFilter**: Ignores `_acme-challenge` records (managed by certificate authorities)
- **ExternalDnsFilter**: Ignores records managed by external-dns

### Logging Filters

Use in your `logging.yaml`:

```yaml
filters:
  suppress_soa:
    (): octodns_gitops.logging.SuppressSoaWarningsFilter
```

### CLI Tools

- `octodns-gitops-validate` - Validate zone file syntax
- `octodns-gitops-sync` - Sync zones with improved output and safety thresholds
- `octodns-gitops-drift` - Check for drift between live DNS and local zones
- `octodns-gitops-report` - Query nameservers and show consistency report
- `octodns-gitops-init` - Generate Makefile for dns-zones repositories
- `octodns-gitops-forwardemail` - Reconcile Forward Email domain settings and aliases with per-domain files (see below)

### Forward Email account settings (opt-in)

A dns-zones repo can also own the *account* side of its mail domains at [Forward Email](https://forwardemail.net):
domain settings and aliases, kept in `mail/forward-email/<domain>.yaml` and reconciled through the REST API.
Opt in with a top-level `forward_email:` block in `config.yaml` (ignored by octoDNS, like `delegation:`):

```yaml
forward_email:
  token: env/FORWARD_EMAIL_API_TOKEN   # env/ reference only, never a literal
  directory: ./mail/forward-email      # default
  defaults:                            # optional repo-level overrides of the package defaults
    settings: {}                       # API-writable domain fields
    expect: {}                         # read-only fields, drift-checked only
    alias: {}                          # alias field defaults
  domains:                             # the ownership boundary: nothing outside it is ever touched
    - example.com
```

One file per claimed domain; everything equal to the resolved defaults is omitted:

```yaml
domain: example.com
settings:
  ignore_mx_check: true          # only fields the API can write
expect:
  has_newsletter: true           # FE-staff-set fields we want reported on mismatch
aliases:
  - name: hello
    recipients: [you@example.org]
  - name: '/^([\w\-\.]+)$/'      # regex names must be single-quoted
    recipients: ['$1@example.org']
    is_enabled: false
```

Contract:

- `make mail-plan` is a dry run; `make mail-apply` writes. `DOMAIN=example.com` scopes either.
- Domains are **never created or deleted** from git; a claimed domain missing from the account is an error.
- `PRUNE=1` deletes aliases absent from git, inside claimed domains only, after a second listing
  agrees with the first. An alias with `has_imap: true` or stored mail is a mailbox: it is never
  pruned and blocks the run until it is added to git or removed in the web UI.
- `make mail-export` writes the files from live state (bootstrap, or re-baseline after a deliberate
  web-UI change). A freshly exported file must plan as **zero changes**. Write-only settings already
  declared in the file being overwritten are preserved, since the API cannot return them.
- `make mail-drift` compares FE's generated DNS records (DKIM key, `fe-bounces` CNAME, verification
  TXT, the DMARC `rua` address) with the repo's zone file, and reports read-only expectation
  mismatches. Unless `ignore_mx_check: true`, the apex MX must be exactly FE's two exchangers at
  one shared preference — any other exchanger is a finding. The zone file is looked up in the
  YamlProvider the zone's `sources:` names; with several YamlProviders and no such entry the
  domain is reported as ambiguous rather than unchecked. Exit 1 on any finding.
- `aliases:` is always an explicit list (`aliases: []` for a domain with none) and every alias
  declares `recipients:`; an absent key is an error, never "empty" — with `PRUNE=1` that would
  have meant "delete everything". `vacation_responder` takes exactly `is_enabled` (bool,
  required), `subject` and `message`.
- `max_quota_per_alias` and `bounce_webhook` cannot be read back from the API: they are sent with
  every domain update but never produce a diff on their own.

## Quick Start with mise

1. Copy the template to your dns-zones repo:

```bash
curl -O https://raw.githubusercontent.com/ginsys/octodns-gitops/main/templates/mise.toml
```

2. Configure your secrets in `mise.local.toml`:

```toml
[hooks.enter]
shell = "bash"
script = "source $HOME/etc/keys/tokens.bash"
```

3. Run setup:

```bash
mise trust
mise run setup
```

4. Use the generated Makefile:

```bash
make plan          # Preview changes
make apply         # Apply changes
make drift-check   # Check for drift
make report        # Query nameservers
```

## Configuration

The CLI tools read environment variables:

- `QUIET=1` - Quiet mode (default)
- `DEBUG=1` - Debug output
- `ZONE=example.com.` - Process single zone

## License

GPL-3.0-or-later
