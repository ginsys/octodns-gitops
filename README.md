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
