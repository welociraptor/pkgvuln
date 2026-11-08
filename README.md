# pkgvuln

Snapshots installed Nix package versions and matches them against NVD, OSV,
CISA KEV and EPSS advisories. Standard library only; no network access is
needed to build or test it.

## Usage

    pkgvuln snapshot                     # record the current system and user profiles
    pkgvuln run --nvd                    # sync, scan, enrich, report, version drift
    pkgvuln report --json                # machine-readable delta report
    pkgvuln outdated --verify-store-paths
    pkgvuln --help

The default database is `~/.local/share/package-versions/packages.db`, the same
location previous versions used. Exit codes: 0 clean, 2 findings remain, 3 only
whitelisted findings; 1 means a crash.

## Nix

    nix build
    nix run . -- --help

The flake exposes `packages.<system>.default` and an `apps.<system>.default`
entry. Consumers only need the package; scheduling, users and whitelist paths
belong to the system configuration.