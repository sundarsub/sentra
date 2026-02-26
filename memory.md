# Execwall Project Memory

## Project Rename: Sentra → Execwall (2026-02-25)

### Reason
Renamed from "Sentra" to "Execwall" to avoid conflict with an existing company named Sentra.

### Changes Made

#### 1. Cargo.toml
- Package name: `sentra` → `execwall`
- Version: `2.2.2` → `1.0.0` (fresh start)
- Repository URL updated to `sundarsub/execwall`

#### 2. Binary Names
- `sentra` → `execwall`
- `sentra-shell` → `execwall-shell`

#### 3. Paths Updated
| Old | New |
|-----|-----|
| `/etc/sentra/` | `/etc/execwall/` |
| `/usr/lib/sentra/` | `/usr/lib/execwall/` |
| `/var/log/sentra/` | `/var/log/execwall/` |
| `/usr/local/bin/sentra` | `/usr/local/bin/execwall` |
| `/usr/local/bin/sentra-shell` | `/usr/local/bin/execwall-shell` |

#### 4. Environment Variables
- `SENTRA_BIN` → `EXECWALL_BIN`
- `SENTRA_POLICY` → `EXECWALL_POLICY`
- `SENTRA_QUIET` → `EXECWALL_QUIET`
- `SENTRA_VERBOSE` → `EXECWALL_VERBOSE`

#### 5. Source Code Updates
- `src/main.rs` - All banner text, prompts, paths
- `src/bin/openclaw_launcher.rs` - Variable names, paths, flags
- `src/bin/python_runner.rs` - Paths
- `src/seccomp_profile.rs` - Struct names (`SentraConfig` → `ExecwallConfig`)
- `src/cgroup.rs` - Cgroup name (`sentra` → `execwall`)
- `src/api.rs` - Banner text
- `src/sandbox.rs` - Temp file prefixes
- `src/policy.rs` - Default paths

#### 6. Scripts
- `scripts/sentra-shell` → `scripts/execwall-shell`
- `scripts/install-oracle-cloud.sh` - All references updated
- `install.sh` - All references updated

#### 7. Documentation
- `README.md` - Full update
- `docs/ORACLE_CLOUD_DEPLOYMENT.md`
- `docs/SECCOMP_PROFILES.md`
- All other markdown files

#### 8. Directory Renames
- `sentra-or-gate/` → `execwall-or-gate/`
- `sentra-oracle.md` → `execwall-oracle.md`

#### 9. GitHub Repository
- Renamed via API: `sundarsub/sentra` → `sundarsub/execwall`
- Old URLs automatically redirect

### GitHub Actions Setup

#### CI Workflow (`.github/workflows/ci.yml`)
- Triggers: Push to main, Pull requests
- Jobs:
  - **Test**: Build and run `cargo test`
  - **Lint**: Check formatting with `cargo fmt`, run `cargo clippy`
- Requires: `libseccomp-dev` on Ubuntu

#### Release Workflow (`.github/workflows/release.yml`)
- Triggers: Tag push matching `v*.*.*`
- Builds for 4 platforms:
  - `x86_64-unknown-linux-gnu` (ubuntu-latest)
  - `aarch64-unknown-linux-gnu` (ubuntu-latest, cross-compiled)
  - `x86_64-apple-darwin` (macos-13)
  - `aarch64-apple-darwin` (macos-14)
- Creates tar.gz archives with SHA256 checksums
- Uploads to GitHub Release

### Release v1.0.0

**Tag:** v1.0.0
**URL:** https://github.com/sundarsub/execwall/releases/tag/v1.0.0

**Assets (manually uploaded):**
- `execwall-linux-x86_64.tar.gz` - Built on Oracle Cloud
- `execwall-macos-aarch64.tar.gz` - Built locally

**Future releases** will have all 4 platform binaries automatically built by GitHub Actions.

### Install Command
```bash
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | bash
```

### Notes
- Support email remains: `sentrahelp@gmail.com` (kept for continuity)
- Old GitHub URLs redirect automatically
- Stars, forks, issues all preserved after rename
