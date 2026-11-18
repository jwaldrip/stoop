#!/bin/sh
# The final call is deliberately last: an incomplete curl pipe cannot install.
stoop_install() {
  set -eu
  action=install
  case ${1-} in
    '') ;;
    --help) printf '%s\n' 'Usage: install.sh [--help|--dry-run|--uninstall]' 'STOOP_VERSION pins a vX.Y.Z release; STOOP_INSTALL_DIR selects the destination.'; return 0 ;;
    --dry-run) action=dry-run ;;
    --uninstall) action=uninstall ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; return 1 ;;
  esac
  [ "$#" -le 1 ] || { echo 'Only one option is accepted.' >&2; return 1; }
  dir=${STOOP_INSTALL_DIR:-${HOME:?HOME is required}/.local/bin}
  case "$dir" in /*) ;; *) echo 'STOOP_INSTALL_DIR must be absolute.' >&2; return 1;; esac
  case "$dir/" in //|/bin/*|/sbin/*|/usr/*|/etc/*|/opt/*|/System/*|/Library/*|/var/*|*/../*|*/./*) echo 'Refusing a system or non-canonical installation directory.' >&2; return 1;; esac
  if [ "$action" = uninstall ]; then
    rm -f "$dir/stoop"
    printf 'Removed %s/stoop if present.\n' "$dir"
    return 0
  fi
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-musl ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    Darwin:arm64) target=aarch64-apple-darwin ;;
    *) echo 'Unsupported OS or architecture. Prebuilt binaries: https://github.com/jwaldrip/stoop/releases' >&2; return 1 ;;
  esac
  # STOOP_RELEASE_BASE is for tests only. Plain HTTP is limited to loopback.
  base=${STOOP_RELEASE_BASE:-https://github.com/jwaldrip/stoop/releases/download}
  case "$base" in
    https://github.com/jwaldrip/stoop/releases/download) proto=https ;;
    http://127.0.0.1:*|http://localhost:*)
      port=${base##*:}
      case "$port" in ''|*[!0-9]*) echo 'Invalid loopback test server port.' >&2; return 1;; esac
      proto=http ;;
    *) echo 'Invalid STOOP_RELEASE_BASE; only the official HTTPS URL or a loopback test server is allowed.' >&2; return 1 ;;
  esac
  base=${base%/}
  command -v curl >/dev/null 2>&1 || { echo 'curl is required.' >&2; return 1; }
  if command -v sha256sum >/dev/null 2>&1; then hash=sha256sum
  elif command -v shasum >/dev/null 2>&1; then hash=shasum
  else echo 'sha256sum or shasum is required.' >&2; return 1; fi
  version=${STOOP_VERSION-}
  if [ -z "$version" ]; then
    if [ "$proto" = http ]; then
      echo 'STOOP_VERSION is required with the test server.' >&2; return 1
    fi
    version=$(curl -fsSL --proto '=https' --proto-redir '=https' https://api.github.com/repos/jwaldrip/stoop/releases/latest | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1) || version=
    if [ -z "$version" ]; then
      latest=$(curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' https://github.com/jwaldrip/stoop/releases/latest) || latest=
      version=${latest##*/}
    fi
  fi
  printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'Invalid or unavailable release version; set STOOP_VERSION=vX.Y.Z.' >&2; return 1; }
  archive="stoop-${version#v}-$target.tar.gz"
  if [ "$action" = dry-run ]; then
    printf 'Would download %s/%s/%s and SHA256SUMS, verify them, and install to %s/stoop.\n' "$base" "$version" "$archive" "$dir"
    return 0
  fi
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/stoop-install.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM
  curl -fsSL --proto "=$proto" --proto-redir "=$proto" "$base/$version/$archive" -o "$tmp/$archive"
  curl -fsSL --proto "=$proto" --proto-redir "=$proto" "$base/$version/SHA256SUMS" -o "$tmp/SHA256SUMS"
  expected=$(awk -v name="$archive" '$2 == name {print $1}' "$tmp/SHA256SUMS")
  printf '%s\n' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$' || { echo 'Missing or invalid checksum.' >&2; return 1; }
  if [ "$hash" = sha256sum ]; then actual=$(sha256sum "$tmp/$archive"); else actual=$(shasum -a 256 "$tmp/$archive"); fi
  actual=${actual%% *}
  [ "$actual" = "$expected" ] || { echo 'Checksum mismatch. Nothing installed.' >&2; return 1; }
  echo 'SHA-256 verified.'
  if command -v gh >/dev/null 2>&1; then
    gh attestation verify "$tmp/$archive" --repo jwaldrip/stoop || { echo 'Provenance verification failed. Nothing installed.' >&2; return 1; }
  else
    echo 'gh not found; provenance verification skipped.'
  fi
  tar -xzf "$tmp/$archive" -C "$tmp" stoop
  [ -f "$tmp/stoop" ] && [ ! -L "$tmp/stoop" ] || { echo 'Invalid archive.' >&2; return 1; }
  mkdir -p "$dir"
  staged=$(mktemp "$dir/.stoop.XXXXXX")
  trap 'rm -f "$staged"; rm -rf "$tmp"' EXIT HUP INT TERM
  cat "$tmp/stoop" > "$staged"
  chmod 755 "$staged"
  mv -f "$staged" "$dir/stoop"
  printf 'Installed %s/stoop\n' "$dir"
  case ":${PATH-}:" in *":$dir:"*) ;; *) printf 'Add %s to PATH.\n' "$dir";; esac
}
stoop_install "$@"
