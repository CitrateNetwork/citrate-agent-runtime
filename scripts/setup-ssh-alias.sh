#!/usr/bin/env bash
# REM-22 (2026-05-21 federation-split audit closeout):
# Configure the `github-citrate-chain` SSH host alias required to
# resolve `citrate-wallet-core` from `citrate-chain` at cargo-fetch
# time.
#
# Run this once on a fresh machine before `cargo build`. Idempotent —
# safe to re-run. Does NOT install any keys; it only edits
# ~/.ssh/config to map the alias to a key you specify.
#
# Usage:
#   ./scripts/setup-ssh-alias.sh                 # uses ~/.ssh/id_ed25519 by default
#   ./scripts/setup-ssh-alias.sh PATH_TO_KEY     # uses the specified key
#
# Audit reference:
#   citrate-agentile-archive/audits/2026-05/2026-05-19-federation-split-audit/06_REMEDIATION_PLAN.md (REM-22)

set -euo pipefail

KEY="${1:-$HOME/.ssh/id_ed25519}"
CONFIG="$HOME/.ssh/config"

if [ ! -f "$KEY" ]; then
    echo "ERROR: SSH private key not found at: $KEY"
    echo
    echo "Usage:"
    echo "  $0                       # uses ~/.ssh/id_ed25519 (your default GitHub key)"
    echo "  $0 PATH_TO_DEPLOY_KEY    # uses a citrate-chain-specific deploy key"
    echo
    echo "If you don't have a key, generate one with:"
    echo "  ssh-keygen -t ed25519 -f ~/.ssh/citrate_chain_deploy"
    echo "Then add its .pub to CitrateNetwork/citrate-chain → Settings → Deploy keys."
    exit 1
fi

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$CONFIG"
chmod 600 "$CONFIG"

# Idempotent: remove any existing github-citrate-chain block before appending
if grep -q "^Host github-citrate-chain\b" "$CONFIG" 2>/dev/null; then
    # Strip the existing block (Host ... up to the next blank line or next Host)
    python3 - "$CONFIG" <<'EOF'
import re, sys
path = sys.argv[1]
text = open(path).read()
# Remove the Host github-citrate-chain block plus its associated indented lines
pattern = re.compile(
    r'^Host github-citrate-chain\b.*?(?=^Host \b|\Z)',
    re.MULTILINE | re.DOTALL,
)
text = pattern.sub('', text)
# Tidy multiple blank lines
text = re.sub(r'\n{3,}', '\n\n', text)
open(path, 'w').write(text.rstrip() + '\n')
EOF
    echo "Removed existing github-citrate-chain block from $CONFIG"
fi

# Append the fresh block
cat >> "$CONFIG" <<EOF

# REM-22 / federation-split audit 2026-05-19
# citrate-agent-runtime needs to fetch citrate-wallet-core from
# CitrateNetwork/citrate-chain via this alias. Maps to:
#   $KEY
Host github-citrate-chain
    HostName github.com
    User git
    IdentityFile $KEY
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
EOF

echo "Configured SSH alias 'github-citrate-chain' → github.com using key:"
echo "  $KEY"
echo
echo "Verifying with: ssh -T git@github-citrate-chain"
echo "(this should print 'Hi <user>! You've successfully authenticated' if your key has chain access)"
echo

if ssh -T -o BatchMode=yes -o ConnectTimeout=10 git@github-citrate-chain 2>&1 | grep -q "successfully authenticated"; then
    echo "✓ SSH alias verified."
    echo "  You can now run: cargo build --release"
else
    echo "⚠ SSH connection succeeded but didn't return the 'successfully authenticated' marker."
    echo "  If this still fails on cargo build with 'Permission denied (publickey)',"
    echo "  ensure your key ($KEY.pub) is registered with citrate-chain as a deploy key,"
    echo "  or that your GitHub account has access to the repo."
fi
