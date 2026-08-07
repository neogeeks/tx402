# shellcheck shell=sh
#
# Normalise a local .env into the variable names and formats the live testnet suites
# actually read. SOURCE this, do not execute it:
#
#     . tools/live-env.sh
#     pnpm --filter tx402 exec vitest run test/base-sepolia.live.test.ts
#
# Why this exists (PLAN.md open item O33). Neither vitest nor pytest loads .env, and both
# live suites skip themselves when their variable is unset. A wrong name, a missing 0x, or
# a base58 Solana key therefore produces a green run that tested nothing, and the output is
# indistinguishable from an unfunded wallet. That failure cost a session once. This script
# accepts the forms people actually have and converts them, so the only way to end up
# skipped is to genuinely have no key.
#
# It prints what it resolved, never a value.

_tx402_env_file="${TX402_ENV_FILE:-.env}"

# zsh's `.` resolves a slashless argument against $PATH, not the working directory, so
# sourcing a bare ".env" fails with a confusing "no such file" even when it is right there.
# Forcing an explicit "./" makes the lookup a path in every POSIX shell.
case "$_tx402_env_file" in
  */*) ;;
  *) _tx402_env_file="./$_tx402_env_file" ;;
esac

if [ ! -f "$_tx402_env_file" ]; then
  echo "tx402: no $_tx402_env_file — copy .env.example and fill it in" >&2
else
  set -a
  # shellcheck disable=SC1090
  . "$_tx402_env_file"
  set +a
fi

# --- Base Sepolia: accept EVM_PRIVATE_KEY, with or without the 0x prefix ----------------
if [ -z "${TX402_BASE_SEPOLIA_PRIVATE_KEY:-}" ] && [ -n "${EVM_PRIVATE_KEY:-}" ]; then
  TX402_BASE_SEPOLIA_PRIVATE_KEY="$EVM_PRIVATE_KEY"
fi
if [ -n "${TX402_BASE_SEPOLIA_PRIVATE_KEY:-}" ]; then
  # `${var#0x}` strips at most one leading 0x, so re-prefixing is idempotent.
  TX402_BASE_SEPOLIA_PRIVATE_KEY="0x${TX402_BASE_SEPOLIA_PRIVATE_KEY#0x}"
  export TX402_BASE_SEPOLIA_PRIVATE_KEY
fi

# --- Solana Devnet: accept SOLANA_PRIVATE_KEY as base58 and convert to the byte array ----
if [ -z "${TX402_SOLANA_DEVNET_KEYPAIR:-}" ] && [ -n "${SOLANA_PRIVATE_KEY:-}" ]; then
  TX402_SOLANA_DEVNET_KEYPAIR="$SOLANA_PRIVATE_KEY"
fi
if [ -n "${TX402_SOLANA_DEVNET_KEYPAIR:-}" ]; then
  case "$TX402_SOLANA_DEVNET_KEYPAIR" in
    \[*) ;; # already the 64-byte JSON array the suite wants
    *)
      # Passed through the environment rather than argv so it never appears in `ps`.
      TX402_SOLANA_DEVNET_KEYPAIR="$(
        TX402_B58_IN="$TX402_SOLANA_DEVNET_KEYPAIR" node tools/b58-keypair.js
      )" || echo "tx402: could not decode SOLANA_PRIVATE_KEY as base58" >&2
      ;;
  esac
  export TX402_SOLANA_DEVNET_KEYPAIR
fi

export TX402_FACILITATOR_URL="${TX402_FACILITATOR_URL:-https://x402.org/facilitator}"

# Report resolution status only. A length or a prefix is not a secret; a value is.
printf 'tx402 live env:\n'
printf '  TX402_BASE_SEPOLIA_PRIVATE_KEY  %s\n' \
  "$(if [ -n "${TX402_BASE_SEPOLIA_PRIVATE_KEY:-}" ]; then
    echo "set (${#TX402_BASE_SEPOLIA_PRIVATE_KEY} chars, 0x-prefixed)"
  else echo 'UNSET — Base Sepolia suite will skip'; fi)"
printf '  TX402_SOLANA_DEVNET_KEYPAIR     %s\n' \
  "$(if [ -n "${TX402_SOLANA_DEVNET_KEYPAIR:-}" ]; then
    echo "set (JSON array form)"
  else echo 'UNSET — Solana Devnet suite will skip'; fi)"
printf '  TX402_FACILITATOR_URL           %s\n' "$TX402_FACILITATOR_URL"

unset _tx402_env_file
