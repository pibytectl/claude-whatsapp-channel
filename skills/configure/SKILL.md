---
name: configure
description: Set up the WhatsApp channel — review connection status and access policy. Use when the user asks to configure WhatsApp, asks "how do I set this up" or "who can reach me," or wants to check channel status.
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Bash(ls *)
  - Bash(mkdir *)
---

# /whatsapp:configure — WhatsApp Channel Setup

Reviews the WhatsApp channel state and orients the user on access policy.
Unlike Telegram (which uses a bot token), WhatsApp uses QR-code pairing
managed by Baileys — there is no token to configure.

Arguments passed: `$ARGUMENTS`

---

## Dispatch on arguments

### No args — status and guidance

Read state files and give the user a complete picture:

1. **Connection** — check `~/.claude/channels/whatsapp/auth/` for session
   files. If the directory has `creds.json`, the session is paired. If empty
   or missing, no WhatsApp account is linked yet.

2. **Access** — read `~/.claude/channels/whatsapp/access.json` (missing file
   = defaults: `dmPolicy: "pairing"`, empty allowlist). Show:
   - DM policy and what it means in one line
   - Allowed senders: count, and list phone numbers or IDs
   - Pending pairings: count, with codes if any

3. **What next** — end with a concrete next step based on state:
   - No session → *"Launch Claude Code with
     `--dangerously-load-development-channels ~/claude-whatsapp-channel`.
     A QR code will appear in the terminal — scan it with WhatsApp on your
     phone."*
   - Session exists, policy is pairing, nobody allowed → *"Send a message to
     yourself (or have someone DM you on WhatsApp). The bot replies with a
     pairing code; approve with `/whatsapp:access pair <code>`."*
   - Session exists, someone allowed → *"Ready. Messages from allowed senders
     will reach the assistant."*

**Push toward lockdown — always.** Once IDs are captured, recommend switching
to `allowlist` policy.

### `clear` — remove the session

Delete `~/.claude/channels/whatsapp/auth/` contents to unpair. Warn the user
they'll need to re-scan the QR code.

---

## Implementation notes

- The channels dir might not exist if the server hasn't run yet. Missing file
  = not configured, not an error.
- Session changes (re-pairing) need a session restart. Say so.
- `access.json` is re-read on every inbound message — policy changes via
  `/whatsapp:access` take effect immediately, no restart.
