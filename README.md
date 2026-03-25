# Claude Code WhatsApp Channel

Connect WhatsApp to your Claude Code session via the MCP channel protocol. Send a message on WhatsApp, get a response from Claude — with full filesystem, tool, and context access.

Built on [Baileys](https://github.com/WhiskeySockets/Baileys) (WhatsApp Web API) and the same MCP channel architecture as the official [Telegram plugin](https://github.com/anthropics/claude-plugins-official/tree/main/external_plugins/telegram).

## How it works

This is an MCP server that:
1. Connects to WhatsApp as a linked device (QR code pairing)
2. Listens for incoming messages via Baileys WebSocket
3. Pushes them into your Claude Code session as `notifications/claude/channel`
4. Exposes `reply`, `react`, `edit_message`, and `download_attachment` tools

## Prerequisites

- [Bun](https://bun.sh) — `curl -fsSL https://bun.sh/install | bash`
- Claude Code v2.1.80+

## Setup

**1. Clone and install**

```sh
git clone https://github.com/andrewftadros/claude-whatsapp-channel.git
cd claude-whatsapp-channel
bun install
```

**2. Register as an MCP server**

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "whatsapp": {
      "command": "bun",
      "args": ["run", "/path/to/claude-whatsapp-channel/server.ts"],
      "env": {}
    }
  }
}
```

**3. Launch Claude Code with the channel**

```sh
claude --dangerously-load-development-channels server:whatsapp
```

**4. Pair with WhatsApp**

On first launch, a QR code is saved to `~/.claude/channels/whatsapp/qr.txt`. Generate a scannable image:

```sh
pip3 install qrcode[pil]
python3 -c "
import qrcode
with open('$HOME/.claude/channels/whatsapp/qr.txt') as f:
    img = qrcode.make(f.read().strip())
    img.save('qr.png')
"
```

Scan `qr.png` with WhatsApp > Linked Devices > Link a Device.

**Alternative: Pairing code** — set `WHATSAPP_PHONE=+1234567890` in the env to get an 8-digit code instead of QR.

**5. Pair a sender**

Have someone message you on WhatsApp. The bot replies with a 6-character pairing code. Approve it by editing `~/.claude/channels/whatsapp/access.json`:

```json
{
  "dmPolicy": "allowlist",
  "allowFrom": ["<senderId from pending>"],
  "groups": {},
  "pending": {}
}
```

Then create the approval file:
```sh
mkdir -p ~/.claude/channels/whatsapp/approved
echo "<chatJid>" > ~/.claude/channels/whatsapp/approved/<senderId>
```

The bot sends a confirmation message and future messages are delivered to Claude.

## Tools exposed to Claude

| Tool | Purpose |
| --- | --- |
| `reply` | Send text + file attachments to a chat. Images send as photos; other types as documents. |
| `react` | Add an emoji reaction to a message. |
| `edit_message` | Edit a previously sent message. |
| `download_attachment` | Download media from a received message to local disk. |

## Access control

State lives in `~/.claude/channels/whatsapp/access.json`:

- `dmPolicy`: `pairing` (default), `allowlist`, or `disabled`
- `allowFrom`: array of sender IDs (phone numbers or LIDs)
- `groups`: group JID policies with optional mention requirements
- `pending`: auto-managed pairing codes (1hr expiry, max 3)

## Architecture

```
WhatsApp Phone
    |
    | (WhatsApp Web protocol)
    v
Baileys WebSocket ──> server.ts (MCP server)
    |                      |
    | messages.upsert      | notifications/claude/channel
    v                      v
 gate() ──────────> Claude Code Session
                           |
                           | reply/react/edit tools
                           v
                    server.ts ──> Baileys ──> WhatsApp
```

## Key differences from Telegram plugin

| | Telegram | WhatsApp |
|---|---|---|
| Auth | Bot token from BotFather | QR code / pairing code |
| Connection | HTTP long-polling (grammY) | WebSocket (Baileys) |
| Session | Stateless (token-based) | Persistent (linked device) |
| JID format | Numeric user IDs | `@s.whatsapp.net` or `@lid` |
| API | Official Bot API | Reverse-engineered (unofficial) |
| History | None (Bot API limitation) | None (same limitation) |

## Known limitations

- **Unofficial API**: Baileys reverse-engineers WhatsApp Web. Meta could break it at any time.
- **QR expiry**: QR codes expire in ~20 seconds. Use pairing code mode for easier setup.
- **Self-messages**: Messages you send to yourself are marked `fromMe` and skipped. Test with another account.
- **Skills not auto-loaded**: When using `--dangerously-load-development-channels`, skills aren't registered. Manage access by editing `access.json` directly.
- **No history**: Like Telegram, WhatsApp's protocol exposes no message history or search.

## License

MIT
