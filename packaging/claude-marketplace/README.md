# Claude Code plugin marketplace — `armur-claude-plugins`

This directory holds the **marketplace manifest** (`marketplace.json`) for
distributing the Trishul Claude Code plugin. It lets users run:

```
/plugin marketplace add Armur-Ai/claude-plugins
/plugin install trishul@armur-claude-plugins
```

## Nothing is published from this repo

These files are **prepared only**. No GitHub repo is created and nothing is
published here — this is local-first packaging that lives in the Trishul tree
until the owner chooses to ship it.

## Owner / D-HUMAN steps (not done here)

The following are deliberately left to the repository owner:

1. **Create the marketplace repo** `Armur-Ai/claude-plugins` on GitHub.
2. **Copy the plugin into it.** Place the contents of this repo's
   `plugins/claude-code/` at `plugins/trishul/` in the marketplace repo so the
   layout matches `marketplace.json`:

   ```
   claude-plugins/
   ├── .claude-plugin/
   │   └── marketplace.json        # copy of this file
   └── plugins/
       └── trishul/                # copy of Trishul/plugins/claude-code/
           ├── .claude-plugin/plugin.json
           ├── .mcp.json
           ├── hooks/hooks.json
           ├── commands/
           └── README.md
   ```

   Note: `marketplace.json` must live at `.claude-plugin/marketplace.json` in the
   marketplace repo root. The copy kept here (`packaging/claude-marketplace/`) is
   the source of truth to copy from.

   The `source` field (`"./plugins/trishul"`) is a path **relative to the
   marketplace repo root**. Alternatively, the owner may point `source` at the
   Trishul repo directly (e.g. a `github` source) to avoid duplicating files —
   adjust the manifest accordingly.
3. **(Optional) Submit** the marketplace to any public plugin directory.

Until those steps are taken by the owner (D-HUMAN), this manifest is inert.
