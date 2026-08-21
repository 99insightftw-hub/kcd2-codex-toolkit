# KCD2 Codex Toolkit

An open-source, evidence-first Codex toolkit for Kingdom Come: Deliverance II mod work.

It combines:

- read-only mod inspection and conflict analysis;
- deterministic candidate building and package validation;
- guarded install and exact-receipt rollback workflows;
- local index adapters for source, path, localization, table, and provider research;
- version-bound native research and bounded passive probe workflows.

## Safety boundary

This repository contains tooling and schemas only. It does **not** contain game binaries, extracted game data, an IDA database, Ghidra projects, decompiled game code, private indexes, saves, logs, API keys, or personal paths. You must supply your own legally obtained KCD2 installation and analysis inputs.

The toolkit does not grant authority to launch or close the game, modify a live process, install a candidate, consume an approval, or overwrite shared game state. The build/install/rollback skills apply their own preflight and receipt gates.

## Install in Codex

Clone the repository, then add its root as a local Codex plugin or marketplace source. The default plugin exposes seven progressively loaded skills and starts **no background MCP or Python processes**.

Requirements:

- Windows 10/11
- Python 3.11 or newer
- PowerShell 7 or Windows PowerShell 5.1
- a legally installed copy of KCD2 for game-specific inspection

The two read-only MCP servers are advanced opt-in components. Their reference configuration is stored at `examples/optional-mcp.json`; enable only the server needed by a dedicated task and disable it afterward. The launchers use the bundled Python source under `runtime/src` and do not download dependencies or game content.

## Performance model

- Default installation: skills only; no persistent helper processes.
- Mod inspection task: optionally enable only `kcd2-mod-build-deploy`.
- Native probe task: optionally enable only `kcd2-native-probes`.
- Ordinary skills load their detailed instructions only when the task matches them.
- Large schema and runtime directories remain inert until a selected tool imports or reads them.

Do not globally enable both MCP servers. Codex may otherwise start a separate Python helper for every active task, increasing startup latency and memory use.

## Skills

- `analyze-kcd2-mod`: bounded read-only package, conflict, winner, and lifecycle analysis
- `build-kcd2-mod`: deterministic clean-staging candidate builds
- `install-kcd2-mod`: guarded exact-target deployment
- `rollback-kcd2-mod`: receipt-bound restoration
- `kcd2-index-research`: research routing through a user-owned local KCD2 index
- `kcd2-native-research`: evidence-driven WHGame/Ghidra/IDA/x64dbg methodology
- `capture-kcd2-native-probes`: bounded passive native probe planning and validation

## IDA and native evidence

The toolkit never redistributes an `.i64` database. See [docs/IDA_EVIDENCE_WORKFLOW.md](docs/IDA_EVIDENCE_WORKFLOW.md) for the safe bring-your-own-database workflow and fingerprint rules.

## Local index

The private indexed corpus is not bundled. The `kcd2_index_adapter` package is included so users can connect Codex to an index built locally from files they own. A partial index miss is not proof that something does not exist.

## Development

```powershell
python -m unittest discover -s tests -v
python C:\path\to\plugin-creator\scripts\validate_plugin.py .
```

Before publishing, `tests/test_release_safety.py` rejects proprietary payload extensions, private machine paths, secrets, caches, and generated analysis databases.

## License

Apache-2.0. Kingdom Come: Deliverance II and related names are trademarks of their respective owners. This project is unofficial and is not endorsed by Warhorse Studios.
