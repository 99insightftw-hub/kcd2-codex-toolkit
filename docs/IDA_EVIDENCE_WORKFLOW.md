# Bring-your-own IDA evidence workflow

The repository intentionally does not include an IDA database or WHGame binary.

1. Hash the installed `WHGame.dll` and record the game build.
2. Create or obtain an IDA database from your own legally installed files.
3. Never work on the only copy. Make a disposable project-private copy and verify its hash before opening it.
4. Use an IDA version compatible with the database.
5. Record module-relative RVAs, function-boundary evidence, xrefs, and confidence. Do not publish proprietary bytes or unrestricted decompilation.
6. Treat every result as version-bound. If the installed module hash changes, revalidate before reusing an RVA, signature, offset, type, or vtable.
7. Publish only sanitized derived facts and reproducible query metadata.

The `kcd2-native-research` skill routes native questions through static evidence first, then a verified disposable IDA/Ghidra database, and only then bounded runtime observation when needed.
