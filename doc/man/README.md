# Carbonado manual pages

Roff man pages for the `carbonado` CLI, generated from the clap schema in `src/cli_app.rs`.

## Regenerate

```bash
just gen-man
```

This writes `carbonado.1`, `carbonado-encode.1`, `carbonado-decode.1`, `carbonado-key.1`, and nested `carbonado-key-*.1` files into this directory.

## Install locally

```bash
just install-man
```

Installs into `~/.local/share/man/man1` by default. Override the destination:

```bash
MANPREFIX=/usr/local just install-man
```

After installation, run `mandb` (Linux) or `makewhatis` (some BSDs) if your system does not pick up new pages automatically.

## View without installing

```bash
man -l doc/man/carbonado.1
man -l doc/man/carbonado-encode.1
```