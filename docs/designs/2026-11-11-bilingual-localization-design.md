# OWBM bilingual localization design

**Status:** approved for implementation  
**Date:** 2026-11-11

## Goals

- Make the OWBM command-line and interactive interfaces usable in Russian and English.
- Keep Russian as the default and preserve existing command behavior.
- Add English documentation without removing or moving the existing Russian documentation.
- Keep the profile README bilingual, with English first and Russian second.

## Language selection

For the OWBM application, the effective language is selected in this order:

1. `--lang ru|en` on the current invocation.
2. `general.language` in the configuration file.
3. Russian (`ru`) when neither is set.

A command-line override is temporary and does not modify the saved configuration. Changing the language in the interactive settings menu saves it and applies it to subsequent screens and operations in that session. CLI help uses an explicit `--lang` override when present; otherwise it uses a valid configured language, falling back to Russian if configuration cannot be read.

The standalone installer runs before application configuration is available. It selects English for an English system locale (`LC_ALL`, then `LC_MESSAGES`, then `LANG`) and otherwise falls back to Russian.

## Localization architecture and scope

Add a dependency-free, package-local translation catalog addressed by stable message keys. Application code requests translated messages through this catalog rather than embedding language branches at output sites. Tests must detect missing English entries. Runtime fallback for a missing translation is Russian so an incomplete catalog cannot prevent an operation from running.

Localize application-authored human-facing text, including:

- CLI help and command descriptions;
- interactive menu labels, prompts, confirmations, and settings;
- operation progress, plans, summaries, warnings, and diagnostics;
- errors, their explanations and remediation guidance;
- installer messages.

Do not translate device-supplied text, user-provided values, paths, package names, or other data. The selected language does not alter command names, option names, stable error codes, JSON property names, exit codes, or archive schemas. Human-readable JSON message values follow the selected language. Text already stored in an archive or returned by a device remains as stored/received.

## Documentation and profile

- Keep the current Russian `README.md` content and Russian files in `docs/`.
- Make the project README bilingual, English first and Russian second, with links to language-appropriate documentation.
- Add English counterparts for each existing user-facing document under `docs/en/`; generate the English error reference from the same bilingual error catalog as the Russian reference.
- Keep `config.example.toml` understandable in both languages.
- Keep the public profile README bilingual, English first and Russian second. Do not change the separate GitHub bio field.

## Compatibility and verification

This work does not change backup/restore behavior, CLI option names, error-code meanings, JSON structure, or archive formats. Existing Russian remains the default. Tests will cover language selection and precedence, representative CLI/menu/error output in both languages, catalog completeness, installer locale selection, generated documentation, and existing behavior. The complete test suite and zipapp build must pass before publishing any release artifact; release publication is a separate step.
