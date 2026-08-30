# Contributing

Thanks for helping make auditchain solid. A few ground rules:

- Keep the library dependency-free (runtime). If something needs a dependency,
  it belongs in an optional extra, not in core.
- Any change to serialization or hashing **must not** break existing logs: add a
  regression test with a fixed vector first.
- Run before opening a PR:

  ```bash
  python -m pytest
  ruff check src tests
  ruff format --check src tests
  ```

- New features ship with tests and an honest note in the README (limitations included).
