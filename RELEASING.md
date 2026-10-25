# Release plan

SiftFetch is pure Python, so there is nothing to compile. Today it installs
from a clone (`pip install -e .`, see [SETUP.md](SETUP.md)). This file is the
plan for publishing it as a package on PyPI, so that users can run
`pip install siftfetch` or `uv tool install siftfetch` instead.

Nothing here is built yet. When a step is done, move it out of this file and
into the docs it changes.

## When to release

v0.1.0 ships when all of these hold:

- [ ] The maintainer has used it as their live guard for a few weeks, and
      the fixes that turned up are in.
- [ ] `siftfetch init` and `siftfetch doctor` exist (see SETUP's
      [Planned](SETUP.md#planned) list). Without them, a package install still
      means the whole manual setup, and the clone gives the same result.
- [ ] CI passes on every OS in the matrix, or the docs and classifiers name
      only the systems that pass.
- [ ] The README and SETUP describe the package install, not the clone.

## What the package needs first

- **Templates inside the package.** `examples/` is not in the wheel.
  `siftfetch init` needs the example policy files (default, locked-down and
  relaxed) as package data, so it can write them without a clone.
- **One command.** Add a `siftfetch` entry point with `init`, `doctor`,
  `hook` and `server` subcommands. Keep `siftfetch-hook` and
  `siftfetch-server` for settings that already use them.
- **Stable hook command.** The settings line should not depend on where
  Python lives. With `uv tool install`, `siftfetch hook` is on the PATH, so
  `settings.json` can call it by name. SETUP must say what happens if the
  PATH is wrong: the hook can't start, and Claude Code treats that as a
  non-blocking error.
- **Version in one place.** Read `__version__` from the package metadata,
  not a second copy.
- **Checks in CI.** Build the sdist and wheel, run `twine check`, install the
  wheel into a clean environment and run the tests against it, not against the
  source tree. That catches files missing from the package.

## How a release is made

1. Bump `version` in `pyproject.toml` and add a `CHANGELOG.md` entry.
2. Commit, then tag `vX.Y.Z` and push the tag.
3. A `release.yml` workflow, started by the tag:
   - builds with `python -m build`;
   - publishes to TestPyPI, installs from there and runs a smoke test
     (`siftfetch doctor` on a throwaway policy folder);
   - publishes to PyPI with trusted publishing (OIDC). No API token is
     stored in the repository or its secrets;
   - creates a GitHub release with the built files and the changelog entry.
4. The publish job runs in a protected GitHub environment that needs the
   owner's approval.

The PyPI name is claimed on the first upload. Set up the trusted publisher on
PyPI and TestPyPI before the first tag.

## Versioning

- Semantic versioning. Before 1.0, a minor bump (0.2.0) may change policy
  files or settings; the changelog says how to move over.
- The policy file format is the public interface. A change to it is listed
  in the changelog with the old and new form side by side.
- TOML policy files (planned) arrive with a reader for the JSON files, and
  `doctor` says which format it found.

## After the first release

- **injection-gauntlet** depends on a version range (`siftfetch>=0.1,<0.2`)
  instead of a git URL.
- **The maintainer's own install** moves from a clone to
  `uv tool install siftfetch`, upgraded with `uv tool upgrade siftfetch`,
  so daily use runs exactly what users get. A clone stays for testing
  changes before they are released.
- **Security fixes** get a patch release and a GitHub security advisory.
