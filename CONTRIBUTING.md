# Contributing

The most useful contribution is a report from a real device: which model, what the plan showed,
what worked, what had to be kept. File it with the
[device report form](https://github.com/DoAideAi/DoAide-Debloat/issues/new?template=device-report.yml);
it asks exactly the questions a profile line needs and refuses identifiers. The second most useful
is a profile line.

## Adding or changing a profile line

Profiles live in `data/profiles/<oem>.txt`, one package per line:

```
com.vendor.package | category | one-line note of what it is and why it is listed
```

| Category | Meaning |
|---|---|
| `ads` | serves ads or sponsored content |
| `telemetry` | usage profiling, analytics, background reporting |
| `junk` | preloaded stubs, duplicates and promo apps nobody asked for |
| `ask` | depends on the owner (a payment app, a cloud, a browser, a game launcher): only disabled when they name it |

Rules the validator enforces (`python3 tools/validate_lists.py --uad`):

* no package listed twice across profiles;
* nothing that matches `data/never-disable.txt`;
* every non-`ask` entry is Recommended or Advanced in the community UAD list, or unknown to it
  (then say in the note where the name came from). Expert must be `ask`; Unsafe is rejected.

When in doubt, use `ask`. A wrong `junk` line costs someone an app they use; a wrong `ask` line
costs one question.

## Before a pull request

```sh
python3 -m unittest discover -s tests -v
python3 tools/validate_lists.py --uad
```

## What never goes into the repository

Serial numbers, IMEIs, phone numbers, account emails, Wi-Fi names, and the contents of
`backups/`. Reports should say "Redmi Note 13, HyperOS 1.0.4, India", not paste a backup file.

## Adding a never-disable pattern

`data/never-disable.txt` takes glob patterns. Add one when a package is known to boot-loop,
lock or brick a device if disabled, with a comment saying why. Removing one needs a device
report showing it is safe.
