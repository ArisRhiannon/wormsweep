# Contributing to wormsweep

Thanks for helping! wormsweep stays small: no runtime dependencies, no network access during scans, deterministic output.

## Dev setup

```bash
git clone https://github.com/ArisRhiannon/wormsweep && cd wormsweep
python -m unittest discover -s tests -v
```

## Pull requests

- Add a test for every behaviour change (one true positive and one near-miss for new rules).
- Update README and CHANGELOG.
- Short imperative commit subjects.
