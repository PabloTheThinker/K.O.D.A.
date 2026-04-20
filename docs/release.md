# Release runbook (PyPI + GitHub Pages)

Operational notes for cutting a K.O.D.A. release — one-time PyPI setup
plus the per-release checklist.

## One-time: publishing `koda-security` on PyPI Works off a phone or
laptop. ~10 minutes if nothing goes sideways.

We're using **Trusted Publishing (OIDC)**, so no API tokens are ever
stored in GitHub — PyPI validates each upload against the workflow
directly. Modern, safer, less to rotate.

---

## 1. Create your PyPI account

1. Open [https://pypi.org/account/register/](https://pypi.org/account/register/)
2. Use any email you control (Mr.Navarro@protonmail.com is fine)
3. Username suggestion: `pablothethinker` (matches GitHub/X)
4. Confirm your email via the verification link

## 2. Enable 2FA (required for uploads)

1. Open [https://pypi.org/manage/account/](https://pypi.org/manage/account/)
2. Scroll to **"Two factor authentication (2FA)"**
3. Add a TOTP app (Aegis / Google Authenticator / 1Password) **or** a
   hardware key (WebAuthn)
4. Save the recovery codes in a password manager — losing both the TOTP
   device and recovery codes locks you out permanently

## 3. Add a pending Trusted Publisher

This tells PyPI "when `PabloTheThinker/K.O.D.A.` runs `release.yml` from
the `pypi` environment, trust it to publish `koda-security`." Has to be
configured BEFORE the first upload.

1. Open [https://pypi.org/manage/account/publishing/](https://pypi.org/manage/account/publishing/)
2. Scroll to **"Add a new pending publisher"**
3. Fill exactly:
   - **PyPI Project Name:** `koda-security`
   - **Owner:** `PabloTheThinker`
   - **Repository name:** `K.O.D.A.`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
4. Click **Add**

## 4. Create the `pypi` environment on GitHub

1. Open [https://github.com/PabloTheThinker/K.O.D.A./settings/environments](https://github.com/PabloTheThinker/K.O.D.A./settings/environments)
2. Click **New environment**
3. Name: `pypi` (exactly — must match the workflow)
4. Optional but recommended:
   - **Required reviewers:** add yourself. PyPI uploads will pause for
     your approval before running. Belt-and-suspenders.
   - **Deployment branches and tags:** restrict to tags matching `v*`
5. Save

## 5. Enable GitHub Pages (for the docs site)

1. Open [https://github.com/PabloTheThinker/K.O.D.A./settings/pages](https://github.com/PabloTheThinker/K.O.D.A./settings/pages)
2. Under **Build and deployment → Source**, pick **GitHub Actions**
3. Save. Docs will deploy to
   `https://pablothethinker.github.io/K.O.D.A./` on the next push to
   `main` that touches `docs/` or `mkdocs.yml`.

## 6. Cut the first release

Back on your dev box:

```bash
cd ~/koda
git pull
git tag -s v0.5.0 -m "K.O.D.A. v0.5.0"   # -s signs if you have GPG set up; plain -a is fine otherwise
git push origin v0.5.0
```

The `release.yml` workflow will:

1. Build wheel + sdist
2. Run `twine check`
3. Pause for your approval (if you set required reviewers)
4. Publish to PyPI via OIDC
5. Create a GitHub Release with changelog-extracted notes

Watch it at
[https://github.com/PabloTheThinker/K.O.D.A./actions](https://github.com/PabloTheThinker/K.O.D.A./actions).

## 7. Verify

After the workflow finishes:

```bash
pipx install koda-security
koda --version       # should print: koda 0.5.0
koda doctor
```

Project page: [https://pypi.org/project/koda-security/](https://pypi.org/project/koda-security/)

---

## Gotchas

- **Workflow name must match exactly.** If you rename `release.yml`, the
  PyPI trusted publisher stops trusting it. Update both.
- **Environment name is case-sensitive.** `pypi` ≠ `PyPI`.
- **First publish creates the project.** You don't need to "register" the
  name separately — the first successful OIDC upload claims it.
- **If someone squats `koda-security` before you publish**, rename in
  `pyproject.toml` (`name = "..."`) and update the pending publisher on
  PyPI to match.

## What NOT to do

- Don't generate a PyPI API token and paste it into GitHub. Trusted
  Publishing is the whole point — no long-lived secrets.
- Don't `pip install .` and then `twine upload` from your laptop. The
  workflow is the only approved publish path; manual uploads bypass the
  audit trail.
