# Deploy to sandiesdoodles.com

Recovered from Aug 11 takeover + earlier Litter 2 site work.

## What’s already true

| Item | Value |
|------|--------|
| Live domain | **https://sandiesdoodles.com/** (note the **s** — `sandiedoodles.com` does not resolve) |
| Hosting | GitHub Pages |
| Repo | **https://github.com/sandiesdoodles/landing** |
| Formspree | `https://formspree.io/f/xykpbwkg` (already in `data/litter.js`) |
| Local build | `~/Projects/sandies-doodles` (Litter 2 cards live) |

Live site still serves the **old Litter 1** build. Cutover = replace that repo’s `main` with this folder.

## Blocker (same as Aug)

No GitHub write auth on this machine (`gh` not logged in). Need the account that owns `sandiesdoodles/landing`, or write access granted.

## Safe cutover

1. Snapshot current live `main` (tag or note commit SHA) for rollback.
2. Branch `litter-2-launch` from `main` (or push this tree as that branch).
3. Publish **public site files only** at repo root:
   - `index.html`, `thank-you.html`, `app.js`, `styles.css`
   - `data/`, `assets/` (litter2 cards, parents, alumni, brand)
   - `CNAME` → `sandiesdoodles.com`
   - `.nojekyll`
4. **Do not** push `ops/Abby_Litter_2/` media dumps to the public repo (huge + private).
5. Draft PR → smoke check homepage / cards / form / mobile → merge to `main`.
6. Confirm https://sandiesdoodles.com shows Litter 2 cards in order: Cypress → Oakley → Delilah → Violet → Cedar → Ginger → Lotus → Meadow.
7. One Formspree early-list test.
8. Paste live URL into `ops/auto-reply.txt`; pin Facebook.

## Rollback

Revert the merge commit (or reset Pages branch to the pre-launch SHA).

## One-liner once auth works

```bash
cd ~/Projects/sandies-doodles
# install/login: sudo apt install gh && gh auth login
git remote add origin https://github.com/sandiesdoodles/landing.git   # if missing
# Prefer a clean public tree, then:
git push -u origin HEAD:litter-2-launch
# open PR → merge to main after smoke check
```

Force-push to `main` only if you explicitly want an instant overwrite (no PR).
