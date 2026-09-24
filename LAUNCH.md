# Launch checklist

## Done in repo

- [x] Launch-ready homepage (hero, litter, parents, alumni, pricing, transport, FAQ, early list)
- [x] Initial git commit on `master`
- [x] Ops kit under `ops/`
- [x] Internal slideshow kept out of public nav

## Before go-live

- [ ] Formspree endpoint in `data/litter.js` receives a real test submission
- [ ] Swap Litter 2 group photo into `currentLitter.image` when you have a clean shot
- [ ] Confirm Facebook URL
- [ ] Mobile check: hero, litter, form, pricing, transport

## Deploy (GitHub Pages) — needs your GitHub login

`gh` is not installed on this machine yet. From the project folder:

```bash
git remote add origin git@github.com:YOUR_USER/sandies-doodles.git
git push -u origin master
```

Then: GitHub → Settings → Pages → Source: Deploy from branch `master` / `/ (root)`.

After the URL is live:

- [ ] Paste it into `ops/auto-reply.txt`
- [ ] Optional: custom domain + `CNAME`
- [ ] Pin Facebook post with site link

## Not on the public site (by design)

- `slideshow.html` — internal ops
- `ops/` — trackers, agreements, policies
