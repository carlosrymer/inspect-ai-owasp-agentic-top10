# How this site actually deploys

**Live: https://carlosrymer.github.io/inspect-ai-owasp-agentic-top10/**

GitHub Pages serves the **`gh-pages` branch**, which holds the contents of `site/` at its
root plus a `.nojekyll` marker. `scripts/publish_site.sh` builds that branch and force-pushes
it. `main` keeps the source, the committed `.eval` logs and the exported JSON.

```bash
uv run python scripts/export_results.py --log-dir logs --out-dir site/data
./scripts/publish_site.sh
```

## Why not GitHub Actions?

The intended mechanism is the workflow parked in this directory as
`github-pages-workflow.yml` — `actions/configure-pages@v5` with `enablement: true`, then
`upload-pages-artifact@v3` and `deploy-pages@v4`. Two things blocked it in the environment
this repo was built in:

1. **No `workflow` OAuth scope on the push credentials.** Any push whose diff touches
   `.github/workflows/**` is rejected by GitHub:
   `refusing to allow an OAuth App to create or update workflow ... without workflow scope`.
2. **The REST Pages endpoints are unreachable.** `GET`/`POST /repos/{owner}/{repo}/pages`
   return `403 Access to this GitHub API path is not permitted through this proxy`, so Pages
   could not be configured through the API either.

Pushing a `gh-pages` branch needs neither: GitHub auto-enables Pages for the repository when
that branch appears. Since the site is fully static — no bundler, no build step, no external
requests at all — publishing the directory to a branch produces exactly the same artifact the
workflow would have uploaded.

To switch to Actions later, copy `github-pages-workflow.yml` to `.github/workflows/deploy.yml`
and push with a `workflow`-scoped token, then set Pages' source back to "GitHub Actions".
