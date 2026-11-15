# Host this site with Cloudflare Pages (private GitHub repo)

GitHub Pages on the **Free** plan needs a **public** repository.  
**Cloudflare Pages** deploys from a **private** GitHub repo for free, gives you HTTPS, a custom domain, and (optionally) login-gated access.

The static site lives in this `docs/` folder. No build step.

---

## A. Deploy from your private repo

1. Make the GitHub repo private (if it is not already):  
   **Settings → General → Danger Zone → Change repository visibility → Private**.
2. In [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
3. Install / authorize the **Cloudflare Workers & Pages** GitHub App on `vladjoh/RedTeam` (private repos are supported).
4. Build settings:

   | Setting | Value |
   |---------|--------|
   | Production branch | `main` |
   | Framework preset | None |
   | Build command | `exit 0` |
   | Build output directory | `docs` |
   | Root directory | `/` (leave default) |

5. **Save and Deploy**. You get a URL like `https://<project>.pages.dev`.

Every push to `main` redeploys production. Other branches get preview URLs.

---

## B. Custom domain

1. Open the Pages project → **Custom domains** → **Set up a custom domain**.
2. Enter your domain (apex or `www`).
3. DNS:

   - **If the domain is already on Cloudflare:** accept the DNS record Cloudflare suggests (usually a CNAME to `<project>.pages.dev`).
   - **If DNS is elsewhere:** add a `CNAME` for the hostname → `<project>.pages.dev`  
     (apex domains: use Cloudflare DNS, or a flattening/ALIAS CNAME at your registrar).

4. Wait until the domain status is **Active** (often minutes; can take longer). HTTPS is provisioned automatically.

Official docs: [Custom domains](https://developers.cloudflare.com/pages/configuration/custom-domains/).

---

## C. Optional — make the *website* private too

A private **repo** does not make the **site** private. By default anyone with the URL can open it.

To require login (email OTP, Google, GitHub, etc.):

1. Enable **Cloudflare Zero Trust** (free tier is enough for light use).
2. Pages project → **Settings** → enable the **Access policy** for preview deployments.
3. Protect production:
   - Zero Trust → **Access** → **Applications** → **Add** → **Self-hosted**
   - Add hostnames for **both**:
     - `<project>.pages.dev`
     - your custom domain
   - Allow policy: e.g. emails ending in your company domain, or specific addresses.
4. If you only protect the custom domain and leave `pages.dev` open, the site stays reachable on `pages.dev`.

Docs: [Pages + Access](https://developers.cloudflare.com/pages/platform/known-issues/#enable-access-on-your-pagesdev-domain).

---

## D. Turn off GitHub Pages

If GitHub Pages was enabled on this repo:

1. **Settings → Pages** → remove the custom domain (if any).
2. Set source to **None** / disable Pages so only Cloudflare serves the site.

---

## Local preview

```bash
python3 -m http.server 8765 --directory docs
```

Open `http://127.0.0.1:8765`.
