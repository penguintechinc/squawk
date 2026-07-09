# Cloudflare Pages Configuration

## Correct Build Settings

In your Cloudflare Pages dashboard, configure:

### Build Configuration
- **Framework preset**: Next.js (Static HTML Export)
- **Build command**: `npm run build`
- **Build output directory**: `out`
- **Root directory (advanced)**: `website` (if deploying from repo root)

### Alternative: Deploy from repository root
If you want to deploy from the repository root instead:
- **Build command**: `cd website && npm install && npm run build`
- **Build output directory**: `website/out`
- **Root directory (advanced)**: Leave empty

## Troubleshooting

1. **404 on index.html**: Make sure build output directory is set to `out` (not `website/out` if root directory is `website`)
2. **Build fails**: Ensure Node.js version is 18+ in environment variables
3. **Missing files**: Check that `npm run build` generates files in the `out` directory

## Files Generated
After successful build, the `out` directory should contain:
- `index.html` (homepage)
- `404.html` (error page)
- `_next/` directory with static assets
- Individual page directories with `index.html` files

## Current Status
- ✅ Next.js configured for static export
- ✅ Build generates index.html correctly
- ✅ PenguinCloud branding added
- ✅ All pages render properly
- ❓ Check Cloudflare build output directory setting