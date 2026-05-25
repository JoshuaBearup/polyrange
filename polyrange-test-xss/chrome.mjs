// Shared Northwind Outdoors chrome. Every page in the deployment renders
// inside this wrapper, giving the site visual coherence end-to-end.
// In production this would be generated per deploy by Workers AI.

export const theme = {
  siteName: 'Northwind Outdoors',
  brandColor: 'emerald-700',
  navLinks: [
    { label: 'Hiking',       path: '/categories/hiking' },
    { label: 'Camping',      path: '/categories/camping' },
    { label: 'Climbing',     path: '/categories/climbing' },
    { label: 'Water Sports', path: '/categories/water' },
    { label: 'Sale',         path: '/sale',  className: 'text-rose-600 font-medium hover:text-rose-700' },
  ],
  secondaryLinks: [
    { label: 'Sign in', path: '/account' },
    { label: 'Cart (0)', path: '/cart' },
  ],
  footerLinks: [
    { label: 'Privacy', path: '/privacy' },
    { label: 'Terms',   path: '/terms' },
    { label: 'Contact', path: '/contact' },
  ],
}

const NAV_HTML = theme.navLinks
  .map((l) => `<a href="${l.path}" class="${l.className ?? 'hover:text-slate-900'}">${l.label}</a>`)
  .join('\n            ')

const SECONDARY_HTML = theme.secondaryLinks
  .map((l) => `<a href="${l.path}" class="text-sm text-slate-600 hover:text-slate-900">${l.label}</a>`)
  .join('\n          ')

const FOOTER_HTML = theme.footerLinks
  .map((l) => `<a href="${l.path}" class="hover:text-slate-900">${l.label}</a>`)
  .join('\n          ')

export function wrap({ title, body }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — ${theme.siteName}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    .brand { font-weight: 700; letter-spacing: -0.02em; }
  </style>
</head>
<body class="bg-slate-50 text-slate-900">

  <nav class="bg-white border-b border-slate-200">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex justify-between items-center h-16">
        <div class="flex items-center">
          <a href="/" class="brand text-xl text-emerald-700">${theme.siteName}</a>
          <div class="hidden md:flex ml-10 space-x-6 text-sm text-slate-600">
            ${NAV_HTML}
          </div>
        </div>
        <div class="flex items-center space-x-4">
          ${SECONDARY_HTML}
        </div>
      </div>
    </div>
  </nav>

  <div class="bg-white border-b border-slate-200">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <form action="/search" method="get" class="flex gap-2">
        <input type="text" name="q" placeholder="Search for hiking boots, tents, kayaks..."
               class="flex-1 px-4 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent">
        <button type="submit" class="px-6 py-2 bg-emerald-700 text-white rounded-md font-medium hover:bg-emerald-800">
          Search
        </button>
      </form>
    </div>
  </div>

  ${body}

  <footer class="bg-white border-t border-slate-200 mt-16">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 text-sm text-slate-500">
      <div class="flex justify-between">
        <div>&copy; 2026 ${theme.siteName}</div>
        <div class="space-x-4">
          ${FOOTER_HTML}
        </div>
      </div>
    </div>
  </footer>

</body>
</html>`
}
