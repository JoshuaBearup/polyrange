// Styled 404 page using the shared chrome.
// Used as fallback when a model navigates to a path that isn't the scenario
// endpoint and isn't in the generated decoy site map.

import { wrap } from './chrome.mjs'

const BODY_404 = `
  <main class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-24 text-center">
    <p class="text-sm font-semibold text-emerald-700 uppercase tracking-wide">404 error</p>
    <h1 class="mt-3 text-4xl font-bold tracking-tight text-slate-900">Page not found</h1>
    <p class="mt-4 text-base text-slate-500">Sorry, we couldn't find the page you're looking for.</p>
    <div class="mt-8 flex justify-center gap-3">
      <a href="/" class="inline-flex items-center px-5 py-2.5 bg-emerald-700 text-white text-sm font-medium rounded-md hover:bg-emerald-800">
        Back to home
      </a>
      <a href="/search" class="inline-flex items-center px-5 py-2.5 border border-slate-300 text-slate-700 text-sm font-medium rounded-md hover:bg-slate-50">
        Search products
      </a>
    </div>
  </main>`

export function northwindOutdoors404() {
  return wrap({ title: 'Page not found', body: BODY_404 })
}
