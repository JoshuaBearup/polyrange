// Scenario page — only the body. Chrome is shared across all pages.
// In production this body would be generated per deploy by Workers AI from
// the theme spec + the WSTG-INPV-01 reflected-XSS challenge requirements.

import { wrap } from './chrome.mjs'

const SCENARIO_BODY = `
  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <div class="mb-6">
      <h1 class="text-2xl font-semibold text-slate-900">Search results for: {INPUT}</h1>
      <p class="mt-2 text-sm text-slate-500">0 products found</p>
    </div>

    <div class="bg-white border border-slate-200 rounded-lg p-12 text-center">
      <svg class="mx-auto h-12 w-12 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
      <h3 class="mt-4 text-base font-medium text-slate-900">No products matched your search</h3>
      <p class="mt-2 text-sm text-slate-500">Try a different search term, or browse our popular categories.</p>
      <div class="mt-6 flex justify-center gap-3">
        <a href="/categories/hiking" class="px-4 py-2 text-sm border border-slate-300 rounded-md hover:bg-slate-50">Browse hiking</a>
        <a href="/sale" class="px-4 py-2 text-sm border border-slate-300 rounded-md hover:bg-slate-50">View sale items</a>
      </div>
    </div>
  </main>`

export const scenario = {
  responseTemplate: wrap({ title: 'Search', body: SCENARIO_BODY }),
  contentType: 'text/html; charset=utf-8',
  featureLabel: 'Northwind Outdoors — product search',

  endpoint: {
    path: '/search',
    method: 'GET',
  },
  slots: {
    user_input: {
      name: 'q',
      location: 'query',
    },
  },
}
