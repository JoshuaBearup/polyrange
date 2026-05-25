// Decoy page bodies for the Northwind Outdoors deployment.
// Each entry is a body string that gets wrapped by chrome.wrap() at serve time.
// Visually believable, not functionally interactive — links into the catalog
// fall through to the styled 404, forms do not submit, cart state is fixed empty.
//
// In production these would be generated per deploy by Workers AI from the
// theme spec + page role, then passed through the anti-vuln validation pipeline.

const productCard = (name, price, badge, image_hue) => `
  <a href="/products/${name.toLowerCase().replace(/\s+/g, '-')}" class="bg-white border border-slate-200 rounded-lg overflow-hidden hover:shadow-md transition-shadow">
    <div class="aspect-square bg-gradient-to-br from-${image_hue}-100 to-${image_hue}-200"></div>
    <div class="p-4">
      ${badge ? `<div class="text-xs font-medium text-rose-600 uppercase tracking-wide mb-1">${badge}</div>` : ''}
      <h3 class="text-sm font-medium text-slate-900">${name}</h3>
      <p class="mt-1 text-sm text-slate-600">$${price.toFixed(2)}</p>
    </div>
  </a>`

const categoryPage = ({ title, blurb, products }) => `
  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <div class="mb-8">
      <h1 class="text-3xl font-semibold text-slate-900">${title}</h1>
      <p class="mt-2 text-slate-600">${blurb}</p>
    </div>
    <div class="flex gap-6">
      <aside class="hidden lg:block w-56 flex-shrink-0">
        <div class="bg-white border border-slate-200 rounded-lg p-4">
          <h3 class="text-sm font-semibold text-slate-900 mb-3">Filter</h3>
          <div class="space-y-3 text-sm text-slate-600">
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> In stock</label></div>
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> On sale</label></div>
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> Free shipping</label></div>
          </div>
          <h3 class="text-sm font-semibold text-slate-900 mt-6 mb-3">Price</h3>
          <div class="space-y-2 text-sm text-slate-600">
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> Under $50</label></div>
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> $50 — $150</label></div>
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> $150 — $400</label></div>
            <div><label class="flex items-center gap-2"><input type="checkbox" class="rounded"> $400+</label></div>
          </div>
        </div>
      </aside>
      <div class="flex-1 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        ${products.map((p) => productCard(p.name, p.price, p.badge, p.hue)).join('')}
      </div>
    </div>
  </main>`

export const decoys = {
  '/': categoryPage({
    title: 'Gear up for what\'s next',
    blurb: 'Hand-picked outdoor gear, shipped in 2 days. Free returns within 60 days.',
    products: [
      { name: 'Wayfarer 45L Pack',      price: 189.00, badge: 'New',     hue: 'emerald' },
      { name: 'Stormwall 2P Tent',      price: 349.00, badge: 'Best seller', hue: 'sky' },
      { name: 'Granite Trail Boot',     price: 215.00, badge: null,      hue: 'amber' },
      { name: 'Topo 800 Down Jacket',   price: 279.00, badge: null,      hue: 'orange' },
      { name: 'Riverbend Dry Bag 30L',  price:  58.00, badge: 'Sale',    hue: 'blue' },
      { name: 'Summit Pro Helmet',      price: 119.00, badge: null,      hue: 'rose' },
    ],
  }),

  '/categories/hiking': categoryPage({
    title: 'Hiking',
    blurb: 'Trail-tested gear for day hikes and multi-day expeditions.',
    products: [
      { name: 'Granite Trail Boot',       price: 215.00, badge: null,          hue: 'amber' },
      { name: 'Wayfarer 45L Pack',        price: 189.00, badge: 'New',         hue: 'emerald' },
      { name: 'Wayfarer 65L Pack',        price: 229.00, badge: null,          hue: 'emerald' },
      { name: 'Mesa Trekking Poles',      price:  98.00, badge: null,          hue: 'sky' },
      { name: 'Switchback Insole',        price:  45.00, badge: null,          hue: 'amber' },
      { name: 'Apex Hardshell Jacket',    price: 320.00, badge: 'Best seller', hue: 'orange' },
      { name: 'Drylite Merino Socks 3pk', price:  48.00, badge: null,          hue: 'slate' },
      { name: 'Foothill Daypack 20L',     price:  85.00, badge: 'Sale',        hue: 'rose' },
      { name: 'Glacier Trail Gaiters',    price:  72.00, badge: null,          hue: 'sky' },
    ],
  }),

  '/categories/camping': categoryPage({
    title: 'Camping',
    blurb: 'Tents, sleep systems, and camp kitchens that pack down small.',
    products: [
      { name: 'Stormwall 2P Tent',       price: 349.00, badge: 'Best seller', hue: 'sky' },
      { name: 'Stormwall 4P Tent',       price: 489.00, badge: null,          hue: 'sky' },
      { name: 'Cirrus 15° Sleeping Bag', price: 245.00, badge: null,          hue: 'emerald' },
      { name: 'Loft 3.5 Sleeping Pad',   price: 138.00, badge: 'New',         hue: 'orange' },
      { name: 'Trailhead Camp Stove',    price:  79.00, badge: null,          hue: 'rose' },
      { name: 'Basecamp Lantern',        price:  42.00, badge: null,          hue: 'amber' },
      { name: 'Riverbend Dry Bag 30L',   price:  58.00, badge: 'Sale',        hue: 'blue' },
      { name: 'Topo 800 Down Jacket',    price: 279.00, badge: null,          hue: 'orange' },
      { name: 'Trail Pillow',            price:  35.00, badge: null,          hue: 'slate' },
    ],
  }),

  '/categories/climbing': categoryPage({
    title: 'Climbing',
    blurb: 'Trad, sport, and alpine — gear from teams that depend on it.',
    products: [
      { name: 'Summit Pro Helmet',         price: 119.00, badge: null,          hue: 'rose' },
      { name: 'Vortex Climbing Harness',   price: 145.00, badge: null,          hue: 'orange' },
      { name: 'Spire Belay Device',        price:  68.00, badge: null,          hue: 'sky' },
      { name: 'Pitch Climbing Shoes',      price: 178.00, badge: 'Best seller', hue: 'rose' },
      { name: 'Anchor Quickdraw 6-pack',   price: 124.00, badge: null,          hue: 'amber' },
      { name: 'Dynamic Rope 60m',          price: 219.00, badge: null,          hue: 'emerald' },
      { name: 'Crag Chalk Bag',            price:  32.00, badge: 'Sale',        hue: 'slate' },
      { name: 'Approach Trail Shoe',       price: 158.00, badge: null,          hue: 'amber' },
    ],
  }),

  '/categories/water': categoryPage({
    title: 'Water Sports',
    blurb: 'Kayaks, SUPs, drysuits and PFDs for moving water and flatwater.',
    products: [
      { name: 'Riverbend Dry Bag 30L',  price:  58.00, badge: 'Sale',        hue: 'blue' },
      { name: 'Coastal PFD',            price: 119.00, badge: null,          hue: 'sky' },
      { name: 'Whitewater Helmet',      price:  98.00, badge: null,          hue: 'rose' },
      { name: 'Tidal SUP 11\'2"',       price: 689.00, badge: 'Best seller', hue: 'sky' },
      { name: 'Eddy Spray Skirt',       price:  85.00, badge: null,          hue: 'emerald' },
      { name: 'Riverline Drysuit',      price: 749.00, badge: null,          hue: 'amber' },
    ],
  }),

  '/sale': categoryPage({
    title: 'Sale',
    blurb: 'Up to 40% off seasonal gear. While stocks last.',
    products: [
      { name: 'Riverbend Dry Bag 30L',  price:  58.00, badge: '50% off', hue: 'blue' },
      { name: 'Foothill Daypack 20L',   price:  85.00, badge: '30% off', hue: 'rose' },
      { name: 'Crag Chalk Bag',         price:  32.00, badge: '40% off', hue: 'slate' },
      { name: 'Trail Pillow',           price:  35.00, badge: '25% off', hue: 'slate' },
      { name: 'Stormwall 2P Tent',      price: 279.00, badge: 'Was $349', hue: 'sky' },
      { name: 'Glacier Trail Gaiters',  price:  56.00, badge: 'Was $72', hue: 'sky' },
    ],
  }),

  '/account': `
  <main class="max-w-md mx-auto px-4 py-16">
    <div class="bg-white border border-slate-200 rounded-lg p-8">
      <h1 class="text-2xl font-semibold text-slate-900">Sign in</h1>
      <p class="mt-2 text-sm text-slate-500">New customer? <a href="/account/register" class="text-emerald-700 hover:underline">Create an account</a></p>
      <form action="/account/login" method="post" class="mt-6 space-y-4">
        <div>
          <label class="block text-sm font-medium text-slate-700">Email</label>
          <input type="email" name="email" required class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent">
        </div>
        <div>
          <label class="block text-sm font-medium text-slate-700">Password</label>
          <input type="password" name="password" required class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent">
        </div>
        <div class="flex items-center justify-between">
          <label class="flex items-center gap-2 text-sm text-slate-600">
            <input type="checkbox" class="rounded"> Remember me
          </label>
          <a href="/account/forgot" class="text-sm text-emerald-700 hover:underline">Forgot password?</a>
        </div>
        <button type="submit" class="w-full py-2.5 bg-emerald-700 text-white rounded-md font-medium hover:bg-emerald-800">
          Sign in
        </button>
      </form>
    </div>
  </main>`,

  '/cart': `
  <main class="max-w-3xl mx-auto px-4 py-16">
    <h1 class="text-3xl font-semibold text-slate-900 mb-8">Cart</h1>
    <div class="bg-white border border-slate-200 rounded-lg p-12 text-center">
      <svg class="mx-auto h-12 w-12 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"/>
      </svg>
      <h3 class="mt-4 text-base font-medium text-slate-900">Your cart is empty</h3>
      <p class="mt-2 text-sm text-slate-500">Browse our latest gear or check out the sale.</p>
      <div class="mt-6 flex justify-center gap-3">
        <a href="/" class="px-4 py-2 bg-emerald-700 text-white text-sm font-medium rounded-md hover:bg-emerald-800">Continue shopping</a>
        <a href="/sale" class="px-4 py-2 border border-slate-300 text-sm font-medium rounded-md hover:bg-slate-50">View sale</a>
      </div>
    </div>
  </main>`,

  '/privacy': `
  <main class="max-w-3xl mx-auto px-4 py-12 prose prose-slate">
    <h1 class="text-3xl font-semibold text-slate-900">Privacy policy</h1>
    <p class="mt-2 text-sm text-slate-500">Last updated: February 12, 2026</p>
    <div class="mt-8 space-y-6 text-slate-700">
      <p>This Privacy Policy describes how Northwind Outdoors ("we", "us", "our") collects, uses, and discloses personal information when you visit, use, or make a purchase from our website.</p>
      <h2 class="text-xl font-semibold text-slate-900">Information we collect</h2>
      <p>When you visit our site, we automatically collect certain information about your device, including web browser, IP address, time zone, and some of the cookies installed on your device. When you place an order, we collect billing and shipping addresses, payment information (processed by Stripe), and contact details.</p>
      <h2 class="text-xl font-semibold text-slate-900">How we use your information</h2>
      <p>We use the information that we collect generally to fulfill orders placed through the site (processing your payment, arranging shipping, providing you with invoices and order confirmations), and to communicate with you about your order.</p>
      <h2 class="text-xl font-semibold text-slate-900">Cookies</h2>
      <p>A cookie is a small amount of information that's downloaded to your device when you visit our site. We use a number of different cookies, including functional, performance, advertising, and social media or content cookies.</p>
      <h2 class="text-xl font-semibold text-slate-900">Contact</h2>
      <p>For questions about this policy or to make a data subject access request, contact <a href="mailto:privacy@northwind-outdoors.com" class="text-emerald-700 hover:underline">privacy@northwind-outdoors.com</a>.</p>
    </div>
  </main>`,

  '/terms': `
  <main class="max-w-3xl mx-auto px-4 py-12 prose prose-slate">
    <h1 class="text-3xl font-semibold text-slate-900">Terms of service</h1>
    <p class="mt-2 text-sm text-slate-500">Last updated: February 12, 2026</p>
    <div class="mt-8 space-y-6 text-slate-700">
      <p>By accessing or using the Northwind Outdoors website, you agree to be bound by these Terms of Service. If you do not agree with any part of the terms, you may not use the service.</p>
      <h2 class="text-xl font-semibold text-slate-900">Use of the site</h2>
      <p>You agree not to use the site in any unlawful manner or in a way that could damage, disable, overburden, or impair the site or interfere with any other party's use of the site.</p>
      <h2 class="text-xl font-semibold text-slate-900">Orders, prices and availability</h2>
      <p>All orders are subject to acceptance and availability. We reserve the right to refuse any order. Prices are subject to change without notice. Promotional discounts may not be combined.</p>
      <h2 class="text-xl font-semibold text-slate-900">Returns</h2>
      <p>Unused items in their original packaging may be returned within 60 days of delivery for a full refund. Some items, including custom orders and personal-use safety equipment, are non-returnable.</p>
      <h2 class="text-xl font-semibold text-slate-900">Limitation of liability</h2>
      <p>In no event shall Northwind Outdoors, its directors or employees be liable for any indirect, incidental, special, consequential or punitive damages arising from your use of the site or our products.</p>
    </div>
  </main>`,

  '/contact': `
  <main class="max-w-3xl mx-auto px-4 py-12">
    <h1 class="text-3xl font-semibold text-slate-900">Contact us</h1>
    <p class="mt-2 text-slate-600">Have a question about an order or a product? We respond to most enquiries within 24 hours, Mon–Fri.</p>
    <div class="mt-8 grid md:grid-cols-2 gap-8">
      <div class="bg-white border border-slate-200 rounded-lg p-6">
        <h3 class="text-sm font-semibold text-slate-900">Customer support</h3>
        <p class="mt-2 text-sm text-slate-600">Email: <a href="mailto:support@northwind-outdoors.com" class="text-emerald-700 hover:underline">support@northwind-outdoors.com</a><br>Phone: 1-800-555-0142</p>
        <p class="mt-3 text-sm text-slate-600">Hours: Mon–Fri 8am–6pm PT</p>
      </div>
      <form action="/contact/submit" method="post" class="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div>
          <label class="block text-sm font-medium text-slate-700">Name</label>
          <input type="text" name="name" required class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-slate-700">Email</label>
          <input type="email" name="email" required class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500">
        </div>
        <div>
          <label class="block text-sm font-medium text-slate-700">Message</label>
          <textarea name="message" rows="4" required class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500"></textarea>
        </div>
        <button type="submit" class="w-full py-2.5 bg-emerald-700 text-white rounded-md font-medium hover:bg-emerald-800">Send message</button>
      </form>
    </div>
  </main>`,
}

// Each decoy is metadata: a title and a body. Chrome wraps it at serve time.
export const decoyPages = Object.fromEntries(
  Object.entries(decoys).map(([path, body]) => {
    const title = path === '/'
      ? 'Outdoor gear'
      : path.split('/').filter(Boolean).pop().replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
    return [path, { title, body }]
  })
)
