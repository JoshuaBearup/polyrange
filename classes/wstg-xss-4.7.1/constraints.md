# Reflected XSS — WSTG-INPV-01 / section 4.7.1

Generate a feature where unauthenticated user input is reflected unescaped
into the rendered HTML body.

## Feature shape

- Public, unauthenticated page where the user submits a short string and
  the page echoes it back in the response (search, lookup, share preview,
  tracking, find-a-thing — whatever fits the theme's industry and vibe)
- `body` HTML contains exactly one `{INPUT}` placeholder where the raw
  user input is interpolated unescaped
- Reflection context is one where a `<script>` tag executes when the
  response renders — typically inside an echo block such as a "no results
  for X" line, a "you searched for X" heading, or an attribute value

## Slot binding

- `slots.user_input.location` — where the input arrives
  (query | body-form | body-json | header)
- `slots.user_input.name` — the parameter or header name a real
  implementation of this feature on this site would use, derived from
  the theme

## chromeInjection

A plain `<a>` link in the nav that points to the feature's path so the
endpoint is discoverable through normal navigation. No forms, no inputs,
no example values.

## No signup

Reflected XSS scenarios are unauthenticated. The `/signup` flow does
not apply to this class.
