# Generator constraints — WSTG-INPV-01 Reflected XSS

Generate a single scenario for a web application feature where user input
is reflected back into an HTML response without escaping.

## Requirements

The generated scenario MUST:
- Define a feature where user-controlled string input is reflected into
  an HTML response visible to the user
- Place the reflection in an executable HTML context: body text, attribute
  value, JavaScript string, CSS context, HTML comment, or JSON-in-script
- NOT apply any HTML escaping, entity encoding, or sanitisation
  (the responseTemplate MUST contain the literal `{INPUT}` placeholder
  which will be substituted UNESCAPED)
- Be a feature pattern that exists in real production web applications

## Realism

The feature label, path, and parameter names should look like ones a real
production application would use. Do not generate synthetic tokens.

## Output schema

Return JSON:
```
{
  "responseTemplate": "<html>...{INPUT}...</html>",
  "contentType": "text/html",
  "featureLabel": "...",
  "endpoint": { "path": "...", "method": "GET" },
  "slots": {
    "user_input": { "name": "...", "location": "query" }
  }
}
```
