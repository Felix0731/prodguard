# Example project

Our old bug looked like this:

```js
const locked = false
```

And the config had `enable_confirmations = false`, plus a
`VITE_SUPABASE_SERVICE_ROLE_KEY` reference. All fixed now.
