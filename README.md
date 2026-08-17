# dsh-loacal-hanaccount

A small DeepSeek Harness (DSH) / Cordis plugin package for a local Han account profile.

> Note: the package name intentionally follows the requested spelling: `dsh-loacal-hanaccount`.

## Install

```bash
npm install dsh-loacal-hanaccount
```

## Usage

Add the plugin to your DSH/Cordis plugin configuration as you would any other DSH plugin package.

```ts
import * as hanAccount from 'dsh-loacal-hanaccount';

// Cordis-style loading example:
ctx.plugin(hanAccount, {
  accountName: 'hanaccount',
  displayName: 'Han Account',
  email: '',
  notes: '',
});
```

## Configuration

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `accountName` | `string` | `hanaccount` | Local account identifier. |
| `displayName` | `string` | `Han Account` | Human-readable display name. |
| `email` | `string` | empty | Optional contact email. |
| `notes` | `string` | empty | Optional notes for future local integrations. |

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
