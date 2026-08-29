# CWE Navigation

An interactive browser for the [CWE Research Concepts view (CWE-1000)](https://cwe.mitre.org/data/definitions/1000.html). It turns the CWE hierarchy and related-weakness links into a searchable graph for exploring how software weaknesses are connected.

[Open the live site](https://habaneraa.github.io/cwe-navigation/)

## Features

- Search by CWE ID, name, or description.
- Explore the complete Research Concepts graph or a focused pillar tree.
- Filter nodes by abstraction and links by relationship type.
- Inspect descriptions, mapping guidance, status, structure, and related weaknesses.
- Share a URL that restores the selected CWE and graph view.
- Use the responsive desktop, tablet, and mobile layouts without signing in.

## Tech stack

- [Vue 3](https://vuejs.org/) and [Vite](https://vite.dev/)
- [Apache ECharts](https://echarts.apache.org/) for graph rendering
- [Tailwind CSS](https://tailwindcss.com/) for styling
- TypeScript data generator using `fast-xml-parser`

## Local development

Node.js 20.19 or newer is required.

```bash
npm ci
npm run dev
```

Vite prints the local development URL after startup. The application uses the generated JSON files already committed under `public/`, so normal frontend development and production builds do not need network access.

## Commands

| Command                        | Purpose                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `npm run dev`                  | Start the Vite development server.                                 |
| `npm run build`                | Create a production build in `dist/`.                              |
| `npm run preview`              | Preview the production build locally.                              |
| `npm run lint`                 | Check the JavaScript and Vue source.                               |
| `npm test`                     | Run the data pipeline fixture tests.                               |
| `npm run data:typecheck`       | Type-check the data generator and tests.                           |
| `npm run data:generate`        | Generate the frontend JSON from the cached or current CWE catalog. |
| `npm run data:update-fixtures` | Regenerate fixture baselines after an intentional output change.   |
| `npm run format`               | Format the repository with Prettier.                               |

## Updating CWE data

The generator downloads the official CWE XML catalog when `data/cache/cwec_latest.xml` is absent. Pass `--download` to force a refresh:

```bash
npm run data:generate -- --download
npm test
npm run data:typecheck
```

Review and commit changes to these generated files:

- `public/catalog_info.json`
- `public/cwe_metadata.json`
- `public/graph_data.json`

The cache directory is intentionally ignored. Fixture baselines under `data/fixtures/expected/` should only change when the generator's output format changes, not for a routine catalog update.

## Repository layout

```text
.
├── data/                  # CWE XML parser, graph generator, fixtures, and tests
├── public/                # Generated CWE data and static assets
├── src/                   # Vue application
├── .github/workflows/     # CI and GitHub Pages deployment
└── vite.config.js         # Vite configuration and Pages base path
```

Pushes and pull requests run linting, type checking, tests, and a production build. Successful pushes to `main` publish `dist/` to the `gh-pages` branch.

## Data source and license

CWE data comes from the [MITRE CWE project](https://cwe.mitre.org/data/downloads.html). The application source is available under the [MIT License](LICENSE).
