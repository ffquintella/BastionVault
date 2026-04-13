# BastionVault Documentation

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

## Quick Start

From the **project root**, run:

```console
make docs
```

This installs dependencies and starts the local development server at http://localhost:3000. Changes are reflected live without restarting.

## Manual Commands

If you prefer to run commands directly from the `docs/` directory:

```console
cd docs
npm install
npx docusaurus start
```

### Build

```console
cd docs
npx docusaurus build
```

Generates static content into the `build` directory for deployment.

### Deployment

```console
cd docs
GIT_USER=<Your GitHub username> USE_SSH=true npx docusaurus deploy
```

Builds the website and pushes to the `gh-pages` branch for GitHub Pages hosting.
