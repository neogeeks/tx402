import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "**/.venv/**",
      "packages/tx402-python/**",
      // Hand-written declarations for the JS tools. They belong to no tsconfig project, so
      // the type-aware linter cannot parse them; `tsc` still checks them at every import.
      "tools/**/*.d.ts",
      // The documentation site is an Astro project with its own toolchain and its own
      // tsconfig. `astro check` is its linter and type-checker; pointing this one at it
      // would only mean maintaining a second, worse configuration for the same files.
      "docs/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    // Type-aware linting applies to the TypeScript sources only. Repo tooling and config
    // files are plain Node ESM and are not members of any tsconfig project.
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // SEC-003: nothing in library code may write to the console. Diagnostics go through
      // the injected Tx402Logger; the CLI renders from the structured event stream.
      "no-console": "error",
      "@typescript-eslint/explicit-module-boundary-types": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        // `ignoreRestSiblings` is what allows the omit-a-key idiom, which is how the
        // manifest's signing input is built: `const { signature: _s, ...unsigned } = doc`.
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  {
    // The Durable Object subtree needs the Workers runtime types, which conflict with node's on the
    // core path, so it is NOT a member of the default `tsconfig.json` the project service discovers.
    // Point the type-aware linter at its own tsconfig instead (classic `project` mode).
    files: [
      "packages/tx402/src/durable-object/**/*.ts",
      // The Worker capability gateway + its test worker/suite reach the Workers globals too.
      "packages/tx402/src/gateway/worker.ts",
      "packages/tx402/test/gateway/**/*.ts",
      "packages/tx402/test/gateway-durable-object.test.ts",
      "packages/tx402/test/durable-object.test.ts",
      "packages/tx402/test/durable-object/**/*.ts",
      "packages/tx402/vitest.durable-object.config.ts",
      "packages/tx402/vitest.gateway-durable-object.config.ts",
    ],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: ["packages/tx402/tsconfig.durable-object.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // The CLI is the one place in the *SDK* allowed to write to stdout/stderr (SPEC §11).
    files: ["packages/tx402/src/cli/**/*.ts"],
    rules: { "no-console": "off" },
  },
  {
    // Examples are programs a reader runs and watches. Printing is the point of them, and
    // routing their output through a logger abstraction would obscure the very thing they
    // exist to demonstrate. They are not part of the published package.
    files: ["examples/**/*.ts"],
    rules: { "no-console": "off" },
  },
  {
    files: ["**/*.test.ts", "tools/**/*.js"],
    rules: {
      "no-console": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
    },
  },
  {
    // Repo tooling + gateway launchers run on Node directly and are not part of any TS project.
    files: ["**/*.js", "**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
        URL: "readonly",
        Buffer: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        fetch: "readonly",
        Request: "readonly",
        AbortSignal: "readonly",
        performance: "readonly",
        __dirname: "readonly",
      },
    },
    rules: {
      // Spread first: an explicit `rules` key replaces the one from the spread above, and
      // dropping `disableTypeChecked` would re-enable type-aware rules on files that have
      // no TypeScript program behind them.
      ...tseslint.configs.disableTypeChecked.rules,
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
    },
  },
);
