import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: [
      '**/dist/**',
      '**/build/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/.yarn/**',
      '**/.pnp.*',
    ],
  },

  js.configs.recommended,

  ...tseslint.configs.recommendedTypeChecked.map((c) => ({
    ...c,
    files: ['**/*.{ts,tsx}'],
  })),

  // Main TS rules (strict for app code)
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parserOptions: {
        project: ['./backend/tsconfig.eslint.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Practical baseline for server-side TS:
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // Allow unused vars that start with _
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },

  // DB tooling scripts: allow pragmatic typing (avoid wasting time on migration internals)
  {
    files: ['backend/src/shared/db/**/*.ts'],
    rules: {
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },

  // Migration files specifically: allow any (Kysely migration types often require flexibility)
  {
    files: ['backend/src/shared/db/migrations/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
];
