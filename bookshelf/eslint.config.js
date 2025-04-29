// eslint.config.js
import js from '@eslint/js';
import security from 'eslint-plugin-security';

const recommendedGlobals = js.configs.recommended.languageOptions?.globals || {};

export default [
  {
    ...js.configs.recommended,
    rules: {
      ...js.configs.recommended.rules,
      semi: ['error', 'always'], // Enforce semicolons as errors
    },
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      globals: {
        ...recommendedGlobals,
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        process: 'readonly',
        describe: 'readonly',
        it: 'readonly',
      },
    },
    plugins: {
      security,
    },
    rules: {
      'security/detect-object-injection': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      'no-undef': 'error',
    },
  },
];