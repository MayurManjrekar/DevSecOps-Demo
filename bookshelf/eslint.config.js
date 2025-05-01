// eslint.config.js
import js from '@eslint/js';
import security from 'eslint-plugin-security';

const recommendedGlobals = js.configs.recommended.languageOptions?.globals || {};

export default [
  {
    ...js.configs.recommended,
    rules: {
      // Include only rules that are actual syntax errors
      'no-undef': 'error',
      'no-unused-vars': 'error',
      'no-extra-semi': 'error',
      'no-unexpected-multiline': 'error',
      'semi': ['error', 'always'], // semicolons are required
    },
  },
  {
    files: ['**/*.js'],
    ignores: ['eslint.config.js'], // Ignore the config file
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
      // Keep only security-related rules (which aren't just style-based)
      'security/detect-object-injection': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
    },
  },
];
