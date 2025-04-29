// eslint.config.js
import js from '@eslint/js';
import security from 'eslint-plugin-security';

export default [
  js.configs.recommended, // Add the recommended rules as a separate config
  {
    files: ['**/*.js'],
    languageOptions: {
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        process: 'readonly',
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