// eslint.config.js
import js from '@eslint/js';
import security from 'eslint-plugin-security';

export default [
  {
    files: ['**/*.js'], // Apply these settings to all .js files
    languageOptions: {
      globals: {
        ...js.configs.recommended.languageOptions.globals,
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
      ...js.configs.recommended.rules,
      'security/detect-object-injection': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      'no-undef': 'error', // Ensure no undefined variables are used
    },
  },
];