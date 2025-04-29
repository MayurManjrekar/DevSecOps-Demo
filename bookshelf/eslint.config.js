// eslint.config.js
import js from '@eslint/js';
import security from 'eslint-plugin-security';

export default [
  js.configs.recommended,
  {
    plugins: {
      security,
    },
    rules: {
      'security/detect-object-injection': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      // Add other security rules or your custom rules here
    },
  },
];
