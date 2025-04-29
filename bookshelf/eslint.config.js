// eslint.config.js
import legacy from '@eslint/js/use-at-your-own-risk';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default [
  legacy.config({
    configFile: join(__dirname, '.eslintrc.js'), // Adjust the filename if yours is different
  }),
];
