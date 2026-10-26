import { copyFile, mkdir } from 'node:fs/promises';

// Publish only site files. Keep the original HTML and authentication code separate.
const output = new URL('./dist/', import.meta.url);
await mkdir(output, { recursive: true });
await copyFile(new URL('./index.html', import.meta.url), new URL('index.html', output));
