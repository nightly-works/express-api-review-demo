import { openDb, seed } from './db.js';
import { createApp } from './app.js';
import { loadSecret } from './auth.js';

const jwtSecret = loadSecret();
const db = openDb();
seed(db);
const port = process.env.PORT || 3000;
createApp(db, { jwtSecret }).listen(port, () => console.log(`API on http://localhost:${port}`));
