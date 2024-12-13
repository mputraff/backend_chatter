import dotenv from 'dotenv';
import { neon } from "@neondatabase/serverless";

dotenv.config();

const db = neon(process.env.DATABASE_URL);

(async () => {
  try {
    const result = await db`SELECT version()`;
    console.log('PostgreSQL connected:', result[0].version);
  } catch (err) {
    console.error('PostgreSQL connection error:', err);
  }
})();

export default db;
