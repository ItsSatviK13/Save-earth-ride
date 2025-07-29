import { MongoClient, Db, Collection } from 'mongodb';

export const categories = [
  'drives',
  'blog',
  'gallery',
  'map',
  'timeline',
  'treecounter',
  'admins',
  'sponsors',
  'registrations',
  'donations',
];


const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) throw new Error('Missing env var:  MONGODB_URI');

const DB_NAME = process.env.MONGODB_DB || 'app';

let clientPromise: Promise<MongoClient>;

declare global {
  var _mongoClientPromise: Promise<MongoClient> | undefined;
}

if (!global._mongoClientPromise) {
  global._mongoClientPromise = new MongoClient(MONGODB_URI).connect();
}
clientPromise = global._mongoClientPromise;

export async function getDb(): Promise<Db> {
  const client = await clientPromise;
  return client.db(DB_NAME);
}

export async function getCollection<T extends Document = any>(
  name: string,
): Promise<Collection<T>> {
  const db = await getDb();
  return db.collection<T>(name);
}

export { clientPromise as getMongoClient };