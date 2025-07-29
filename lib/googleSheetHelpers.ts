import clientPromise from './mongo';
import { Collection } from 'mongodb';

export interface Admin {
  id: number;
  username: string;
  email: string;
  password: string;
  role: string;
  createdAt?: string;
  lastLogin?: string;
  status?: string;
}

const DB_NAME           = process.env.MONGODB_DB || 'app';
const ADMIN_COLLECTION  = 'admins';          
const CACHE_TTL         = 5 * 60_000;        

interface CacheEntry {
  data: Admin[];
  timestamp: number;
}

let cache: CacheEntry | null = null;
let collectionReady = false;

async function getCollection(): Promise<Collection<Admin>> {
  const client = await clientPromise;
  const col    = client.db(DB_NAME).collection<Admin>(ADMIN_COLLECTION);

  if (!collectionReady) {
    await col.createIndex({ id: 1 }, { unique: true });
    collectionReady = true;
  }
  return col;
}

function hasAdminChanged(existing: Admin, incoming: Admin): boolean {
  const fields = [
    'username',
    'email',
    'password',
    'role',
    'createdAt',
    'lastLogin',
    'status',
  ] as const;

  return fields.some(
    (f) => (existing as any)[f] !== (incoming as any)[f],
  );
}


export async function readAdminsFromSheet(): Promise<Admin[]> {
  const now = Date.now();
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data;

  const col   = await getCollection();
  const docs  = await col.find({}).toArray();
  const admins = docs.map(({ _id, ...rest }) => rest as Admin);

  cache = { data: admins, timestamp: now };
  return admins;
}


export async function writeAdminsToSheet(admins: Admin[]) {
  const col            = await getCollection();
  const existingAdmins = await readAdminsFromSheet();
  const existingMap    = new Map(existingAdmins.map((a) => [a.id, a]));

  const newAdmins: Admin[] = [];
  const changedAdmins: Admin[] = [];

  admins.forEach((adm) => {
    const prev = existingMap.get(adm.id);
    if (!prev) {
      newAdmins.push(adm);
    } else if (hasAdminChanged(prev, adm)) {
      changedAdmins.push(adm);
    }
  });

  if (changedAdmins.length) {
    await col.bulkWrite(
      changedAdmins.map((adm) => ({
        updateOne: {
          filter: { id: adm.id },
          update: { $set: { ...adm } },
        },
      })),
    );
  }

  if (newAdmins.length) {
    await col.insertMany(newAdmins);
  }

  if (cache) {
    changedAdmins.forEach((adm) => {
      const idx = cache!.data.findIndex((a) => a.id === adm.id);
      if (idx !== -1) cache!.data[idx] = adm;
    });
    cache.data.push(...newAdmins);
    cache.timestamp = Date.now();
  }

  return {
    success: true,
    newAdmins: newAdmins.length,
    updatedAdmins: changedAdmins.length,
  };
}


export async function replaceAdminsInSheet(admins: Admin[]) {
  const col = await getCollection();
  await col.deleteMany({});
  if (admins.length) {
    await col.insertMany(admins);
  }
  cache = null;
  return { success: true, totalAdmins: admins.length };
}


export async function addSingleAdmin(admin: Admin) {
  const col   = await getCollection();
  const found = await col.findOne({ id: admin.id });
  if (found) {
    return { success: false, message: 'Admin already exists' };
  }
  await writeAdminsToSheet([admin]);
  return { success: true, message: 'Admin added' };
}

export function invalidateAdminCache() {
  cache = null;
}

export function getAdminCacheStats() {
  return {
    cached: cache !== null,
    age: cache ? Date.now() - cache.timestamp : 0,
    size: cache ? cache.data.length : 0,
  };
}