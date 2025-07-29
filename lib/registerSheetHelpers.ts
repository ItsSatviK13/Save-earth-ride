// lib/registrationHelpers.ts   ← replaces previous Sheets implementation

import clientPromise from './mongo';
import { Collection } from 'mongodb';

export interface RegistrationData {
  type: 'individual' | 'club';
  firstName?: string;
  lastName?: string;
  bio?: string;
  ridingExperience?: string;

  clubName?: string;
  adminName?: string;
  description?: string;
  website?: string;

  email: string;
  phone: string;
  country: string;
  city: string;
  licenceNumber: string;
  instagram?: string;
  facebook?: string;
  twitter?: string;
  acceptTerms: boolean;

  registrationId?: string;
  timestamp?: string;          
  registrationDate?: string;  
}

const COLLECTION_NAME = 'registrations';             
const DB_NAME         = process.env.MONGODB_DB || 'app';
const CACHE_TTL       = 5 * 60_000;                  

interface CacheEntry {
  data: RegistrationData[];
  timestamp: number;
}
let cache: CacheEntry | null = null;
let collectionReady = false;

async function getCollection(): Promise<Collection<RegistrationData>> {
  const client = await clientPromise;
  const col    = client.db(DB_NAME).collection<RegistrationData>(COLLECTION_NAME);

  if (!collectionReady) {
    await col.createIndex({ registrationId: 1 }, { unique: true });
    collectionReady = true;
  }
  return col;
}

export async function ensureRegistrationSheet(): Promise<void> {
  await getCollection(); 
}

export async function addRegistration(data: RegistrationData): Promise<string> {
  await ensureRegistrationSheet();

  const registrationId = `reg-${Date.now().toString()}`;
  const nowIso         = new Date().toISOString();
  const regDate        = new Date().toLocaleDateString();

  const doc: RegistrationData = {
    ...data,
    registrationId,
    timestamp: nowIso.toString(),
    registrationDate: regDate.toString(),
  };

  const col = await getCollection();
  console.log("Doc going to db " , doc);
  if (!doc.type) throw new Error("Registration 'type' is required");
  await col.insertOne(cleanDoc(doc) as RegistrationData);

  if (cache) {
    cache.data.push(doc);
    cache.timestamp = Date.now();
  }

  return registrationId;
}

export async function getRegistrations(): Promise<RegistrationData[]> {
  const now = Date.now();
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data;

  const col   = await getCollection();
  const docs  = await col.find({}).toArray();
  const items = docs.map(({ _id, ...rest }) => rest as RegistrationData);

  cache = { data: items, timestamp: now };
  return items;
}

export async function getRegistrationStats(): Promise<{
  total: number;
  individuals: number;
  clubs: number;
  recentRegistrations: number;
}> {
  const regs  = await getRegistrations();
  const total = regs.length;
  const individuals = regs.filter((r) => r.type === 'individual').length;
  const clubs       = regs.filter((r) => r.type === 'club').length;

  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const recent = regs.filter((r) => {
    if (!r.timestamp) return false;
    return new Date(r.timestamp) >= thirtyDaysAgo;
  }).length;

  return { total, individuals, clubs, recentRegistrations: recent };
}

function cleanDoc<T extends object>(doc: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(doc).filter(([_, v]) => v !== undefined)
  ) as Partial<T>;
}


export async function updateRegistration(
  registrationId: string,
  updates: Partial<RegistrationData>,
): Promise<void> {
  await ensureRegistrationSheet();

  const col = await getCollection();
  const updatedAt = new Date().toISOString();

  const res = await col.findOneAndUpdate(
    { registrationId },
    { $set: { ...updates, timestamp: updatedAt } },
    { returnDocument: 'after' },
  );

  if (!res) throw new Error('Registration not found');

  if (cache) {
    const idx = cache.data.findIndex((d) => d.registrationId === registrationId);
    if (idx !== -1 && res) cache.data[idx] = { ...(res as any).value, registrationId };
    cache.timestamp = Date.now();
  }
}

export async function deleteRegistration(registrationId: string): Promise<void> {
  await ensureRegistrationSheet();
  const col = await getCollection();

  const res = await col.deleteOne({ registrationId });
  if (res.deletedCount === 0) throw new Error('Registration not found');

  if (cache) {
    const idx = cache.data.findIndex((d) => d.registrationId === registrationId);
    if (idx !== -1) cache.data.splice(idx, 1);
    cache.timestamp = Date.now();
  }
}

export function invalidateRegistrationCache() {
  cache = null;
}

export function getRegistrationCacheStats() {
  return {
    cached: cache !== null,
    age: cache ? Date.now() - cache.timestamp : 0,
    size: cache ? cache.data.length : 0,
  };
}