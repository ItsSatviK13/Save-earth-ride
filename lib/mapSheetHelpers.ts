import clientPromise from './mongo';
import { Collection } from 'mongodb';

export interface MapItem {
  id: number;
  name: string;
  location: string;
  coordinates: { lat: number; lng: number };
  date: string;
  type: string;
  participants: number;
  treesPlanted: number;
  description: string;
  image: string;
  organizer: string;
  status: string;
  createdAt?: string;
  updatedAt?: string;
}

const COLLECTION_NAME = 'map';                       
const DB_NAME         = process.env.MONGODB_DB || 'app';
const CACHE_TTL       = 5 * 60_000;                  

interface CacheEntry {
  data: MapItem[];
  timestamp: number;
}

let cache: CacheEntry | null = null;
let collectionInitialised = false;

async function getCollection(): Promise<Collection<MapItem>> {
  const client = await clientPromise;
  const col = client.db(DB_NAME).collection<MapItem>(COLLECTION_NAME);

  if (!collectionInitialised) {
    await col.createIndex({ id: 1 }, { unique: true });
    collectionInitialised = true;
  }
  return col;
}

export async function getMapData(): Promise<MapItem[]> {
  const now = Date.now();
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data;

  const col = await getCollection();
  const docs = await col.find({}).toArray();
  const items = docs.map(({ _id, ...rest }) => rest as MapItem);

  cache = { data: items, timestamp: now };
  return items;
}

export async function appendToMapSheet(
  item: Omit<MapItem, 'id' | 'createdAt' | 'updatedAt'>,
): Promise<MapItem> {
  const nowIso = new Date().toISOString();
  const newItem: MapItem = {
    id: Date.now(),
    ...item,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  const col = await getCollection();
  await col.insertOne({ ...newItem });

  if (cache) {
    cache.data.push(newItem);
    cache.timestamp = Date.now();
  }
  return newItem;
}

export async function updateMapSheet(item: MapItem): Promise<MapItem> {
  const col = await getCollection();
  const updatedAt = new Date().toISOString();

  const doc = await col.findOneAndUpdate(
    { id: item.id },
    { $set: { ...item, updatedAt } },
    { returnDocument: 'after' },
  );

  if (!doc) throw new Error('Item not found');

  const { _id, ...updatedItem } = doc as any;

  if (cache) {
    const idx = cache.data.findIndex((d) => d.id === item.id);
    if (idx !== -1) cache.data[idx] = updatedItem as MapItem;
    cache.timestamp = Date.now();
  }
  return updatedItem as MapItem;
}

export async function deleteFromMapSheet(id: number): Promise<void> {
  const col = await getCollection();
  const res = await col.deleteOne({ id });
  if (res.deletedCount === 0) throw new Error('Item not found');

  if (cache) {
    const idx = cache.data.findIndex((d) => d.id === id);
    if (idx !== -1) cache.data.splice(idx, 1);
    cache.timestamp = Date.now();
  }
}


async function createMapSheet(): Promise<void> {
}

async function getSheetId(_sheetName: string): Promise<number> {
  return 0; 
}