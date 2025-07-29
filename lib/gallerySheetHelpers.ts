
import clientPromise from './mongo';              
import { Collection } from 'mongodb';

export interface GalleryItem {
  id: number;
  image: string;
  title: string;
  location: string;
  city: string;
  year: string;
  tags: string[];
  description: string;
  createdAt?: string;
  updatedAt?: string;
}

const COLLECTION_NAME = 'gallery';                         
const DB_NAME         = process.env.MONGODB_DB || 'app';   
const CACHE_TTL       = 5 * 60_000;                        

interface CacheEntry {
  data: GalleryItem[];
  timestamp: number;
}

let cache: CacheEntry | null = null;
let initialized = false;

async function getCollection(): Promise<Collection<GalleryItem>> {
  const client = await clientPromise;
  const col = client.db(DB_NAME).collection<GalleryItem>(COLLECTION_NAME);

  if (!initialized) {
    await col.createIndex({ id: 1 }, { unique: true });
    initialized = true;
  }
  return col;
}

export async function getGalleryData(): Promise<GalleryItem[]> {
  const now = Date.now();
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data;

  const col   = await getCollection();
  const docs  = await col.find({}).toArray();
  const items = docs.map(({ _id, ...rest }) => rest as GalleryItem);

  cache = { data: items, timestamp: now };
  return items;
}

export async function appendToGallerySheet(
  item: Omit<GalleryItem, 'id' | 'createdAt' | 'updatedAt'>,
): Promise<GalleryItem> {
  const nowIso = new Date().toISOString();
  const newDoc: GalleryItem = {
    id: Date.now(),
    ...item,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  const col = await getCollection();
  await col.insertOne({ ...newDoc });

  if (cache) {
    cache.data.push(newDoc);
    cache.timestamp = Date.now();
  }
  return newDoc;
}

export async function updateGallerySheet(
  item: GalleryItem,
): Promise<GalleryItem> {
  const col       = await getCollection();
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
    if (idx !== -1) cache.data[idx] = updatedItem as GalleryItem;
    cache.timestamp = Date.now();
  }
  return updatedItem as GalleryItem;
}

export async function deleteFromGallerySheet(id: number): Promise<void> {
  const col = await getCollection();
  const res = await col.deleteOne({ id });
  if (res.deletedCount === 0) throw new Error('Item not found');

  if (cache) {
    const idx = cache.data.findIndex((d) => d.id === id);
    if (idx !== -1) cache.data.splice(idx, 1);
    cache.timestamp = Date.now();
  }
}

async function createGallerySheet(): Promise<void> {
}

async function getSheetId(_sheetName: string): Promise<number> {
  return 0;
}