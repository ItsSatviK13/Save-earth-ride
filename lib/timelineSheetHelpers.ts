
import clientPromise from './mongo';
import { Collection } from 'mongodb';

export interface TimelineItem {
  id: number;
  date: string;
  title: string;
  location: string;
  type: string;
  participants: number;
  treesPlanted: number;
  description: string;
  image: string;
  side: 'left' | 'right';
  contactEmail?: string;
}

const COLLECTION_NAME = 'timeline';                 
const DB_NAME         = process.env.MONGODB_DB || 'app';
const CACHE_TTL       = 5 * 60_000;                  

interface CacheEntry {
  data: TimelineItem[];
  timestamp: number;
}

let cache: CacheEntry | null = null;
let collectionReady = false;

async function getCollection(): Promise<Collection<TimelineItem>> {
  const client = await clientPromise;
  const col    = client.db(DB_NAME).collection<TimelineItem>(COLLECTION_NAME);

  if (!collectionReady) {
    await col.createIndex({ id: 1 }, { unique: true });
    collectionReady = true;
  }
  return col;
}

export async function getTimelineData(): Promise<TimelineItem[]> {
  const now = Date.now();
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data;

  const col   = await getCollection();
  const docs  = await col.find({}).sort({ id: 1 }).toArray();
  const items = docs.map(({ _id, ...rest }) => rest as TimelineItem);

  cache = { data: items, timestamp: now };
  return items;
}

export async function saveTimelineData(
  timelineData: TimelineItem[],
): Promise<void> {
  const col = await getCollection();
  await col.deleteMany({});
  if (timelineData.length) {
    await col.insertMany(timelineData);
  }
  cache = { data: timelineData, timestamp: Date.now() };
}

export async function addTimelineItem(
  item: Omit<TimelineItem, 'id'>,
): Promise<TimelineItem> {
  const current = await getTimelineData();
  const newId   = current.length ? Math.max(...current.map((d) => d.id)) + 1 : 1;

  const newItem: TimelineItem = { ...item, id: newId };

  const col = await getCollection();
  await col.insertOne({ ...newItem });

  if (cache) {
    cache.data.push(newItem);
    cache.timestamp = Date.now();
  }
  return newItem;
}

export async function updateTimelineItem(
  id: number,
  updates: Partial<TimelineItem>,
): Promise<TimelineItem> {
  const col = await getCollection();

  const res = await col.findOneAndUpdate(
    { id },
    { $set: { ...updates } },
    { returnDocument: 'after' },
  );
  if (!res) throw new Error('Timeline item not found');
  const { _id, ...updated } = res as any;

  if (cache) {
    const idx = cache.data.findIndex((d) => d.id === id);
    if (idx !== -1) cache.data[idx] = updated as TimelineItem;
    cache.timestamp = Date.now();
  }
  return updated as TimelineItem;
}

export async function deleteTimelineItem(id: number): Promise<void> {
  const col = await getCollection();
  const res = await col.deleteOne({ id });
  if (res.deletedCount === 0) throw new Error('Timeline item not found');

  if (cache) {
    const idx = cache.data.findIndex((d) => d.id === id);
    if (idx !== -1) cache.data.splice(idx, 1);
    cache.timestamp = Date.now();
  }
}

export async function initializeTimelineSheet(): Promise<void> {
  await getCollection(); 
}