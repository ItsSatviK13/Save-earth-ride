import clientPromise from './mongo';
import { Collection } from 'mongodb';
import {
  validateDriveSheetData,
  DRIVE_SHEET_NAME,
} from './driveSheetHeaders';

export interface DriveData {
  id?: string;
  title: string;
  location: string;
  date: string;
  participants?: number;
  treesTarget?: number;
  status?: 'upcoming' | 'ongoing' | 'completed' | 'cancelled';
  registrationOpen?: boolean;
  description?: string;
  organizer: string;
  contactEmail: string;
  registrationDeadline?: string;
  meetingPoint?: string;
  endingPoint?: string;
  duration?: string;
  difficulty?: 'Easy' | 'Moderate' | 'Challenging' | 'Expert';
  logo?: string;
  createdAt?: string;
  updatedAt?: string;
}

interface CacheEntry {
  data: DriveData[];
  timestamp: number;
}

let memoryCache: CacheEntry | null = null;
let isInitialized = false;

const CACHE_TTL = 5 * 60 * 1000;                    
const DB_NAME   = process.env.MONGODB_DB || 'app';  
const COLLECTION_NAME = DRIVE_SHEET_NAME;           

async function getCollection(): Promise<Collection<DriveData>> {
  const client = await clientPromise;
  return client.db(DB_NAME).collection<DriveData>(COLLECTION_NAME);
}

export async function initializeDriveSheet(): Promise<boolean> {
  if (isInitialized) return true;

  const collection = await getCollection();
  await collection.createIndex({ id: 1 }, { unique: true }); 
  isInitialized = true;
  return true;
}

export async function getAllDrives(): Promise<DriveData[]> {
  const now = Date.now();
  if (memoryCache && now - memoryCache.timestamp < CACHE_TTL) {
    return memoryCache.data;
  }

  const collection = await getCollection();
  const docs = await collection.find({}).toArray();
  const drives = docs.map(({ _id, ...rest }) => rest as DriveData);

  memoryCache = { data: drives, timestamp: now };
  return drives;
}

export async function getDriveById(id: string): Promise<DriveData | null> {
  if (memoryCache && Date.now() - memoryCache.timestamp < CACHE_TTL) {
    return memoryCache.data.find((d) => d.id === id) || null;
  }

  const collection = await getCollection();
  const doc = await collection.findOne({ id });
  if (!doc) return null;
  const { _id, ...rest } = doc as any;
  return rest as DriveData;
}

export async function getDrivesByStatus(status: string): Promise<DriveData[]> {
  const drives = await getAllDrives();
  return drives.filter((d) => d.status === status);
}

export async function addDrive(driveData: DriveData): Promise<DriveData> {
  validateDriveSheetData(driveData);

  const nowIso = new Date().toISOString();
  const newDrive: DriveData = {
    ...driveData,
    id: driveData.id || Date.now().toString(),
    createdAt: nowIso,
    updatedAt: nowIso,
    participants: driveData.participants ?? 0,
    treesTarget: driveData.treesTarget ?? 0,
    status: driveData.status ?? 'upcoming',
    registrationOpen: driveData.registrationOpen ?? true,
    difficulty: driveData.difficulty ?? 'Easy',
  };

  const collection = await getCollection();
  await collection.insertOne({ ...newDrive });

  if (memoryCache) {
    memoryCache.data.push(newDrive);
    memoryCache.timestamp = Date.now();
  }
  return newDrive;
}

export async function updateDrive(
  id: string,
  driveData: Partial<DriveData>,
): Promise<DriveData> {
  validateDriveSheetData({ ...driveData, id });

  const collection = await getCollection();
  const updatedAt = new Date().toISOString();

  const updatedDoc = await collection.findOneAndUpdate(
    { id },
    { $set: { ...driveData, updatedAt } },
    { returnDocument: 'after' }         
  );

  if (!updatedDoc) throw new Error('Drive not found');
  const { _id, ...updatedDrive } = updatedDoc as any;

  if (memoryCache) {
    const idx = memoryCache.data.findIndex((d) => d.id === id);
    if (idx !== -1) memoryCache.data[idx] = updatedDrive as DriveData;
    memoryCache.timestamp = Date.now();
  }
  return updatedDrive as DriveData;
}

export async function deleteDrive(id: string): Promise<boolean> {
  const collection = await getCollection();
  const res = await collection.deleteOne({ id });
  if (res.deletedCount === 0) throw new Error('Drive not found');

  if (memoryCache) {
    const idx = memoryCache.data.findIndex((d) => d.id === id);
    if (idx !== -1) memoryCache.data.splice(idx, 1);
    memoryCache.timestamp = Date.now();
  }
  return true;
}

export async function batchUpdateDrives(
  updates: { id: string; data: Partial<DriveData> }[],
): Promise<DriveData[]> {
  if (!updates.length) return [];

  const collection = await getCollection();
  const updatedAt = new Date().toISOString();

  await collection.bulkWrite(
    updates.map(({ id, data }) => ({
      updateOne: { filter: { id }, update: { $set: { ...data, updatedAt } } },
    })),
  );

  const ids = updates.map((u) => u.id);
  const docs = await collection.find({ id: { $in: ids } }).toArray();
  const drives = docs.map(({ _id, ...rest }) => rest as DriveData);

  if (memoryCache) {
    drives.forEach((d) => {
      const idx = memoryCache!.data.findIndex((x) => x.id === d.id);
      if (idx !== -1) memoryCache!.data[idx] = d;
      else memoryCache!.data.push(d);
    });
    memoryCache.timestamp = Date.now();
  }
  return drives;
}

export function invalidateCache(): void {
  memoryCache = null;
}

export function clearCache(): void {
  memoryCache = null;
  isInitialized = false;
}

export function getCacheStats(): { cached: boolean; age: number; size: number } {
  return {
    cached: memoryCache !== null,
    age: memoryCache ? Date.now() - memoryCache.timestamp : 0,
    size: memoryCache ? memoryCache.data.length : 0,
  };
}