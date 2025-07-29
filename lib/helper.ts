import clientPromise from './mongo';
import { Collection, Document } from 'mongodb';

export interface TreeCountData {
  count: number;
  lastUpdated: string;
}

export interface DonationData {
  id: string;
  name: string;
  amount: number;
  currency: string;
  date: string;
  email?: string;
  message?: string;
}

export interface RegistrationData {
  id: string;
  name: string;
  type: 'Individual' | 'Club';
  location: string;
  date: string;
  email?: string;
  phone?: string;
  bikeModel?: string;
}

export interface DashboardData {
  treeCount: TreeCountData;
  recentDonations: DonationData[];
  recentRegistrations: RegistrationData[];
  totalRiders: number;
}

const DB_NAME             = process.env.MONGODB_DB || 'app';
const TREE_COLLECTION     = 'treecounter';
const DONATIONS_COLLECTION = 'donations';
const REG_COLLECTION       = 'helperRegistration';

const CACHE_TTL = 5 * 60_000; 

type Cache<T> = { data: T; at: number };

let treeCache: Cache<TreeCountData>            | null = null;
let donationCache: Cache<DonationData[]>       | null = null;
let registrationCache: Cache<RegistrationData[]> | null = null;

async function getCollection<T extends Document = Document>(
  name: string,
): Promise<Collection<T>> {
  const client = await clientPromise;
  return client.db(DB_NAME).collection<T>(name);
}

export async function getTreeCountData(): Promise<TreeCountData> {
  const now = Date.now();
  if (treeCache && now - treeCache.at < CACHE_TTL) return treeCache.data;

  const col = await getCollection<TreeCountData>(TREE_COLLECTION);

  const doc = await col
    .find({})
    .sort({ lastUpdated: -1 })
    .limit(1)
    .next() as TreeCountData | null;

  const result: TreeCountData = doc
    ? { count: doc.count, lastUpdated: doc.lastUpdated }
    : { count: 25_847, lastUpdated: new Date().toISOString() };

  treeCache = { data: result, at: now };
  return result;
}

export async function updateTreeCount(newCount: number): Promise<boolean> {
  const col = await getCollection<TreeCountData>(TREE_COLLECTION);
  const res = await col.insertOne({
    count: newCount,
    lastUpdated: new Date().toISOString(),
  });
  treeCache = null; 
  return res.acknowledged;
}

export async function getDonationsData(): Promise<DonationData[]> {
  const now = Date.now();
  if (donationCache && now - donationCache.at < CACHE_TTL) {
    return donationCache.data;
  }

  const col = await getCollection<DonationData>(DONATIONS_COLLECTION);
  const docs = await col
    .find({}, { projection: { _id: 0 } })
    .sort({ date: -1 })
    .limit(10)
    .toArray();

  donationCache = { data: docs, at: now };
  return docs;
}

export async function addDonation(
  donation: Omit<DonationData, 'id'>,
): Promise<boolean> {
  const col = await getCollection<DonationData>(DONATIONS_COLLECTION);
  const doc: DonationData = {
    id: `donation-${Date.now()}`,
    ...donation,
  };
  const res = await col.insertOne(doc);
  donationCache = null;
  return res.acknowledged;
}

export async function getRegistrationsData(): Promise<RegistrationData[]> {
  const now = Date.now();
  if (registrationCache && now - registrationCache.at < CACHE_TTL) {
    return registrationCache.data;
  }

  const col = await getCollection<RegistrationData>(REG_COLLECTION);
  const docs = await col
    .find({}, { projection: { _id: 0 } })
    .sort({ date: -1 })
    .limit(10)
    .toArray();

  registrationCache = { data: docs, at: now };
  return docs;
}

export async function addRegistration(
  registration: Omit<RegistrationData, 'id'>,
): Promise<boolean> {
  const col = await getCollection<RegistrationData>(REG_COLLECTION);
  const doc: RegistrationData = {
    id: `registration-${Date.now()}`,
    ...registration,
  };
  const res = await col.insertOne(doc);
  registrationCache = null;
  return res.acknowledged;
}

export async function getTotalRiders(): Promise<number> {
  try {
    const col = await getCollection(REG_COLLECTION);
    return await col.estimatedDocumentCount();
  } catch (err) {
    console.error('Error calculating total riders:', err);
    return 52_340; 
  }
}

export async function getDashboardData(): Promise<DashboardData> {
  try {
    const [treeCount, donations, registrations, totalRiders] =
      await Promise.all([
        getTreeCountData(),
        getDonationsData(),
        getRegistrationsData(),
        getTotalRiders(),
      ]);

    return {
      treeCount,
      recentDonations: donations,
      recentRegistrations: registrations,
      totalRiders,
    };
  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    return {
      treeCount: { count: 25_847, lastUpdated: new Date().toISOString() },
      recentDonations: [],
      recentRegistrations: [],
      totalRiders: 52_340,
    };
  }
}