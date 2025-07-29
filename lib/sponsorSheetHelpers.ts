import clientPromise from './mongo'
import { Collection, Document } from 'mongodb'

/* ── data model that matches your validator ───────── */
export interface SponsorData extends Document {
  id: number
  name: string
  logo: string
  tier: string
  website: string
  description: string
  contribution: string
  since: number
  category: string
  type: string              // sponsor | partner | donor

  /* new optional fields */
  company_name?: string
  email?: string
  phone_number?: string
}

const HEADERS: (keyof SponsorData)[] = [
  'id',
  'name',
  'logo',
  'tier',
  'website',
  'description',
  'contribution',
  'since',
  'category',
  'type',
  'company_name',
  'email',
  'phone_number'
]

const COLLECTION_NAME = 'sponsors'
const DB_NAME         = process.env.MONGODB_DB ?? 'app'
const CACHE_TTL       = 5 * 60_000   // five minutes

let collectionReady = false
async function getCollection(): Promise<Collection<SponsorData>> {
  const client = await clientPromise
  const col    = client.db(DB_NAME).collection<SponsorData>(COLLECTION_NAME)

  if (!collectionReady) {
    await col.createIndex({ id: 1 }, { unique: true })
    collectionReady = true
  }
  return col
}

/* ── simple in-memory cache ───────────────────────── */
interface Cache { data: SponsorData[]; timestamp: number }
let cache: Cache | null = null

export async function getSponsorData(): Promise<SponsorData[]> {
  const now = Date.now()
  if (cache && now - cache.timestamp < CACHE_TTL) return cache.data

  const data = await (await getCollection())
    .find({})
    .sort({ id: 1 })
    .toArray()

  cache = { data, timestamp: now }
  return data
}

export async function addSponsorData(
  sponsor: Omit<SponsorData, 'id'>
): Promise<SponsorData> {
  const col    = await getCollection()
  const last   = await col.find().sort({ id: -1 }).limit(1).next()
  const nextId = last ? last.id + 1 : 1

  /* Just attach the generated id—never blank-out caller data */
  const doc: SponsorData = {
    ...sponsor,
    name: sponsor.name,
    logo: sponsor.logo,
    tier: sponsor.tier,
    website: sponsor.website,
    description: sponsor.description,
    contribution: sponsor.contribution,
    since: 0,
    category: sponsor.category,
    type: sponsor.type,
    id: nextId, 
  }

  await col.insertOne(doc)

  if (cache) {
    cache.data.push(doc)
    cache.timestamp = Date.now()
  }
  return doc
}

export async function updateSponsorData(
  id: number,
  updates: Partial<SponsorData>
): Promise<SponsorData> {
  const col = await getCollection()
  const res = await col.findOneAndUpdate(
    { id },
    { $set: updates },
    { returnDocument: 'after' }
  )
  if (!res?.value) throw new Error('Sponsor not found')

  if (cache) {
    const i = cache.data.findIndex(d => d.id === id)
    if (i !== -1) cache.data[i] = res.value
    cache.timestamp = Date.now()
  }
  return res.value
}

export async function deleteSponsorData(id: number): Promise<void> {
  const col = await getCollection()
  const res = await col.deleteOne({ id })
  if (res.deletedCount === 0) throw new Error('Sponsor not found')

  if (cache) {
    cache.data = cache.data.filter(d => d.id !== id)
    cache.timestamp = Date.now()
  }
}