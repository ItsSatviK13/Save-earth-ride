import clientPromise from "./mongo";

const BLOG_SHEET_NAME = 'blog';

export interface BlogPost {
  id: number;
  title: string;
  excerpt: string;
  content: string;
  blogURL: string;
  authorName: string;
  authorBio: string;
  authorAvatar: string;
  tags: string[];
  image: string;
  readTime: string;
  featured: boolean;
  status: 'draft' | 'published' | 'archived';
  category: string;
  date: string;
  createdAt: string;
  updatedAt: string;
}

interface CacheEntry {
  data: BlogPost[];
  timestamp: number;
  ttl: number;
}

const CACHE_TTL = 5 * 60 * 1000; 
let blogCache: CacheEntry | null = null;

const rateLimiter = {
  requests: [] as number[],
  maxRequests: 100,
  windowMs: 60 * 1000,
  
  canMakeRequest(): boolean {
    const now = Date.now();
    this.requests = this.requests.filter(timestamp => now - timestamp < this.windowMs);
    
    if (this.requests.length >= this.maxRequests) {
      return false;
    }
    
    this.requests.push(now);
    return true;
  }
};

function normalizeBlogPost(row: any[], index: number): BlogPost {
  return {
    id: Number(row[0]) || index + 1,
    title: (row[1] || '').toString().trim(),
    excerpt: (row[2] || '').toString().trim(),
    content: (row[3] || '').toString(),
    blogURL: (row[4] || '').toString().trim(),
    authorName: (row[5] || '').toString().trim(),
    authorBio: (row[6] || '').toString().trim(),
    authorAvatar: (row[7] || '').toString().trim(),
    tags: row[8] ? row[8].toString().split(',').map((tag: string) => tag.trim()).filter(Boolean) : [],
    image: (row[9] || '').toString().trim(),
    readTime: (row[10] || '').toString().trim(),
    featured: row[11] === 'true' || row[11] === true,
    status: (['draft', 'published', 'archived'].includes(row[12]) ? row[12] : 'draft') as 'draft' | 'published' | 'archived',
    category: (row[13] || '').toString().trim(),
    date: row[14] || new Date().toISOString().split('T')[0],
    createdAt: row[15] || new Date().toISOString(),
    updatedAt: row[16] || new Date().toISOString(),
  };
}

export async function readBlogFromSheet(useCache: boolean = true): Promise<BlogPost[]> {
  if (useCache && blogCache) {
    const now = Date.now();
    if (now - blogCache.timestamp < blogCache.ttl) {
      return blogCache.data;
    }
  }

  const client = await clientPromise;
  const db = client.db("database0");
  const blogs = await db.collection<BlogPost>("blog").find({}).toArray();

  blogCache = {
    data: blogs,
    timestamp: Date.now(),
    ttl: CACHE_TTL
  };

  return blogs;
}

export async function writeBlogToSheet(blogs: BlogPost[]): Promise<{ success: boolean; updated: number; added: number; errors: string[] }> {
  const client = await clientPromise;
  const db = client.db("database0");
  const collection = db.collection<BlogPost>("blog");

  const errors: string[] = [];
  let updated = 0;
  let added = 0;

  await Promise.all(blogs.map(async (blog) => {
    try {
      const existing = await collection.findOne({ id: blog.id });
      if (existing) {
        await collection.updateOne({ id: blog.id }, { $set: { ...blog, updatedAt: new Date().toISOString() } });
        updated++;
      } else {
        await collection.insertOne({ ...blog, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
        added++;
      }
    } catch (err) {
      errors.push(`Error processing blog ${blog.id}: ${err}`);
    }
  }));

  blogCache = null;

  return { success: errors.length === 0, updated, added, errors };
}

function blogToSheetRow(blog: BlogPost): any[] {
  return [
    blog.id,
    blog.title,
    blog.excerpt,
    blog.content,
    blog.blogURL,
    blog.authorName,
    blog.authorBio,
    blog.authorAvatar,
    Array.isArray(blog.tags) ? blog.tags.join(', ') : blog.tags,
    blog.image,
    blog.readTime,
    blog.featured ? 'true' : 'false',
    blog.status,
    blog.category,
    blog.date,
    blog.createdAt,
    blog.updatedAt,
  ];
}

function hasBlogChanged(existing: BlogPost, incoming: BlogPost): boolean {
  if (existing === incoming) return false;
  
  const criticalFields = ['title', 'content', 'status', 'featured'] as const;
  
  for (const field of criticalFields) {
    if (existing[field] !== incoming[field]) {
      return true;
    }
  }
  
  const existingTags = Array.isArray(existing.tags) ? existing.tags.join(', ') : existing.tags;
  const incomingTags = Array.isArray(incoming.tags) ? incoming.tags.join(', ') : incoming.tags;
  if (existingTags !== incomingTags) {
    return true;
  }
  
  const otherFields = [
    'excerpt', 'blogURL', 'authorName', 'authorBio', 'authorAvatar', 
    'image', 'readTime', 'category', 'date'
  ] as const;
  
  return otherFields.some(field => (existing[field] || '') !== (incoming[field] || ''));
}

export async function deleteBlogFromSheet(blogIds: number | number[]): Promise<{ success: boolean; deleted: number; errors: string[] }> {
  const ids = Array.isArray(blogIds) ? blogIds : [blogIds];
  const client = await clientPromise;
  const db = client.db("database0");
  const collection = db.collection<BlogPost>("blog");

  try {
    const result = await collection.deleteMany({ id: { $in: ids } });
    blogCache = null;
    return { success: true, deleted: result.deletedCount ?? 0, errors: [] };
  } catch (error) {
    return { success: false, deleted: 0, errors: [error instanceof Error ? error.message : 'Unknown error'] };
  }
}

export async function addSingleBlog(blog: Omit<BlogPost, 'id' | 'createdAt' | 'updatedAt'>): Promise<{ success: boolean; id?: number; message?: string }> {
  try {
    const existingBlogs = await readBlogFromSheet(true);

    const isDuplicate = existingBlogs.some(b =>
      b.title.toLowerCase().trim() === blog.title.toLowerCase().trim() ||
      (b.blogURL && blog.blogURL && b.blogURL === blog.blogURL)
    );

    if (isDuplicate) {
      return { success: false, message: 'A blog with this title or URL already exists' };
    }

    const newId = existingBlogs.length > 0 ? Math.max(...existingBlogs.map(b => b.id)) + 1 : 1;

    const newBlog: BlogPost = {
      ...blog,
      id: newId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const client = await clientPromise;
    const db = client.db("database0");
    await db.collection("blog").insertOne(newBlog);

    blogCache = null;

    return { success: true, id: newId };
  } catch (error) {
    return { success: false, message: 'Failed to add blog due to an error' };
  }
}

export function clearBlogCache(): void {
  blogCache = null;
}

export function getCacheStatus(): { cached: boolean; age: number; ttl: number } {
  if (!blogCache) {
    return { cached: false, age: 0, ttl: 0 };
  }
  
  const age = Date.now() - blogCache.timestamp;
  return {
    cached: true,
    age,
    ttl: blogCache.ttl
  };
}