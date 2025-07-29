// app/api/admins/route.ts

import { NextResponse, NextRequest } from 'next/server';
import { readAdminsFromSheet, writeAdminsToSheet } from '@/lib/googleSheetHelpers';

export async function GET() {
  const data = await readAdminsFromSheet();
  return NextResponse.json({ data });
}

export const dynamic = "force-static";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    console.log('Request body:', body);
    
    // Validate the request body
    if (!Array.isArray(body)) {
      return NextResponse.json(
        { error: 'Request body must be an array of admin objects' },
        { status: 400 }
      );
    }

    await writeAdminsToSheet(body);
    return NextResponse.json({ success: true });
  } catch (error: any) {
    console.error('POST /api/admins error:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to update admin data' },
      { status: 500 }
    );
  }
}