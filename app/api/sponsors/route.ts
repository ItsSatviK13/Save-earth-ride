import { NextRequest, NextResponse } from 'next/server'
import {
  getSponsorData,
  addSponsorData,
  updateSponsorData,
  deleteSponsorData,
  SponsorData
} from '@/lib/sponsorSheetHelpers'

export const dynamic = 'force-static'

export async function GET() {
  try {
    return NextResponse.json({ success: true, data: await getSponsorData() })
  } catch (err) {
    console.error(err)
    return NextResponse.json(
      { success: false, error: 'Failed to fetch sponsors' },
      { status: 500 }
    )
  }
}

type Payload =
  | { action: 'add';    data: Omit<SponsorData, 'id'> }
  | { action: 'update'; data: Partial<SponsorData> & { id: number } }
  | { action: 'delete'; data: { id: number } }

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Payload

    switch (body.action) {
      case 'add':
        return NextResponse.json({
          success: true,
          data: await addSponsorData(body.data)
        })

      case 'update': {
        const { id, ...u } = body.data
        return NextResponse.json({
          success: true,
          data: await updateSponsorData(id, u)
        })
      }

      case 'delete':
        await deleteSponsorData(body.data.id)
        return NextResponse.json({ success: true })

      default:
        return NextResponse.json(
          { success: false, error: 'Invalid action' },
          { status: 400 }
        )
    }
  } catch (err) {
    console.error(err)
    return NextResponse.json(
      { success: false, error: 'Failed to process request' },
      { status: 500 }
    )
  }
}