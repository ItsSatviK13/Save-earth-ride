import { NextRequest, NextResponse } from 'next/server';
import { appendToGallerySheet, updateGallerySheet, deleteFromGallerySheet, getGalleryData } from '@/lib/gallerySheetHelpers';

export async function GET() {
  try {
    const data = await getGalleryData();
    return NextResponse.json({ success: true, data });
  } catch (error) {
    console.error('Error fetching gallery data:', error);
    return NextResponse.json({ success: false, error: 'Failed to fetch gallery data' }, { status: 500 });
  }
}
export const dynamic = "force-static";
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, data } = body;

    switch (action) {
      case 'add':
        const newItem = await appendToGallerySheet(data);
        return NextResponse.json({ success: true, data: newItem });

      case 'update':
        const updatedItem = await updateGallerySheet(data);
        return NextResponse.json({ success: true, data: updatedItem });

      case 'delete':
        await deleteFromGallerySheet(data.id);
        return NextResponse.json({ success: true, message: 'Item deleted successfully' });

      default:
        return NextResponse.json({ success: false, error: 'Invalid action' }, { status: 400 });
    }
  } catch (error) {
    console.error('Error processing gallery request:', error);
    return NextResponse.json({ success: false, error: 'Failed to process request' }, { status: 500 });
  }
}