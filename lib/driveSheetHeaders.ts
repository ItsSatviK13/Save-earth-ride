export const DRIVE_SHEET_HEADERS = [
  'id',
  'title',
  'location',
  'date',
  'participants',
  'treesTarget',
  'status',
  'registrationOpen',
  'description',
  'organizer',
  'contactEmail',
  'registrationDeadline',
  'meetingPoint',
  'endingPoint',
  'duration',
  'difficulty',
  'logo',
  'createdAt',
  'updatedAt'
];

export const DRIVE_SHEET_NAME = 'drive';

export function validateDriveSheetData(data: any) {
  const requiredFields = ['title', 'location', 'date', 'organizer', 'contactEmail'];
  const missingFields = requiredFields.filter(field => !data[field]);
  
  if (missingFields.length > 0) {
    throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(data.contactEmail)) {
    throw new Error('Invalid email format');
  }
  
  if (data.date && isNaN(Date.parse(data.date))) {
    throw new Error('Invalid date format');
  }
  
  return true;
}