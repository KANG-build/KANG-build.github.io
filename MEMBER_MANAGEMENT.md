# Member Management Feature Documentation

## Overview

The SRC Lab website now includes an interactive member management system that allows lab administrators to manage the People and Alumni sections through a drag-and-drop interface.

## Features

### 1. Drag-and-Drop Member Management

Lab members with admin privileges can drag and drop people cards between the "People" and "Alumni" sections on the People page.

#### How to Use:
1. **Login**: First, log in as a lab member through `/pages/login.html`
2. **Navigate to People Page**: Go to `/pages/people.html`
3. **Drag Members**: 
   - Click and hold a member card
   - Drag it to the Alumni section to move them to alumni
   - Drag an alumni card to the People section to restore them as active members
4. **Confirm**: A confirmation dialog will appear before the move is executed
5. **Provide Details**: When moving alumni back to members, you'll be prompted to enter their role and email

### 2. Alumni Filtering in Signup

When new users sign up on the website, only current lab members (not alumni) are shown in the member linking section. This ensures that:
- Alumni cannot be accidentally associated with new user accounts
- Only active lab members can be linked during registration
- The member selection interface remains clean and relevant

### 3. Automatic Data Management

The system automatically:
- Updates YAML data files (`_data/people/member.yml` and `_data/people/alumni.yml`)
- Rebuilds the Jekyll site to reflect changes
- Preserves member information (name, photo, link) when moving between sections
- Strips role and email when moving to alumni (they only show name and photo)
- Adds role and email when moving back to active members

## Technical Details

### API Endpoints

#### POST `/api/members/move-to-alumni`
Moves a member from the People section to Alumni.

**Request Body:**
```json
{
  "memberName": "John Doe"
}
```

**Response:**
```json
{
  "success": true,
  "message": "John Doe moved to alumni",
  "member": {
    "name": "John Doe",
    "photo": "/image/people/johndoe.jpg"
  }
}
```

**Authentication Required:** Yes (member role)

#### POST `/api/members/move-to-members`
Moves an alumni member back to the People section.

**Request Body:**
```json
{
  "memberName": "Jane Smith",
  "role": "PhD Student",
  "email": "jane *at* jnu.ac.kr"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Jane Smith moved to members",
  "member": {
    "name": "Jane Smith",
    "photo": "/image/people/janesmith.jpg",
    "role": "PhD Student",
    "email": "jane *at* jnu.ac.kr"
  }
}
```

**Authentication Required:** Yes (member role)

### Data Files

#### `_data/people/member.yml`
Contains active lab members with full details:
```yaml
- name: John Doe
  photo: "/image/people/johndoe.jpg"
  role: Master degree candidate
  email: johndoe *at* jnu.ac.kr
  link: "/pages/member.html"  # optional
```

#### `_data/people/alumni.yml`
Contains former lab members with minimal information:
```yaml
- name: Jane Smith
  photo: "/image/people/janesmith.jpg"
  link: "/pages/alumni-member.html"  # optional
```

### Security

- Only authenticated users with "member" role can move people between sections
- The "Join us!" placeholder cannot be moved to alumni
- All API calls are protected with JWT authentication
- CSRF protection is implemented through SameSite cookies

### Frontend Implementation

The drag-and-drop functionality is implemented using native HTML5 Drag and Drop API with:
- Visual feedback (opacity changes, hover effects)
- Drop zones with colored borders
- Confirmation dialogs before operations
- Automatic page reload after successful operations
- Error handling with user-friendly messages

## Maintenance

### Adding New Members

To add a new member manually, edit `_data/people/member.yml`:

```yaml
- name: New Member
  photo: "/image/people/newmember.jpg"
  role: Undergraduate Researcher
  email: newmember *at* jnu.ac.kr
```

Then rebuild the Jekyll site:
```bash
jekyll build
```

### Removing Members

Members can be removed by:
1. Using the drag-and-drop interface to move them to alumni
2. Or manually editing the YAML files

## Troubleshooting

### Drag-and-drop not working?
- Ensure you are logged in as a member
- Check browser console for JavaScript errors
- Verify that the API server is running

### Changes not reflected?
- Wait for Jekyll rebuild to complete (automatic)
- Clear browser cache and reload
- Check server logs for rebuild errors

### Permission denied errors?
- Verify user has "member" role
- Check authentication token is valid
- Re-login if session expired

## Future Enhancements

Potential improvements for future versions:
- Bulk member operations
- Member role editing without moving
- Member search and filtering
- Import/export functionality
- Audit log for member changes
- Email notifications on status changes
