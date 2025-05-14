# Attendance Management System

A comprehensive attendance management system built with Flask.

## Features
- Employee attendance tracking
- Leave management
- Team management
- Performance reviews
- Salary management
- QR code-based attendance
- Mobile app support
- Location-based attendance

## Deployment Steps

### Local Development
1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```

### Deploying to Render
1. Create a Render account at https://render.com
2. Create a new Web Service
3. Connect your GitHub repository
4. Configure the following:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
5. Add the following environment variables:
   - `SECRET_KEY`: Your secret key
   - `DATABASE_URL`: Your database URL (if using external database)

## Environment Variables
- `SECRET_KEY`: Secret key for session management
- `DATABASE_URL`: Database connection URL (optional)
- `PORT`: Port number (default: 5000)

## Database Setup
The application uses SQLite by default. For production, it's recommended to use PostgreSQL. 