# A R GOLD - Attendance Management System API Documentation

## Overview
This document outlines the API endpoints for A R GOLD's attendance management system. The system provides comprehensive features for managing employee attendance, biometric verification, location tracking, and analytics.

## Authentication

### Login
```
POST /api/mobile/login
Content-Type: application/json

Request:
{
    "employee_id": "EMP001",
    "password": "password123"
}

Response:
{
    "success": true,
    "token": "jwt_token_here",
    "employee": {
        "id": 1,
        "name": "John Doe",
        "role": "employee"
    }
}
```

All subsequent requests must include the JWT token in the Authorization header:
```
Authorization: Bearer jwt_token_here
```

## Attendance Management

### Check In
```
POST /api/mobile/check-in
Content-Type: application/json

Request:
{
    "latitude": "12.9716",
    "longitude": "77.5946",
    "device_info": {
        "device_id": "device_uuid",
        "device_type": "mobile",
        "device_name": "iPhone 12"
    },
    "is_remote": false
}

Response:
{
    "success": true,
    "message": "Check-in successful"
}
```

### Check Out
```
POST /api/mobile/check-out
Content-Type: application/json

Request:
{
    "latitude": "12.9716",
    "longitude": "77.5946",
    "device_info": {
        "device_id": "device_uuid",
        "device_type": "mobile",
        "device_name": "iPhone 12"
    }
}

Response:
{
    "success": true,
    "message": "Check-out successful"
}
```

## Biometric Integration

### Register Biometric
```
POST /api/biometric/register
Content-Type: application/json

Request:
{
    "employee_id": 1,
    "type": "face",  // or "fingerprint"
    "data": "base64_encoded_biometric_data"
}

Response:
{
    "success": true,
    "message": "face registered successfully"
}
```

### Verify Biometric
```
POST /api/biometric/verify
Content-Type: application/json

Request:
{
    "employee_id": "EMP001",
    "type": "face",  // or "fingerprint"
    "data": "base64_encoded_biometric_data"
}

Response:
{
    "success": true,
    "employee_id": 1
}
```

## Location Management

### Get Office Locations
```
GET /api/locations

Response:
{
    "locations": [
        {
            "id": 1,
            "name": "Main Office",
            "address": "123 Main St",
            "latitude": 12.9716,
            "longitude": 77.5946,
            "radius": 100
        }
    ]
}
```

### Add Office Location (Admin Only)
```
POST /api/locations
Content-Type: application/json

Request:
{
    "name": "Branch Office",
    "address": "456 Branch St",
    "latitude": 12.9816,
    "longitude": 77.5846,
    "radius": 100
}

Response:
{
    "success": true,
    "location_id": 2
}
```

## Analytics

### Get Attendance Analytics (Admin Only)
```
GET /api/analytics/attendance?start_date=2024-01-01&end_date=2024-01-31&department=IT

Response:
{
    "total_present": 150,
    "total_absent": 10,
    "total_late": 5,
    "total_overtime_hours": 45.5,
    "department_wise": {
        "IT": {
            "present": 80,
            "absent": 5
        }
    },
    "daily_attendance": {
        "2024-01-01": {
            "present": 8,
            "absent": 2
        }
    }
}
```

## Error Responses

All endpoints may return the following error responses:

```
401 Unauthorized:
{
    "error": "No token provided"
}

403 Forbidden:
{
    "error": "Unauthorized access"
}

400 Bad Request:
{
    "error": "Invalid location"
}

500 Internal Server Error:
{
    "error": "Error message here"
}
```

## Implementation Notes

1. Mobile App Integration:
   - Use secure HTTPS connections
   - Implement token refresh mechanism
   - Handle offline mode gracefully
   - Cache location data

2. Biometric Implementation:
   - Face recognition requires good lighting
   - Store biometric data securely
   - Implement liveness detection
   - Consider multiple face angles

3. Location Validation:
   - Account for GPS accuracy
   - Implement geo-fencing
   - Handle different time zones
   - Consider network connectivity issues

4. Security Considerations:
   - Implement rate limiting
   - Monitor for suspicious patterns
   - Encrypt sensitive data
   - Regular security audits 