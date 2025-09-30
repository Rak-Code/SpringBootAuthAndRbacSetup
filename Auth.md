# Auth.md - Postman Testing Guide

## Complete Postman Collection for Authentication Testing

### Base URL
```
http://localhost:8080
```

---

## 1. Login (Get JWT Token)

### Request
**POST** `/api/auth/login`

**Headers:**
```json
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

**Other Test Users:**
```json
// Onboarding User
{
  "username": "onboard_user",
  "password": "Onboard@123"
}

// Compliance User
{
  "username": "compliance_user",
  "password": "Compliance@123"
}

// Risk User
{
  "username": "risk_user",
  "password": "Risk@123"
}

// Approver User
{
  "username": "approver_user",
  "password": "Approver@123"
}

// Manager (Multi-role)
{
  "username": "manager_user",
  "password": "Manager@123"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 86400,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@laitusneo.com",
      "fullName": "System Administrator",
      "roles": ["ROLE_ADMIN"],
      "status": "ACTIVE"
    }
  },
  "error": null,
  "timestamp": "2025-01-15T10:30:00"
}
```

**Postman Tests Script:**
```javascript
// Save access token to environment variable
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("access_token", jsonData.data.accessToken);
    pm.environment.set("refresh_token", jsonData.data.refreshToken);
    console.log("Access token saved:", jsonData.data.accessToken);
}
```

---

## 2. Refresh Token

### Request
**POST** `/api/auth/refresh`

**Headers:**
```json
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "refreshToken": "{{refresh_token}}"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 86400
  },
  "error": null,
  "timestamp": "2025-01-15T10:35:00"
}
```

**Postman Tests Script:**
```javascript
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("access_token", jsonData.data.accessToken);
    console.log("New access token saved");
}
```

---

## 3. Validate Token

### Request
**GET** `/api/auth/validate`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Token is valid",
  "data": {
    "valid": true,
    "username": "admin",
    "userId": 1,
    "roles": ["ROLE_ADMIN"],
    "expiresIn": 86395,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@laitusneo.com",
      "fullName": "System Administrator",
      "roles": ["ROLE_ADMIN"],
      "status": "ACTIVE"
    }
  },
  "error": null,
  "timestamp": "2025-01-15T10:40:00"
}
```

---

## 4. Get Current User (Me)

### Request
**GET** `/api/auth/me`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User retrieved successfully",
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@laitusneo.com",
    "fullName": "System Administrator",
    "phoneNumber": "+1234567890",
    "roles": ["ROLE_ADMIN"],
    "status": "ACTIVE",
    "lastLoginAt": "2025-01-15T10:30:00",
    "createdAt": "2025-01-15T08:00:00",
    "updatedAt": "2025-01-15T10:30:00",
    "passwordChangeRequired": false,
    "accountExpiresAt": null,
    "passwordExpiresAt": "2025-04-15T08:00:00"
  },
  "error": null,
  "timestamp": "2025-01-15T10:45:00"
}
```

---

## 5. Change Password

### Request
**POST** `/api/auth/change-password`

**Headers:**
```json
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "currentPassword": "Admin@123",
  "newPassword": "NewAdmin@123",
  "confirmPassword": "NewAdmin@123"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Password changed successfully",
  "data": null,
  "error": null,
  "timestamp": "2025-01-15T10:50:00"
}
```

**Error Response (400 Bad Request) - Passwords don't match:**
```json
{
  "success": false,
  "message": "New password and confirmation do not match",
  "data": null,
  "error": "New password and confirmation do not match",
  "status": 400,
  "timestamp": "2025-01-15T10:51:00"
}
```

---

## 6. Register User (Admin Only)

### Request
**POST** `/api/auth/register`

**Headers:**
```json
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "username": "test_user",
  "email": "test@laitusneo.com",
  "password": "Test@123456",
  "fullName": "Test User",
  "phoneNumber": "+1234567890",
  "roles": ["ROLE_ONBOARD"]
}
```

**Expected Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": 7,
    "username": "test_user",
    "email": "test@laitusneo.com",
    "fullName": "Test User",
    "phoneNumber": "+1234567890",
    "roles": ["ROLE_ONBOARD"],
    "status": "ACTIVE",
    "lastLoginAt": null,
    "createdAt": "2025-01-15T10:55:00",
    "updatedAt": "2025-01-15T10:55:00",
    "passwordChangeRequired": false,
    "accountExpiresAt": null,
    "passwordExpiresAt": "2025-04-15T10:55:00"
  },
  "error": null,
  "timestamp": "2025-01-15T10:55:00",
  "status": 201
}
```

---

## 7. Logout

### Request
**POST** `/api/auth/logout`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Logout successful",
  "data": null,
  "error": null,
  "timestamp": "2025-01-15T11:00:00"
}
```

---

## 8. Get All Users (Admin Only)

### Request
**GET** `/api/users`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@laitusneo.com",
      "fullName": "System Administrator",
      "phoneNumber": "+1234567890",
      "roles": ["ROLE_ADMIN"],
      "status": "ACTIVE",
      "lastLoginAt": "2025-01-15T10:30:00",
      "createdAt": "2025-01-15T08:00:00",
      "updatedAt": "2025-01-15T10:30:00"
    },
    {
      "id": 2,
      "username": "onboard_user",
      "email": "onboard@laitusneo.com",
      "fullName": "Onboarding Personnel",
      "phoneNumber": "+1234567890",
      "roles": ["ROLE_ONBOARD"],
      "status": "ACTIVE",
      "lastLoginAt": null,
      "createdAt": "2025-01-15T08:00:00",
      "updatedAt": "2025-01-15T08:00:00"
    }
  ],
  "error": null,
  "timestamp": "2025-01-15T11:05:00"
}
```

---

## 9. Get User by ID (Admin Only)

### Request
**GET** `/api/users/1`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User retrieved successfully",
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@laitusneo.com",
    "fullName": "System Administrator",
    "phoneNumber": "+1234567890",
    "roles": ["ROLE_ADMIN"],
    "status": "ACTIVE",
    "lastLoginAt": "2025-01-15T10:30:00",
    "createdAt": "2025-01-15T08:00:00",
    "updatedAt": "2025-01-15T10:30:00",
    "passwordChangeRequired": false,
    "accountExpiresAt": null,
    "passwordExpiresAt": "2025-04-15T08:00:00"
  },
  "error": null,
  "timestamp": "2025-01-15T11:10:00"
}
```

---

## 10. Create User (Admin Only)

### Request
**POST** `/api/users`

**Headers:**
```json
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "username": "new_user",
  "email": "newuser@laitusneo.com",
  "password": "NewUser@123",
  "fullName": "New User Name",
  "phoneNumber": "+9876543210",
  "roles": ["ROLE_COMPLIANCE", "ROLE_RISK"]
}
```

**Expected Response (201 Created):**
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "id": 8,
    "username": "new_user",
    "email": "newuser@laitusneo.com",
    "fullName": "New User Name",
    "phoneNumber": "+9876543210",
    "roles": ["ROLE_COMPLIANCE", "ROLE_RISK"],
    "status": "ACTIVE",
    "lastLoginAt": null,
    "createdAt": "2025-01-15T11:15:00",
    "updatedAt": "2025-01-15T11:15:00",
    "passwordChangeRequired": true
  },
  "error": null,
  "timestamp": "2025-01-15T11:15:00",
  "status": 201
}
```

---

## 11. Update User (Admin Only)

### Request
**PUT** `/api/users/8`

**Headers:**
```json
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "username": "new_user",
  "email": "updated@laitusneo.com",
  "fullName": "Updated User Name",
  "phoneNumber": "+1111111111"
}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User updated successfully",
  "data": {
    "id": 8,
    "username": "new_user",
    "email": "updated@laitusneo.com",
    "fullName": "Updated User Name",
    "phoneNumber": "+1111111111",
    "roles": ["ROLE_COMPLIANCE", "ROLE_RISK"],
    "status": "ACTIVE",
    "updatedAt": "2025-01-15T11:20:00"
  },
  "error": null,
  "timestamp": "2025-01-15T11:20:00"
}
```

---

## 12. Update User Roles (Admin Only)

### Request
**PUT** `/api/users/8/roles`

**Headers:**
```json
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

**Body (raw JSON):**
```json
["ROLE_ONBOARD", "ROLE_COMPLIANCE"]
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User roles updated successfully",
  "data": {
    "id": 8,
    "username": "new_user",
    "email": "updated@laitusneo.com",
    "fullName": "Updated User Name",
    "roles": ["ROLE_ONBOARD", "ROLE_COMPLIANCE"],
    "status": "ACTIVE"
  },
  "error": null,
  "timestamp": "2025-01-15T11:25:00"
}
```

---

## 13. Lock User (Admin Only)

### Request
**POST** `/api/users/8/lock`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User locked successfully",
  "data": {
    "id": 8,
    "username": "new_user",
    "status": "LOCKED"
  },
  "error": null,
  "timestamp": "2025-01-15T11:30:00"
}
```

---

## 14. Unlock User (Admin Only)

### Request
**POST** `/api/users/8/unlock`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User unlocked successfully",
  "data": {
    "id": 8,
    "username": "new_user",
    "status": "ACTIVE"
  },
  "error": null,
  "timestamp": "2025-01-15T11:35:00"
}
```

---

## 15. Search Users (Admin Only)

### Request
**GET** `/api/users/search?searchTerm=admin`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Search completed successfully",
  "data": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@laitusneo.com",
      "fullName": "System Administrator",
      "roles": ["ROLE_ADMIN"],
      "status": "ACTIVE"
    }
  ],
  "error": null,
  "timestamp": "2025-01-15T11:40:00"
}
```

---

## 16. Get Users by Role (Admin Only)

### Request
**GET** `/api/users/by-role/ADMIN`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@laitusneo.com",
      "fullName": "System Administrator",
      "roles": ["ROLE_ADMIN"],
      "status": "ACTIVE"
    }
  ],
  "error": null,
  "timestamp": "2025-01-15T11:45:00"
}
```

---

## 17. Get User Statistics (Admin Only)

### Request
**GET** `/api/users/statistics`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Statistics retrieved successfully",
  "data": {
    "totalUsers": 8,
    "activeUsers": 7,
    "adminUsers": 1,
    "onboardUsers": 2,
    "complianceUsers": 2,
    "riskUsers": 2,
    "approverUsers": 1
  },
  "error": null,
  "timestamp": "2025-01-15T11:50:00"
}
```

---

## 18. Delete User (Admin Only)

### Request
**DELETE** `/api/users/8`

**Headers:**
```json
Authorization: Bearer {{access_token}}
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "User deleted successfully",
  "data": null,
  "error": null,
  "timestamp": "2025-01-15T11:55:00"
}
```

---

## Error Responses

### 401 Unauthorized (Invalid/Missing Token)
```json
{
  "timestamp": "2025-01-15T12:00:00",
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource",
  "path": "/api/users"
}
```

### 403 Forbidden (Insufficient Permissions)
```json
{
  "success": false,
  "message": "You don't have permission to access this resource",
  "error": "Access Denied",
  "status": 403,
  "path": "/api/users",
  "timestamp": "2025-01-15T12:05:00"
}
```

### 400 Bad Request (Validation Error)
```json
{
  "success": false,
  "message": "Validation failed",
  "data": {
    "username": "Username is required",
    "password": "Password must be at least 8 characters long"
  },
  "error": "Validation Error",
  "status": 400,
  "timestamp": "2025-01-15T12:10:00"
}
```

---

## Postman Environment Variables

Create these environment variables in Postman:

| Variable Name | Initial Value | Current Value |
|--------------|---------------|---------------|
| base_url | http://localhost:8080 | |
| access_token | | (auto-filled after login) |
| refresh_token | | (auto-filled after login) |

---

## Testing Workflow

1. **Login** - Use admin credentials to get tokens
2. **Save tokens** - Tokens saved automatically via test script
3. **Test authenticated endpoints** - Use {{access_token}} variable
4. **Test role-based access** - Login with different role users
5. **Test token refresh** - Use refresh token endpoint
6. **Test authorization** - Try accessing admin endpoints with non-admin user

Happy Testing!