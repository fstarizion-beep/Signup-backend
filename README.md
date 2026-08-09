# STARIZION Mini Auth Server

Backend for STARIZION signup/login.

## Signup fields

- First Name
- Last Name
- Username
- Email Address
- Phone Number
- Country
- Password
- Confirm Password

## Included

- MongoDB Atlas connection
- Password hashing with bcrypt
- JWT authentication
- Email/verification code flow
- Forgot/reset password
- Rate limiting
- Basic bot/risk detection
- Optional SMTP email sending
- CORS
- Health endpoint

## Setup

1. Install Node.js 18+.
2. Open this folder in a terminal.
3. Run:
   `npm install`
4. Open `config.env`.
5. Replace `MONGODB_URI` with your MongoDB connection string.
6. Replace `JWT_SECRET` with a long random secret.
7. Optionally configure SMTP.
8. Run:
   `npm start`

The server runs on `http://localhost:5000` by default.

## API

POST `/api/auth/signup`
POST `/api/auth/verify-email`
POST `/api/auth/resend-code`
POST `/api/auth/login`
POST `/api/auth/forgot-password`
POST `/api/auth/reset-password`
GET `/api/auth/me` with `Authorization: Bearer <token>`
GET `/api/health`

## Signup example

```json
{
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe",
  "email": "john@example.com",
  "phoneNumber": "+2348012345678",
  "country": "Nigeria",
  "password": "StrongPassword123!",
  "confirmPassword": "StrongPassword123!"
}
```

## Security note

The risk engine is intentionally a server-side rule-based layer. It should not be treated as a magical AI or as the sole authentication control. CAPTCHA/Turnstile and stronger behavioural/AI scoring can be plugged into `src/services/riskEngine.js` later without exposing secrets to the frontend.

Do not put MongoDB credentials in frontend code.
