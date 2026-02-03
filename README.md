# Node.js Auth System

A robust, production-ready authentication backend built with Node.js, Express, TypeScript, and MongoDB.

## 🚀 Features

- **Modular Architecture**: Organized by features (`src/modules/*`).
- **Authentication**: JWT-based access and refresh tokens (HttpOnly cookies).
- **Security**: Rate limiting, SHA256 token hashing, Bcrypt password hashing.
- **2FA**: Two-Factor Authentication support (Email/OTP).
- **Google Auth**: Integrated Google OAuth verification.
- **Type Safety**: Full TypeScript support with Zod validation.

## 🛠️ Tech Stack

- **Runtime**: Node.js
- **Framework**: Express
- **Language**: TypeScript
- **Database**: MongoDB (Mongoose)
- **Validation**: Zod
- **Email**: Nodemailer

## 📂 Project Structure

```
src/
├── config/         # Environment & DB setup
├── middleware/     # Auth, Rate Limit, Error handling
├── modules/        # Feature modules (Auth, User, Mail, Token, OTP)
├── utils/          # Helpers (Hash, Cookies, IP)
├── app.ts          # Express App Setup
└── server.ts       # Entry Point
```

## ⚡ Getting Started

### 1. Installation

```bash
npm install
```

### 2. Environment Variables

Create a `.env` file in the root directory:

```env
MONGO_URI=mongodb://localhost:27017/auth-db
JWT_ACCESS_SECRET=your_access_secret_key
JWT_REFRESH_SECRET=your_refresh_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
MAIL_USER=your_email@gmail.com
MAIL_PASS=your_email_app_password
PORT=4000
```

### 3. Run Development Server

```bash
npm run dev
```
The server will start on `http://localhost:4000`.

## 🔌 API Routes

**Base URL**: `/auth`

### Public
- `POST /signup` - Register new user
- `POST /login` - Login (returns access token & refresh cookie)
- `POST /verify-email` - Verify email OTP
- `POST /verify-2fa` - Verify 2FA OTP during login
- `POST /refresh` - Refresh access token
- `POST /google-login` - Login with Google ID Token
- `POST /forgot-password` - Request password reset
- `POST /reset-password` - Reset password with token

### Protected (Requires `Authorization: Bearer <token>`)
- `GET /me` - Get current user profile
- `POST /2fa/enable` - Enable 2FA
- `POST /2fa/disable` - Disable 2FA
- `POST /logout` - Logout user

## 🧪 Testing

Refer to `testing_guide.md` for detailed Postman instructions.
