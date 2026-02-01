# Growmore Exchange Backend - Railway Deployment

## Quick Setup (5 minutes)

### Step 1: Create Railway Account
1. Go to https://railway.app
2. Sign up with GitHub

### Step 2: Create New Project
1. Click "New Project"
2. Select "Deploy from GitHub repo"
3. Connect your GitHub and select this repo

### Step 3: Add MongoDB Database
1. In your project, click "+ New"
2. Select "Database" → "MongoDB"
3. Wait for it to deploy
4. Click on MongoDB → "Variables" tab
5. Copy the MONGO_URL

### Step 4: Set Environment Variables
In your backend service, go to "Variables" tab and add:

| Variable | Value |
|----------|-------|
| MONGO_URL | (paste from MongoDB) |
| DB_NAME | growmore_exchange |
| JWT_SECRET | growmore_jwt_secret_2025_railway |
| CORS_ORIGINS | * |
| UPI_ID | trustrentacar99-9@okhdfcbank |
| PAYEE_NAME | Growmore Exchange |
| ADMIN_MOBILE | 9999999999 |

### Step 5: Get Your Backend URL
After deployment, Railway will give you a URL like:
https://growmore-backend-production.up.railway.app

Use this URL in your frontend!

## First Time Admin Setup
After deployment, create admin user by calling:
POST https://your-railway-url.up.railway.app/api/admin/setup
