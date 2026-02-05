from fastapi import FastAPI, APIRouter, HTTPException, status, UploadFile, File, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import bcrypt
import jwt
import random
import base64
from bson import ObjectId
import qrcode
from io import BytesIO

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Secret
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 720  # 30 days

# Security
security = HTTPBearer()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ========================= MODELS =========================

# User Models
class UserSignup(BaseModel):
    full_name: str
    mobile: str
    referral_code: str
    login_password: str
    transaction_password: str

class UserLogin(BaseModel):
    mobile: str
    password: str

class OTPVerify(BaseModel):
    mobile: str
    otp: str

class ForgotPasswordWithDOB(BaseModel):
    mobile: str
    date_of_birth: str  # DD/MM/YYYY format
    new_password: str

class UserProfile(BaseModel):
    full_name: str
    mobile: str
    referral_code: str
    my_referral_code: str
    is_active: bool
    wallet_balance: float = 0.0
    total_income: float = 0.0
    today_income: float = 0.0
    referral_income: float = 0.0
    reward_income: float = 0.0
    created_at: datetime

# Package Models
class Package(BaseModel):
    id: str
    amount: float
    daily_income: float
    duration_days: int
    total_return: float
    is_active: bool = True

# Payment Models
class PaymentSubmit(BaseModel):
    package_id: str
    screenshot_base64: str
    utr_number: str
    transaction_password: str

class PaymentResponse(BaseModel):
    id: str
    user_id: str
    package_id: str
    amount: float
    screenshot_base64: str
    status: str  # pending, approved, rejected
    created_at: datetime
    verified_at: Optional[datetime] = None

# Withdrawal Models
class WithdrawalRequest(BaseModel):
    amount: float
    bank_name: Optional[str] = None
    account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    upi_id: Optional[str] = None
    transaction_password: str

class WithdrawalResponse(BaseModel):
    id: str
    user_id: str
    amount: float
    admin_charge: float
    final_amount: float
    status: str  # pending, successful, rejected
    created_at: datetime
    processed_at: Optional[datetime] = None
    admin_utr: Optional[str] = None
    admin_screenshot: Optional[str] = None

# Admin Withdrawal Verification with UTR
class WithdrawalVerificationWithUTR(BaseModel):
    withdrawal_id: str
    status: str  # approved, rejected
    admin_utr: Optional[str] = None
    admin_screenshot: Optional[str] = None

# Admin Settings
class AdminSettings(BaseModel):
    upi_id: str
    payee_name: Optional[str] = "Growmore Exchange"

# Bank Details
class BankDetails(BaseModel):
    bank_name: str
    account_number: str
    ifsc_code: str
    account_holder_name: str
    is_primary: bool = False

class UPIDetails(BaseModel):
    upi_id: str
    is_primary: bool = False

# Ticket Models
class TicketCreate(BaseModel):
    subject: str
    message: str

class TicketResponse(BaseModel):
    id: str
    user_id: str
    subject: str
    message: str
    status: str  # open, closed
    reply: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

# Admin Models
class AdminLogin(BaseModel):
    email: str
    password: str

class AdminChangePassword(BaseModel):
    current_password: str
    new_password: str

class PaymentVerification(BaseModel):
    payment_id: str
    action: str  # approve, reject

class WithdrawalVerification(BaseModel):
    withdrawal_id: str
    action: str  # approve, reject

class UserManagement(BaseModel):
    user_id: str
    action: str  # activate, deactivate, block

# ========================= HELPER FUNCTIONS =========================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(credentials.credentials)
    user = await db.users.find_one({"_id": ObjectId(payload['user_id'])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(credentials.credentials)
    # Try to find in admins collection first
    admin = await db.admins.find_one({"_id": ObjectId(payload['user_id'])})
    if admin:
        return admin
    # If not found in admins, try users collection (for backward compatibility)
    user = await db.users.find_one({"_id": ObjectId(payload['user_id'])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Download backup endpoint
@api_router.get("/download-backup")
async def download_backup():
    """Download the application backup file"""
    backup_path = ROOT_DIR / "static" / "growmore-exchange-backup.zip"
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup file not found")
    return FileResponse(
        path=str(backup_path),
        filename="growmore-exchange-backup.zip",
        media_type="application/zip"
    )

# Download web build for Hostinger
@api_router.get("/download-web")
async def download_web():
    """Download the web build for Hostinger hosting"""
    web_path = ROOT_DIR / "static" / "growmore-web-hostinger.zip"
    if not web_path.exists():
        raise HTTPException(status_code=404, detail="Web build not found")
    return FileResponse(
        path=str(web_path),
        filename="growmore-web-hostinger.zip",
        media_type="application/zip"
    )

# Download User Panel for Hostinger
@api_router.get("/download-user-panel")
async def download_user_panel():
    """Download Complete Panel (User + Admin) for Hostinger"""
    path = ROOT_DIR / "static" / "growmore-v7.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Panel not found")
    return FileResponse(path=str(path), filename="growmore-complete.zip", media_type="application/zip")

# Download Admin Panel - Same as user panel (combined build)
@api_router.get("/download-admin-panel")
async def download_admin_panel():
    """Download Complete Panel (User + Admin) for Hostinger"""
    path = ROOT_DIR / "static" / "growmore-final.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Panel not found")
    return FileResponse(path=str(path), filename="growmore-complete.zip", media_type="application/zip")

# Download Database Export
@api_router.get("/download-database")
async def download_database():
    """Download MongoDB database export"""
    path = ROOT_DIR / "static" / "database-export.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Database export not found")
    return FileResponse(path=str(path), filename="database-export.zip", media_type="application/zip")

# Download Railway Backend
@api_router.get("/download-railway-backend")
async def download_railway_backend():
    """Download Railway Backend files for deployment"""
    path = ROOT_DIR / "static" / "railway-backend.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Railway backend not found")
    return FileResponse(path=str(path), filename="railway-backend.zip", media_type="application/zip")

def generate_referral_code(length: int = 8) -> str:
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def generate_user_id() -> str:
    """Generate unique 6-digit user ID in format GMX-XXXXXX"""
    digits = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    return f"GMX-{digits}"

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

async def get_payment_settings():
    """Get payment settings from database or environment"""
    settings = await db.admin_settings.find_one({"type": "payment"})
    if settings:
        return settings.get('upi_id'), settings.get('payee_name', 'Growmore Exchange')
    return os.environ.get('UPI_ID', 'trustrentacar99-9@okhdfcbank'), os.environ.get('PAYEE_NAME', 'Growmore Exchange')

def generate_upi_qr_sync(amount: float, reference_id: str, upi_id: str, payee_name: str) -> str:
    """Generate UPI QR code with payment details (sync version)"""
    # Create UPI deep link
    upi_string = f"upi://pay?pa={upi_id}&pn={payee_name}&am={amount}&cu=INR&tn=GrowmoreRef{reference_id}"
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(upi_string)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

# ========================= AUTHENTICATION ENDPOINTS =========================

@api_router.post("/auth/reset-transaction-password")
async def reset_transaction_password(data: dict, user = Depends(get_current_user)):
    """Reset transaction password for the logged-in user"""
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    
    hashed_password = hash_password(new_password)
    await db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"transaction_password": hashed_password}}
    )
    
    return {"success": True, "message": "Transaction password updated successfully!"}

@api_router.post("/auth/reset-login-password")
async def reset_login_password(data: dict, user = Depends(get_current_user)):
    """Reset login password for the logged-in user"""
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        raise HTTPException(status_code=400, detail="Current and new password are required")
    
    if len(new_password) < 4:
        raise HTTPException(status_code=400, detail="New password must be at least 4 characters")
    
    # Verify current password
    if not verify_password(current_password, user.get('login_password', '')):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    hashed_password = hash_password(new_password)
    await db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"login_password": hashed_password}}
    )
    
    return {"success": True, "message": "Login password updated successfully!"}

@api_router.post("/auth/add-demo-fund")
async def add_demo_fund(user = Depends(get_current_user)):
    """Add demo fund for testing withdrawal - ₹5000"""
    await db.users.update_one(
        {"_id": user['_id']},
        {"$inc": {"wallet_balance": 5000}}
    )
    
    # Get updated balance
    updated_user = await db.users.find_one({"_id": user['_id']})
    
    return {
        "success": True, 
        "message": "₹5000 demo fund added successfully!",
        "new_balance": updated_user.get('wallet_balance', 0)
    }

@api_router.post("/auth/send-otp")
async def send_otp(data: dict):
    mobile = data.get('mobile')
    otp = generate_otp()
    
    # Store OTP in database (expires in 10 minutes)
    await db.otps.update_one(
        {"mobile": mobile},
        {"$set": {"otp": otp, "created_at": datetime.utcnow(), "expires_at": datetime.utcnow() + timedelta(minutes=10)}},
        upsert=True
    )
    
    # In production, send SMS here
    # For now, return OTP for testing
    return {"success": True, "message": "OTP sent successfully", "otp": otp}

@api_router.post("/auth/signup")
async def signup(data: dict):
    """User signup with DOB for password recovery"""
    full_name = data.get('full_name')
    mobile = data.get('mobile')
    date_of_birth = data.get('date_of_birth')  # DD/MM/YYYY
    referral_code = data.get('referral_code')
    login_password = data.get('login_password')
    transaction_password = data.get('transaction_password')
    
    # Validate required fields
    if not all([full_name, mobile, date_of_birth, referral_code, login_password, transaction_password]):
        raise HTTPException(status_code=400, detail="All fields are required")
    
    # Check if mobile already exists
    existing_user = await db.users.find_one({"mobile": mobile})
    if existing_user:
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    # Verify referral code
    referrer = await db.users.find_one({"my_referral_code": referral_code})
    if not referrer:
        raise HTTPException(status_code=400, detail="Invalid referral code")
    
    # Create user
    my_referral_code = generate_referral_code()
    user_id = generate_user_id()
    
    # Ensure unique user_id
    while await db.users.find_one({"user_id": user_id}):
        user_id = generate_user_id()
    
    user_doc = {
        "user_id": user_id,
        "full_name": full_name,
        "mobile": mobile,
        "date_of_birth": hash_password(date_of_birth),  # Store DOB hashed for security
        "referral_code": referral_code,
        "my_referral_code": my_referral_code,
        "login_password": hash_password(login_password),
        "transaction_password": hash_password(transaction_password),
        "is_active": False,
        "wallet_balance": 0.0,
        "total_income": 0.0,
        "today_income": 0.0,
        "referral_income": 0.0,
        "reward_income": 0.0,
        "created_at": datetime.utcnow(),
        "is_blocked": False,
        "reset_failed_attempts": 0,
        "reset_last_attempt": None
    }
    
    result = await db.users.insert_one(user_doc)
    
    # Track referral
    await db.referrals.insert_one({
        "referrer_id": str(referrer['_id']),
        "referred_id": str(result.inserted_id),
        "created_at": datetime.utcnow()
    })
    
    token = create_token(str(result.inserted_id))
    return {"success": True, "token": token, "message": "Signup successful"}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"mobile": data.mobile})
    if not user or not verify_password(data.password, user['login_password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if user.get('is_blocked', False):
        raise HTTPException(status_code=403, detail="Account is blocked")
    
    token = create_token(str(user['_id']))
    return {"success": True, "token": token}

@api_router.post("/auth/verify-otp")
async def verify_otp(data: OTPVerify):
    otp_doc = await db.otps.find_one({"mobile": data.mobile})
    if not otp_doc or otp_doc['otp'] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if otp_doc['expires_at'] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP expired")
    
    return {"success": True, "message": "OTP verified"}

@api_router.post("/auth/forgot-password")
async def forgot_password(data: dict):
    """Reset password using DOB verification - No OTP needed"""
    mobile = data.get('mobile')
    date_of_birth = data.get('date_of_birth')  # DD/MM/YYYY format
    new_password = data.get('new_password')
    
    if not mobile or not date_of_birth or not new_password:
        raise HTTPException(status_code=400, detail="All fields are required")
    
    # Find user
    user = await db.users.find_one({"mobile": mobile})
    if not user:
        # Generic error for security
        raise HTTPException(status_code=400, detail="Invalid credentials. Please check your details.")
    
    # Check failed attempts (security measure)
    failed_attempts = user.get('reset_failed_attempts', 0)
    last_attempt_time = user.get('reset_last_attempt')
    
    # Lock for 30 minutes after 3 failed attempts
    if failed_attempts >= 3 and last_attempt_time:
        time_diff = datetime.utcnow() - last_attempt_time
        if time_diff.total_seconds() < 1800:  # 30 minutes
            remaining = int((1800 - time_diff.total_seconds()) / 60)
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {remaining} minutes.")
        else:
            # Reset counter after lock period
            failed_attempts = 0
    
    # Verify DOB
    stored_dob = user.get('date_of_birth')
    if not stored_dob:
        raise HTTPException(status_code=400, detail="Password reset not available. Contact support.")
    
    # Compare DOB (hashed comparison)
    if not verify_password(date_of_birth, stored_dob):
        # Increment failed attempts
        await db.users.update_one(
            {"mobile": mobile},
            {
                "$set": {"reset_last_attempt": datetime.utcnow()},
                "$inc": {"reset_failed_attempts": 1}
            }
        )
        raise HTTPException(status_code=400, detail="Invalid credentials. Please check your details.")
    
    # DOB verified - Reset password
    await db.users.update_one(
        {"mobile": mobile},
        {
            "$set": {
                "login_password": hash_password(new_password),
                "reset_failed_attempts": 0,
                "reset_last_attempt": None
            }
        }
    )
    
    return {"success": True, "message": "Password reset successfully!"}

# ========================= USER ENDPOINTS =========================

@api_router.get("/user/profile")
async def get_profile(user = Depends(get_current_user)):
    return {
        "success": True,
        "user": {
            "id": str(user['_id']),
            "user_id": user.get('user_id', 'N/A'),
            "full_name": user['full_name'],
            "mobile": user['mobile'],
            "my_referral_code": user.get('my_referral_code', 'N/A'),
            "is_active": user.get('is_active', False),
            "wallet_balance": user.get('wallet_balance', 0),
            "total_income": user.get('total_income', 0),
            "today_income": user.get('today_income', 0),
            "referral_income": user.get('referral_income', 0),
            "reward_income": user.get('reward_income', 0),
            "created_at": user.get('created_at', datetime.utcnow())
        }
    }

@api_router.get("/user/dashboard")
async def get_dashboard(user = Depends(get_current_user)):
    # Get active package
    active_package = await db.user_packages.find_one({
        "user_id": str(user['_id']),
        "is_active": True,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    # Get referral count
    referral_count = await db.referrals.count_documents({"referrer_id": str(user['_id'])})
    
    # Get total invested amount (approved deposits)
    approved_deposits = await db.payments.find({
        "user_id": str(user['_id']),
        "status": "approved"
    }).to_list(100)
    total_invested = sum(d.get('amount', 0) for d in approved_deposits)
    
    return {
        "success": True,
        "dashboard": {
            "today_income": user.get('today_income', 0),
            "total_income": user.get('total_income', 0),
            "referral_income": user.get('referral_income', 0),
            "reward_income": user.get('reward_income', 0),
            "wallet_balance": user.get('wallet_balance', 0),
            "total_invested": total_invested,
            "is_active": user.get('is_active', False),
            "has_active_package": active_package is not None,
            "active_package_name": active_package.get('package_name') if active_package else None,
            "referral_count": referral_count,
            "my_referral_code": user.get('my_referral_code', '')
        }
    }

# ========================= PACKAGE ENDPOINTS =========================

@api_router.get("/packages/list")
async def get_packages():
    packages = [
        {"id": "copper", "name": "Copper", "amount": 1500, "daily_income": 100, "duration_days": 30, "total_return": 3000, "is_active": True},
        {"id": "crypto", "name": "Crypto", "amount": 3000, "daily_income": 200, "duration_days": 30, "total_return": 6000, "is_active": True},
        {"id": "aipower", "name": "AI Power", "amount": 6000, "daily_income": 400, "duration_days": 30, "total_return": 12000, "is_active": True},
        {"id": "solar", "name": "Solar Energy", "amount": 12000, "daily_income": 800, "duration_days": 30, "total_return": 24000, "is_active": True},
        {"id": "gold", "name": "Gold", "amount": 24000, "daily_income": 1600, "duration_days": 30, "total_return": 48000, "is_active": True},
        {"id": "silver", "name": "Silver", "amount": 48000, "daily_income": 3200, "duration_days": 30, "total_return": 96000, "is_active": True},
    ]
    return {"success": True, "packages": packages}

@api_router.get("/packages/upi-details/{package_id}")
async def get_upi_details(package_id: str, user = Depends(get_current_user)):
    # Get package details
    packages_response = await get_packages()
    package = next((p for p in packages_response['packages'] if p['id'] == package_id), None)
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    # Generate unique reference ID
    reference_id = str(uuid.uuid4())[:8].upper()
    
    # Get payment settings from database
    upi_id, payee_name = await get_payment_settings()
    
    # Generate QR code with amount
    qr_code_base64 = generate_upi_qr_sync(package['amount'], reference_id, upi_id, payee_name)
    
    # Store QR session with expiry
    await db.qr_sessions.insert_one({
        "user_id": str(user['_id']),
        "package_id": package_id,
        "reference_id": reference_id,
        "amount": package['amount'],
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "is_expired": False
    })
    
    return {
        "success": True,
        "upi_id": upi_id,
        "qr_code_base64": qr_code_base64,
        "reference_id": reference_id,
        "amount": package['amount'],
        "package_name": package['name'],
        "valid_for_minutes": 10,
        "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    }

@api_router.post("/packages/purchase")
async def purchase_package(data: PaymentSubmit, user = Depends(get_current_user)):
    # Log the request
    print(f"Purchase request from user: {user.get('mobile', 'unknown')}")
    print(f"Package ID: {data.package_id}")
    print(f"UTR: {data.utr_number}")
    
    # Verify transaction password
    if not verify_password(data.transaction_password, user['transaction_password']):
        print(f"Transaction password mismatch for user: {user.get('mobile', 'unknown')}")
        raise HTTPException(status_code=400, detail="Invalid transaction password. Please enter the transaction password you set during signup.")
    
    # Get package details
    packages = await get_packages()
    package = next((p for p in packages['packages'] if p['id'] == data.package_id), None)
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    # Create payment record (Deposit Request)
    payment_doc = {
        "user_id": str(user['_id']),
        "user_mobile": user.get('mobile', ''),
        "user_name": user.get('full_name', ''),
        "package_id": data.package_id,
        "package_name": package['name'],
        "amount": package['amount'],
        "screenshot_base64": data.screenshot_base64,
        "utr_number": data.utr_number,
        "status": "pending",
        "request_type": "deposit",
        "created_at": datetime.utcnow(),
        "verified_at": None,
        "verified_by": None
    }
    
    result = await db.payments.insert_one(payment_doc)
    print(f"Deposit request created: {result.inserted_id}")
    
    return {
        "success": True,
        "message": "Deposit request submitted successfully! Admin will verify within 24 hours.",
        "payment_id": str(result.inserted_id)
    }

@api_router.get("/packages/deposit-history")
async def get_deposit_history(user = Depends(get_current_user)):
    """Get user's deposit/investment history"""
    deposits = await db.payments.find(
        {"user_id": str(user['_id'])}
    ).sort("created_at", -1).to_list(100)
    
    for deposit in deposits:
        deposit['id'] = str(deposit['_id'])
        del deposit['_id']
        # Don't send screenshot in list view
        if 'screenshot_base64' in deposit:
            del deposit['screenshot_base64']
    
    return {
        "success": True,
        "deposits": deposits
    }

@api_router.get("/packages/my-packages")
async def get_my_packages(user = Depends(get_current_user)):
    packages = await db.user_packages.find({"user_id": str(user['_id'])}).to_list(100)
    for pkg in packages:
        pkg['id'] = str(pkg['_id'])
        del pkg['_id']
    return {"success": True, "packages": packages}

@api_router.get("/payments/history")
async def get_payment_history(user = Depends(get_current_user)):
    payments = await db.payments.find({"user_id": str(user['_id'])}).sort("created_at", -1).to_list(100)
    for payment in payments:
        payment['id'] = str(payment['_id'])
        del payment['_id']
    return {"success": True, "payments": payments}

# ========================= REFERRAL ENDPOINTS =========================

@api_router.get("/referrals/list")
async def get_referrals(user = Depends(get_current_user)):
    referrals = await db.referrals.find({"referrer_id": str(user['_id'])}).to_list(100)
    
    # Get referred user details
    referred_users = []
    for ref in referrals:
        referred_user = await db.users.find_one({"_id": ObjectId(ref['referred_id'])})
        if referred_user:
            referred_users.append({
                "full_name": referred_user['full_name'],
                "mobile": referred_user['mobile'],
                "is_active": referred_user['is_active'],
                "joined_at": ref['created_at']
            })
    
    return {"success": True, "referrals": referred_users}

# ========================= WALLET ENDPOINTS =========================

@api_router.post("/wallet/withdraw")
async def withdraw(data: WithdrawalRequest, user = Depends(get_current_user)):
    # Verify transaction password
    if not verify_password(data.transaction_password, user['transaction_password']):
        raise HTTPException(status_code=401, detail="Invalid transaction password")
    
    # Check minimum withdrawal
    if data.amount < 500:
        raise HTTPException(status_code=400, detail="Minimum withdrawal amount is ₹500")
    
    # Check balance
    if user['wallet_balance'] < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Calculate admin charge (10%)
    admin_charge = data.amount * 0.10
    final_amount = data.amount - admin_charge
    
    # Create withdrawal request
    withdrawal_doc = {
        "user_id": str(user['_id']),
        "amount": data.amount,
        "admin_charge": admin_charge,
        "final_amount": final_amount,
        "bank_name": data.bank_name,
        "account_number": data.account_number,
        "ifsc_code": data.ifsc_code,
        "upi_id": data.upi_id,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "processed_at": None
    }
    
    result = await db.withdrawals.insert_one(withdrawal_doc)
    
    # Deduct from wallet
    await db.users.update_one(
        {"_id": user['_id']},
        {"$inc": {"wallet_balance": -data.amount}}
    )
    
    return {
        "success": True,
        "message": "Withdrawal request submitted",
        "withdrawal_id": str(result.inserted_id),
        "final_amount": final_amount
    }

@api_router.get("/wallet/withdrawals")
async def get_withdrawals(user = Depends(get_current_user)):
    withdrawals = await db.withdrawals.find({"user_id": str(user['_id'])}).sort("created_at", -1).to_list(100)
    for withdrawal in withdrawals:
        withdrawal['id'] = str(withdrawal['_id'])
        del withdrawal['_id']
    return {"success": True, "withdrawals": withdrawals}

@api_router.post("/wallet/bank-details")
async def add_bank_details(data: BankDetails, user = Depends(get_current_user)):
    # If primary, unset other primary banks
    if data.is_primary:
        await db.bank_details.update_many(
            {"user_id": str(user['_id'])},
            {"$set": {"is_primary": False}}
        )
    
    bank_doc = data.dict()
    bank_doc['user_id'] = str(user['_id'])
    bank_doc['created_at'] = datetime.utcnow()
    
    result = await db.bank_details.insert_one(bank_doc)
    return {"success": True, "message": "Bank details added", "id": str(result.inserted_id)}

@api_router.get("/wallet/bank-details")
async def get_bank_details(user = Depends(get_current_user)):
    banks = await db.bank_details.find({"user_id": str(user['_id'])}).to_list(100)
    for bank in banks:
        bank['id'] = str(bank['_id'])
        del bank['_id']
    return {"success": True, "bank_details": banks}

# ========================= SUPPORT ENDPOINTS =========================

@api_router.post("/support/ticket")
async def create_ticket(data: TicketCreate, user = Depends(get_current_user)):
    ticket_doc = {
        "user_id": str(user['_id']),
        "subject": data.subject,
        "message": data.message,
        "status": "open",
        "reply": None,
        "created_at": datetime.utcnow(),
        "updated_at": None
    }
    
    result = await db.tickets.insert_one(ticket_doc)
    return {"success": True, "message": "Ticket created", "ticket_id": str(result.inserted_id)}

@api_router.get("/support/tickets")
async def get_tickets(user = Depends(get_current_user)):
    tickets = await db.tickets.find({"user_id": str(user['_id'])}).sort("created_at", -1).to_list(100)
    for ticket in tickets:
        ticket['id'] = str(ticket['_id'])
        del ticket['_id']
    return {"success": True, "tickets": tickets}

@api_router.get("/support/contact")
async def get_support_contact():
    return {
        "success": True,
        "whatsapp": "https://wa.me/1234567890",
        "telegram": "https://t.me/support"
    }

# ========================= REWARD SYSTEM =========================

# Reward structure for each package (25 & 50 direct IDs)
REWARD_STRUCTURE = {
    "copper": {"25_ids": 11000, "50_ids": 21000},
    "crypto": {"25_ids": 21000, "50_ids": 51000},
    "aipower": {"25_ids": 51000, "50_ids": 81000},
    "solar": {"25_ids": 81000, "50_ids": 121000},
    "gold": {"25_ids": 121000, "50_ids": 221000},
    "silver": {"25_ids": 221000, "50_ids": 551000},
}

@api_router.get("/rewards/eligible")
async def check_eligible_rewards(user = Depends(get_current_user)):
    """Check which rewards user is eligible for"""
    # Get user's active package
    active_package = await db.user_packages.find_one({
        "user_id": str(user['_id']),
        "is_active": True,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not active_package:
        return {"success": True, "eligible_rewards": [], "message": "No active package", "all_rewards": get_all_rewards_structure()}
    
    # Count active referrals (users who have purchased packages)
    referrals = await db.referrals.find({"referrer_id": str(user['_id'])}).to_list(1000)
    active_referrals_count = 0
    
    for ref in referrals:
        referred_user_package = await db.user_packages.find_one({
            "user_id": ref['referred_id'],
            "is_active": True
        })
        if referred_user_package:
            active_referrals_count += 1
    
    package_id = active_package['package_id']
    package_activated_at = active_package.get('activated_at', active_package.get('created_at', datetime.utcnow()))
    
    # Check if 30 days have passed since package activation
    days_since_activation = (datetime.utcnow() - package_activated_at).days
    time_limit_expired = days_since_activation > 30
    days_remaining = max(0, 30 - days_since_activation)
    
    rewards = REWARD_STRUCTURE.get(package_id, {})
    
    eligible_rewards = []
    
    # Check 25 IDs reward
    if active_referrals_count >= 25 and not time_limit_expired:
        # Check if already claimed
        claimed_25 = await db.rewards.find_one({
            "user_id": str(user['_id']),
            "package_id": package_id,
            "reward_type": "25_ids",
            "status": {"$in": ["pending", "approved"]}
        })
        if not claimed_25:
            eligible_rewards.append({
                "reward_type": "25_ids",
                "amount": rewards.get("25_ids", 0),
                "required_ids": 25,
                "current_ids": active_referrals_count,
                "days_remaining": days_remaining
            })
    
    # Check 50 IDs reward
    if active_referrals_count >= 50 and not time_limit_expired:
        claimed_50 = await db.rewards.find_one({
            "user_id": str(user['_id']),
            "package_id": package_id,
            "reward_type": "50_ids",
            "status": {"$in": ["pending", "approved"]}
        })
        if not claimed_50:
            eligible_rewards.append({
                "reward_type": "50_ids",
                "amount": rewards.get("50_ids", 0),
                "required_ids": 50,
                "current_ids": active_referrals_count,
                "days_remaining": days_remaining
            })
    
    return {
        "success": True,
        "eligible_rewards": eligible_rewards,
        "active_referrals": active_referrals_count,
        "package_id": package_id,
        "time_limit_expired": time_limit_expired,
        "days_remaining": days_remaining,
        "all_rewards": get_all_rewards_structure()
    }

def get_all_rewards_structure():
    """Return all package rewards for display"""
    return [
        {"package_id": "copper", "name": "Copper", "rewards": REWARD_STRUCTURE["copper"]},
        {"package_id": "crypto", "name": "Crypto", "rewards": REWARD_STRUCTURE["crypto"]},
        {"package_id": "aipower", "name": "AI Power", "rewards": REWARD_STRUCTURE["aipower"]},
        {"package_id": "solar", "name": "Solar Energy", "rewards": REWARD_STRUCTURE["solar"]},
        {"package_id": "gold", "name": "Gold", "rewards": REWARD_STRUCTURE["gold"]},
        {"package_id": "silver", "name": "Silver", "rewards": REWARD_STRUCTURE["silver"]},
    ]

@api_router.post("/rewards/claim")
async def claim_reward(data: dict, user = Depends(get_current_user)):
    """Submit reward claim for admin verification"""
    reward_type = data.get('reward_type')  # "25_ids" or "50_ids"
    
    if reward_type not in ["25_ids", "50_ids"]:
        raise HTTPException(status_code=400, detail="Invalid reward type")
    
    # Get user's active package
    active_package = await db.user_packages.find_one({
        "user_id": str(user['_id']),
        "is_active": True,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not active_package:
        raise HTTPException(status_code=400, detail="No active package found")
    
    # Count active referrals
    referrals = await db.referrals.find({"referrer_id": str(user['_id'])}).to_list(1000)
    active_referrals_count = 0
    
    for ref in referrals:
        referred_user_package = await db.user_packages.find_one({
            "user_id": ref['referred_id'],
            "is_active": True
        })
        if referred_user_package:
            active_referrals_count += 1
    
    required_ids = 25 if reward_type == "25_ids" else 50
    if active_referrals_count < required_ids:
        raise HTTPException(status_code=400, detail=f"Insufficient active referrals. Need {required_ids}, have {active_referrals_count}")
    
    # Check if already claimed
    existing_claim = await db.rewards.find_one({
        "user_id": str(user['_id']),
        "package_id": active_package['package_id'],
        "reward_type": reward_type,
        "status": {"$in": ["pending", "approved"]}
    })
    
    if existing_claim:
        raise HTTPException(status_code=400, detail="Reward already claimed or pending")
    
    package_id = active_package['package_id']
    reward_amount = REWARD_STRUCTURE.get(package_id, {}).get(reward_type, 0)
    
    # Create reward claim
    reward_doc = {
        "user_id": str(user['_id']),
        "package_id": package_id,
        "reward_type": reward_type,
        "amount": reward_amount,
        "active_referrals_at_claim": active_referrals_count,
        "status": "pending",
        "claimed_at": datetime.utcnow(),
        "verified_at": None
    }
    
    result = await db.rewards.insert_one(reward_doc)
    
    return {
        "success": True,
        "message": "Reward claim submitted for admin verification",
        "reward_id": str(result.inserted_id),
        "amount": reward_amount
    }

@api_router.get("/rewards/history")
async def get_rewards_history(user = Depends(get_current_user)):
    """Get user's reward claim history"""
    rewards = await db.rewards.find({"user_id": str(user['_id'])}).sort("claimed_at", -1).to_list(100)
    for reward in rewards:
        reward['id'] = str(reward['_id'])
        del reward['_id']
    return {"success": True, "rewards": rewards}

# ========================= ADMIN ENDPOINTS =========================

class AdminSetup(BaseModel):
    email: str
    password: str
    name: str = "Admin"

@api_router.post("/admin/setup")
async def setup_first_admin(data: AdminSetup):
    """Create first admin user - only works if no admin exists"""
    # Check if any admin already exists
    existing_admin = await db.admins.find_one({})
    if existing_admin:
        raise HTTPException(status_code=400, detail="Admin already exists")
    
    # Create admin
    hashed_password = hash_password(data.password)
    admin = {
        "email": data.email.lower(),
        "password": hashed_password,
        "name": data.name,
        "role": "super_admin",
        "created_at": datetime.utcnow().isoformat()
    }
    result = await db.admins.insert_one(admin)
    return {"success": True, "message": "Admin created successfully", "admin_id": str(result.inserted_id)}

@api_router.post("/admin/login")
async def admin_login(data: AdminLogin):
    # Check if admin user exists by email
    admin = await db.admins.find_one({"email": data.email.lower()})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not verify_password(data.password, admin.get('password', '')):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_token(str(admin['_id']))
    return {"success": True, "token": token, "role": "admin", "name": admin.get('name', 'Admin')}

@api_router.post("/admin/change-password")
async def admin_change_password(data: AdminChangePassword, user = Depends(get_current_admin)):
    """Change admin password"""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Verify current password
    if not verify_password(data.current_password, admin.get('password', '')):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    
    # Update password
    hashed_password = hash_password(data.new_password)
    await db.admins.update_one(
        {"_id": user['_id']},
        {"$set": {"password": hashed_password, "updated_at": datetime.utcnow()}}
    )
    
    return {"success": True, "message": "Password changed successfully"}

@api_router.post("/admin/process-daily-income")
async def process_daily_income(user = Depends(get_current_admin)):
    """Process daily income for all active users with packages"""
    # Check if user is admin - support both admins collection and mobile admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        # Check if it's the mobile admin
        admin = await db.admins.find_one({"mobile": "9999999999"})
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Check if already processed today
    today = datetime.utcnow().date()
    last_process = await db.daily_income_logs.find_one({
        "date": today.isoformat()
    })
    
    if last_process:
        return {
            "success": False,
            "message": f"Daily income already processed today at {last_process.get('processed_at', 'earlier')}"
        }
    
    # Get all active packages
    active_packages = await db.user_packages.find({
        "is_active": True,
        "expires_at": {"$gt": datetime.utcnow()}
    }).to_list(10000)
    
    processed_count = 0
    total_credited = 0.0
    
    for package in active_packages:
        user_id = package['user_id']
        daily_income = package.get('daily_income', 0)
        
        if daily_income > 0:
            # Credit daily income to user
            await db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$inc": {
                    "wallet_balance": daily_income,
                    "today_income": daily_income,
                    "total_income": daily_income
                }}
            )
            
            # Log the transaction
            await db.transactions.insert_one({
                "user_id": user_id,
                "type": "daily_income",
                "amount": daily_income,
                "package_id": package.get('package_id'),
                "package_name": package.get('package_name'),
                "description": f"Daily income from {package.get('package_name', 'Package')}",
                "created_at": datetime.utcnow()
            })
            
            processed_count += 1
            total_credited += daily_income
    
    # Log this processing
    await db.daily_income_logs.insert_one({
        "date": today.isoformat(),
        "processed_count": processed_count,
        "total_credited": total_credited,
        "processed_at": datetime.utcnow(),
        "processed_by": str(user['_id'])
    })
    
    # Reset today_income for all users at start of day (optional - uncomment if needed)
    # await db.users.update_many({}, {"$set": {"today_income": 0}})
    
    return {
        "success": True,
        "message": "Daily income processed successfully",
        "processed_count": processed_count,
        "total_credited": total_credited
    }

@api_router.get("/admin/stats")
async def get_admin_stats(user = Depends(get_current_admin)):
    """Get dashboard statistics"""
    # Check if user is admin - support both admins collection and mobile admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        # Check if it's the mobile admin
        admin = await db.admins.find_one({"mobile": "9999999999"})
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Get counts
    total_users = await db.users.count_documents({})
    active_users = await db.users.count_documents({"is_active": True})
    pending_deposits = await db.payments.count_documents({"status": "pending"})
    pending_withdrawals = await db.withdrawals.count_documents({"status": "pending"})
    
    # Get totals
    approved_deposits = await db.payments.find({"status": "approved"}).to_list(1000)
    total_deposits = sum(d.get('amount', 0) for d in approved_deposits)
    
    completed_withdrawals = await db.withdrawals.find({"status": "successful"}).to_list(1000)
    total_withdrawals = sum(w.get('final_amount', 0) for w in completed_withdrawals)
    total_commission = sum(w.get('admin_charge', 0) for w in completed_withdrawals)
    
    return {
        "success": True,
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "pending_deposits": pending_deposits,
            "pending_withdrawals": pending_withdrawals,
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_commission": total_commission
        }
    }

@api_router.get("/admin/pending-deposits")
async def get_pending_deposits(user = Depends(get_current_admin)):
    """Get all deposit requests (pending, approved, rejected)"""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Get ALL deposits, not just pending - for full history
    deposits = await db.payments.find().sort("created_at", -1).to_list(200)
    for deposit in deposits:
        deposit['id'] = str(deposit['_id'])
        # Add user info
        user_info = await db.users.find_one({"_id": ObjectId(deposit['user_id'])})
        deposit['user_name'] = user_info['full_name'] if user_info else "Unknown"
        deposit['user_mobile'] = user_info['mobile'] if user_info else "Unknown"
        del deposit['_id']
    return {"success": True, "deposits": deposits}

@api_router.get("/admin/pending-withdrawals")
async def get_pending_withdrawals(user = Depends(get_current_admin)):
    """Get all withdrawal requests (pending, successful, rejected)"""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Get ALL withdrawals, not just pending - for full history
    withdrawals = await db.withdrawals.find().sort("created_at", -1).to_list(200)
    
    # Add user info to each withdrawal
    for withdrawal in withdrawals:
        withdrawal['id'] = str(withdrawal['_id'])
        del withdrawal['_id']
        user_info = await db.users.find_one({"_id": ObjectId(withdrawal['user_id'])})
        if user_info:
            withdrawal['user_name'] = user_info.get('full_name', 'N/A')
            withdrawal['user_mobile'] = user_info.get('mobile', 'N/A')
    
    return {"success": True, "withdrawals": withdrawals}

@api_router.post("/admin/verify-withdrawal")
async def verify_withdrawal(data: dict, user = Depends(get_current_admin)):
    """Approve or reject withdrawal with UTR and screenshot"""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    withdrawal_id = data.get('withdrawal_id')
    status = data.get('status')  # 'successful' or 'rejected'
    admin_utr = data.get('admin_utr', '')
    admin_screenshot = data.get('admin_screenshot', '')
    
    withdrawal = await db.withdrawals.find_one({"_id": ObjectId(withdrawal_id)})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    
    update_data = {
        "status": status, 
        "processed_at": datetime.utcnow()
    }
    
    # Add UTR and screenshot if provided (for approved withdrawals)
    if status == 'successful' and admin_utr:
        update_data["admin_utr"] = admin_utr
    if status == 'successful' and admin_screenshot:
        update_data["admin_screenshot"] = admin_screenshot
    
    await db.withdrawals.update_one(
        {"_id": ObjectId(withdrawal_id)},
        {"$set": update_data}
    )
    
    # If rejected, refund the amount to user's wallet
    if status == 'rejected':
        await db.users.update_one(
            {"_id": ObjectId(withdrawal['user_id'])},
            {"$inc": {"wallet_balance": withdrawal['amount']}}
        )
    
    return {"success": True, "message": f"Withdrawal {status}"}

@api_router.get("/admin/users")
async def get_all_users(user = Depends(get_current_admin)):
    # Check if admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    users = await db.users.find().sort("created_at", -1).to_list(1000)
    for u in users:
        u['id'] = str(u['_id'])
        del u['_id']
        # Safely remove password fields
        u.pop('login_password', None)
        u.pop('transaction_password', None)
        u.pop('password_hash', None)
    return {"success": True, "users": users}

@api_router.post("/admin/verify-payment")
async def verify_payment(data: dict, user = Depends(get_current_admin)):
    # Check if admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    payment_id = data.get('payment_id')
    status = data.get('status', data.get('action', ''))  # Support both status and action
    
    if status == 'approve':
        status = 'approved'
    elif status == 'reject':
        status = 'rejected'
    
    payment = await db.payments.find_one({"_id": ObjectId(payment_id)})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    if status == "approved":
        # Check if payment was already approved (prevent duplicate processing)
        if payment.get('status') == 'approved':
            return {"success": True, "message": "Payment was already approved"}
        
        # Update payment status with referral_processed flag
        await db.payments.update_one(
            {"_id": ObjectId(payment_id)},
            {"$set": {
                "status": "approved", 
                "verified_at": datetime.utcnow(),
                "referral_processed": True
            }}
        )
        
        # Get package details
        packages_response = await get_packages()
        package = next((p for p in packages_response['packages'] if p['id'] == payment['package_id']), None)
        
        if package:
            # Create user package
            user_package = {
                "user_id": payment['user_id'],
                "package_id": payment['package_id'],
                "package_name": package['name'],
                "amount": package['amount'],
                "daily_income": package['daily_income'],
                "total_return": package['total_return'],
                "is_active": True,
                "activated_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(days=package['duration_days']),
                "days_remaining": package['duration_days']
            }
            await db.user_packages.insert_one(user_package)
            
            # Activate user
            await db.users.update_one(
                {"_id": ObjectId(payment['user_id'])},
                {"$set": {"is_active": True, "active_package": package['name']}}
            )
            
            # Process referral income (10%) - ONLY if not already processed for this payment
            if not payment.get('referral_processed'):
                payer = await db.users.find_one({"_id": ObjectId(payment['user_id'])})
                if payer and payer.get('referred_by'):
                    referrer = await db.users.find_one({"my_referral_code": payer['referred_by']})
                    if referrer:
                        referral_income = package['amount'] * 0.10
                        await db.users.update_one(
                            {"_id": referrer['_id']},
                            {"$inc": {
                                "wallet_balance": referral_income,
                                "referral_income": referral_income,
                                "total_income": referral_income
                            }}
                        )
                        # Log referral transaction for tracking
                        await db.transactions.insert_one({
                            "user_id": str(referrer['_id']),
                            "type": "referral_income",
                            "amount": referral_income,
                            "from_user_id": payment['user_id'],
                            "payment_id": str(payment['_id']),
                            "package_id": payment['package_id'],
                            "description": f"10% referral income from {payer.get('full_name', 'User')} - {package['name']} package",
                            "created_at": datetime.utcnow()
                        })
        
        return {"success": True, "message": "Payment approved successfully"}
    
    elif status == "rejected":
        await db.payments.update_one(
            {"_id": ObjectId(payment_id)},
            {"$set": {"status": "rejected", "verified_at": datetime.utcnow()}}
        )
        return {"success": True, "message": "Payment rejected"}
    
    else:
        raise HTTPException(status_code=400, detail="Invalid status")

# Admin endpoint to update user wallet balance
@api_router.post("/admin/update-wallet")
async def update_user_wallet(data: dict, user = Depends(get_current_admin)):
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    user_id = data.get('user_id')
    new_balance = data.get('new_balance')
    
    if new_balance is None or new_balance < 0:
        raise HTTPException(status_code=400, detail="Invalid balance amount")
    
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"wallet_balance": float(new_balance)}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"success": True, "message": f"Wallet balance updated to ₹{new_balance}"}

# Admin endpoint to update ALL user finances (wallet, referral, reward, today, total income)
@api_router.post("/admin/update-user-finances")
async def update_user_finances(data: dict, user = Depends(get_current_admin)):
    """Update all user financial fields - wallet balance, referral income, reward income, etc."""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    user_id = data.get('user_id')
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID is required")
    
    # Build update document with all financial fields
    update_fields = {}
    
    if 'wallet_balance' in data:
        update_fields['wallet_balance'] = float(data.get('wallet_balance', 0))
    if 'referral_income' in data:
        update_fields['referral_income'] = float(data.get('referral_income', 0))
    if 'reward_income' in data:
        update_fields['reward_income'] = float(data.get('reward_income', 0))
    if 'today_income' in data:
        update_fields['today_income'] = float(data.get('today_income', 0))
    if 'total_income' in data:
        update_fields['total_income'] = float(data.get('total_income', 0))
    
    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_fields}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found or no changes made")
    
    return {"success": True, "message": "User finances updated successfully"}

# Admin UPI Settings
@api_router.get("/admin/settings")
async def get_admin_settings(user = Depends(get_current_admin)):
    """Get admin settings including UPI details"""
    settings = await db.admin_settings.find_one({"type": "payment"})
    if not settings:
        # Return default settings
        return {
            "success": True,
            "settings": {
                "upi_id": os.environ.get('UPI_ID', 'trustrentacar99-9@okhdfcbank'),
                "payee_name": os.environ.get('PAYEE_NAME', 'Growmore Exchange')
            }
        }
    return {
        "success": True,
        "settings": {
            "upi_id": settings.get('upi_id'),
            "payee_name": settings.get('payee_name')
        }
    }

@api_router.post("/admin/settings")
async def update_admin_settings(data: dict, user = Depends(get_current_admin)):
    """Update admin settings including UPI details"""
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    upi_id = data.get('upi_id')
    payee_name = data.get('payee_name', 'Growmore Exchange')
    
    if not upi_id:
        raise HTTPException(status_code=400, detail="UPI ID is required")
    
    await db.admin_settings.update_one(
        {"type": "payment"},
        {"$set": {
            "type": "payment",
            "upi_id": upi_id,
            "payee_name": payee_name,
            "updated_at": datetime.utcnow()
        }},
        upsert=True
    )
    
    return {"success": True, "message": "Payment settings updated"}

@api_router.get("/admin/pending-payments")
async def get_pending_payments(user = Depends(get_current_admin)):
    # Check if admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    payments = await db.payments.find({"status": "pending"}).sort("created_at", -1).to_list(100)
    for payment in payments:
        payment['id'] = str(payment['_id'])
        user_info = await db.users.find_one({"_id": ObjectId(payment['user_id'])})
        payment['user_name'] = user_info['full_name'] if user_info else "Unknown"
        payment['user_mobile'] = user_info['mobile'] if user_info else "Unknown"
        del payment['_id']
    return {"success": True, "payments": payments}

# Duplicate endpoint removed - using the one at line 968

# ========================= ADMIN REWARD ENDPOINTS =========================

@api_router.get("/admin/pending-rewards")
async def get_pending_rewards(user = Depends(get_current_user)):
    """Get all pending reward claims"""
    admin = await db.admins.find_one({"mobile": "9999999999"})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    rewards = await db.rewards.find({"status": "pending"}).sort("claimed_at", -1).to_list(100)
    for reward in rewards:
        reward['id'] = str(reward['_id'])
        user_info = await db.users.find_one({"_id": ObjectId(reward['user_id'])})
        reward['user_name'] = user_info['full_name'] if user_info else "Unknown"
        reward['user_mobile'] = user_info['mobile'] if user_info else "Unknown"
        del reward['_id']
    return {"success": True, "rewards": rewards}

@api_router.post("/admin/verify-reward")
async def verify_reward(data: dict, user = Depends(get_current_user)):
    """Approve or reject reward claim"""
    admin = await db.admins.find_one({"mobile": "9999999999"})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    reward_id = data.get('reward_id')
    action = data.get('action')  # approve, reject
    
    reward = await db.rewards.find_one({"_id": ObjectId(reward_id)})
    if not reward:
        raise HTTPException(status_code=404, detail="Reward not found")
    
    if action == "approve":
        # Update reward status
        await db.rewards.update_one(
            {"_id": ObjectId(reward_id)},
            {"$set": {"status": "approved", "verified_at": datetime.utcnow()}}
        )
        
        # Credit reward amount to user wallet
        await db.users.update_one(
            {"_id": ObjectId(reward['user_id'])},
            {"$inc": {
                "wallet_balance": reward['amount'],
                "reward_income": reward['amount'],
                "total_income": reward['amount']
            }}
        )
        
        # Record transaction
        await db.transactions.insert_one({
            "user_id": reward['user_id'],
            "type": "reward_income",
            "amount": reward['amount'],
            "description": f"Reward for {reward['reward_type']} - {reward['package_id'].upper()}",
            "created_at": datetime.utcnow()
        })
        
        return {"success": True, "message": "Reward approved and credited"}
    
    elif action == "reject":
        await db.rewards.update_one(
            {"_id": ObjectId(reward_id)},
            {"$set": {"status": "rejected", "verified_at": datetime.utcnow()}}
        )
        return {"success": True, "message": "Reward rejected"}
    
    raise HTTPException(status_code=400, detail="Invalid action")

@api_router.post("/admin/user-management")
async def manage_user(data: UserManagement, user = Depends(get_current_admin)):
    # Check if admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    if data.action == "activate":
        await db.users.update_one(
            {"_id": ObjectId(data.user_id)},
            {"$set": {"is_active": True, "is_blocked": False}}
        )
        return {"success": True, "message": "User activated"}
    
    elif data.action == "deactivate":
        await db.users.update_one(
            {"_id": ObjectId(data.user_id)},
            {"$set": {"is_active": False}}
        )
        return {"success": True, "message": "User deactivated"}
    
    elif data.action == "block":
        await db.users.update_one(
            {"_id": ObjectId(data.user_id)},
            {"$set": {"is_blocked": True, "is_active": False}}
        )
        return {"success": True, "message": "User blocked"}
    
    raise HTTPException(status_code=400, detail="Invalid action")

@api_router.get("/admin/stats")
async def get_admin_stats(user = Depends(get_current_admin)):
    # Check if admin
    admin = await db.admins.find_one({"_id": user['_id']})
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    total_users = await db.users.count_documents({})
    active_users = await db.users.count_documents({"is_active": True})
    pending_payments = await db.payments.count_documents({"status": "pending"})
    pending_withdrawals = await db.withdrawals.count_documents({"status": "pending"})
    
    return {
        "success": True,
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "pending_payments": pending_payments,
            "pending_withdrawals": pending_withdrawals
        }
    }

# ========================= HEALTH CHECK =========================

@api_router.get("/")
async def root():
    return {"message": "Earning Platform API", "version": "1.0.0"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    # Create default admin if not exists
    admin_exists = await db.admins.find_one({"mobile": "9999999999"})
    if not admin_exists:
        await db.admins.insert_one({
            "mobile": "9999999999",
            "name": "Admin",
            "created_at": datetime.utcnow()
        })
        logger.info("Default admin created: mobile=9999999999")
    
    # Create default referrer for first user
    default_referrer = await db.users.find_one({"my_referral_code": "ADMIN001"})
    if not default_referrer:
        await db.users.insert_one({
            "full_name": "System",
            "mobile": "0000000000",
            "referral_code": "SYSTEM",
            "my_referral_code": "ADMIN001",
            "login_password": hash_password("admin123"),
            "transaction_password": hash_password("admin123"),
            "is_active": True,
            "wallet_balance": 0.0,
            "total_income": 0.0,
            "today_income": 0.0,
            "referral_income": 0.0,
            "reward_income": 0.0,
            "created_at": datetime.utcnow(),
            "is_blocked": False
        })
        logger.info("Default referrer created with code: ADMIN001")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Download Database Export
@api_router.get("/download-database")
async def download_database():
    """Download MongoDB database export"""
    path = ROOT_DIR / "static" / "database-export.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Database export not found")
    return FileResponse(path=str(path), filename="database-export.zip", media_type="application/zip")

# Download Railway Backend
@api_router.get("/download-railway-backend")
async def download_railway_backend():
    """Download Railway Backend files"""
    path = ROOT_DIR / "static" / "railway-backend.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Railway backend not found")
    return FileResponse(path=str(path), filename="railway-backend.zip", media_type="application/zip")

@api_router.get("/download-server-file")
async def download_server_file():
    path = ROOT_DIR / "static" / "server-file.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path=str(path), filename="server-file.zip", media_type="application/zip")

# Download User Panel v3 for Hostinger
@api_router.get("/download-user-panel-v3")
async def download_user_panel_v3():
    """Download User Panel v3 for Hostinger"""
    path = ROOT_DIR / "static" / "user-panel-v3.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="User panel v3 not found")
    return FileResponse(path=str(path), filename="user-panel-v3.zip", media_type="application/zip")

