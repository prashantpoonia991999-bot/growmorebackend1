from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import bcrypt
import jwt
import random
import base64
from bson import ObjectId
import qrcode
from io import BytesIO

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'growmore_exchange')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')
JWT_ALGORITHM = 'HS256'

# MongoDB
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

security = HTTPBearer()
app = FastAPI(title="Growmore Exchange API")
api_router = APIRouter(prefix="/api")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Models - Updated to match frontend
class UserSignup(BaseModel):
    full_name: str
    mobile: str
    date_of_birth: str  # DD/MM/YYYY format
    referral_code: str
    login_password: str
    transaction_password: str

class UserLogin(BaseModel):
    mobile: str
    password: str

class AdminLogin(BaseModel):
    email: str
    password: str

class AdminSetup(BaseModel):
    email: str
    password: str
    name: str = "Admin"

class AdminChangePassword(BaseModel):
    current_password: str
    new_password: str

class ForgotPassword(BaseModel):
    mobile: str
    date_of_birth: str
    new_password: str

class WithdrawalRequest(BaseModel):
    amount: float
    withdrawal_type: str = "upi"
    upi_id: Optional[str] = None
    bank_name: Optional[str] = None
    account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    transaction_password: str

class PackagePurchase(BaseModel):
    package_id: str
    utr_number: str
    screenshot_base64: str
    transaction_password: str

# Helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

def create_token(user_id: str) -> str:
    exp = datetime.utcnow() + timedelta(hours=720)
    return jwt.encode({"user_id": user_id, "exp": exp}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(credentials.credentials)
    user = await db.users.find_one({"_id": ObjectId(payload["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(credentials.credentials)
    admin = await db.admins.find_one({"_id": ObjectId(payload["user_id"])})
    if not admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return admin

def generate_referral_code(length=8):
    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))

def generate_user_id():
    return f"GM{random.randint(100000, 999999)}"

# Auth
@api_router.post("/auth/signup")
async def signup(data: UserSignup):
    if not all([data.full_name, data.mobile, data.login_password, data.date_of_birth, data.referral_code, data.transaction_password]):
        raise HTTPException(status_code=400, detail="All fields required")
    if await db.users.find_one({"mobile": data.mobile}):
        raise HTTPException(status_code=400, detail="Mobile already registered")
    
    # Verify referral code
    referrer = await db.users.find_one({"referral_code": data.referral_code})
    if not referrer and data.referral_code != "ADMIN001":
        raise HTTPException(status_code=400, detail="Invalid referral code")
    
    user = {
        "full_name": data.full_name, 
        "mobile": data.mobile, 
        "login_password": hash_password(data.login_password),
        "transaction_password": hash_password(data.transaction_password),
        "date_of_birth": hash_password(data.date_of_birth),  # Store hashed for security
        "user_id": generate_user_id(), 
        "referral_code": generate_referral_code(),
        "referred_by": data.referral_code, 
        "wallet_balance": 0, 
        "total_investment": 0,
        "total_income": 0, 
        "today_income": 0,
        "referral_income": 0,
        "reward_income": 0,
        "is_active": False,
        "created_at": datetime.utcnow().isoformat()
    }
    result = await db.users.insert_one(user)
    
    # Track referral
    if referrer:
        await db.referrals.insert_one({
            "referrer_id": str(referrer["_id"]),
            "referred_id": str(result.inserted_id),
            "created_at": datetime.utcnow().isoformat()
        })
    
    return {"success": True, "token": create_token(str(result.inserted_id)), "user_id": user["user_id"]}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"mobile": data.mobile})
    if not user or not verify_password(data.password, user.get("login_password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "token": create_token(str(user["_id"])), "user_id": user.get("user_id")}

@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPassword):
    user = await db.users.find_one({"mobile": data.mobile})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify DOB
    stored_dob = user.get("date_of_birth")
    if not stored_dob or not verify_password(data.date_of_birth, stored_dob):
        raise HTTPException(status_code=400, detail="Invalid credentials. Please check your details.")
    
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"login_password": hash_password(data.new_password)}})
    return {"success": True, "message": "Password updated"}

@api_router.post("/auth/reset-transaction-password")
async def reset_transaction_password(data: dict, user = Depends(get_current_user)):
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"transaction_password": hash_password(new_password)}})
    return {"success": True, "message": "Transaction password updated"}

# User
@api_router.get("/user/profile")
async def get_profile(user = Depends(get_current_user)):
    return {
        "success": True, 
        "user": {
            "id": str(user["_id"]),
            "full_name": user.get("full_name"), 
            "mobile": user.get("mobile"), 
            "user_id": user.get("user_id"), 
            "my_referral_code": user.get("referral_code"),
            "referral_code": user.get("referral_code"), 
            "wallet_balance": user.get("wallet_balance", 0), 
            "total_investment": user.get("total_investment", 0),
            "total_income": user.get("total_income", 0),
            "today_income": user.get("today_income", 0),
            "referral_income": user.get("referral_income", 0),
            "reward_income": user.get("reward_income", 0),
            "is_active": user.get("is_active", False),
            "created_at": user.get("created_at")
        }
    }

@api_router.get("/user/dashboard")
async def get_dashboard(user = Depends(get_current_user)):
    # Get active package
    active_package = await db.user_packages.find_one({
        "user_id": str(user["_id"]),
        "is_active": True
    })
    
    # Get referral count
    referral_count = await db.referrals.count_documents({"referrer_id": str(user["_id"])})
    
    # Get total invested
    approved_deposits = await db.payments.find({"user_id": str(user["_id"]), "status": "approved"}).to_list(100)
    total_invested = sum(d.get("amount", 0) for d in approved_deposits)
    
    return {
        "success": True, 
        "dashboard": {
            "wallet_balance": user.get("wallet_balance", 0), 
            "total_invested": total_invested,
            "total_income": user.get("total_income", 0),
            "today_income": user.get("today_income", 0),
            "referral_income": user.get("referral_income", 0),
            "reward_income": user.get("reward_income", 0),
            "is_active": user.get("is_active", False),
            "has_active_package": active_package is not None,
            "active_package_name": active_package.get("package_name") if active_package else None,
            "referral_count": referral_count,
            "my_referral_code": user.get("referral_code", "")
        }
    }

# Packages
PACKAGES = [
    {"id": "copper", "name": "Copper", "amount": 1500, "daily_income": 100, "duration_days": 30, "total_return": 3000, "is_active": True},
    {"id": "crypto", "name": "Crypto", "amount": 3000, "daily_income": 200, "duration_days": 30, "total_return": 6000, "is_active": True},
    {"id": "aipower", "name": "AI Power", "amount": 6000, "daily_income": 400, "duration_days": 30, "total_return": 12000, "is_active": True},
    {"id": "solar", "name": "Solar Energy", "amount": 12000, "daily_income": 800, "duration_days": 30, "total_return": 24000, "is_active": True},
    {"id": "gold", "name": "Gold", "amount": 24000, "daily_income": 1600, "duration_days": 30, "total_return": 48000, "is_active": True},
    {"id": "silver", "name": "Silver", "amount": 48000, "daily_income": 3200, "duration_days": 30, "total_return": 96000, "is_active": True},
]

REWARD_STRUCTURE = {
    "copper": {"25_ids": 11000, "50_ids": 21000}, 
    "crypto": {"25_ids": 21000, "50_ids": 51000},
    "aipower": {"25_ids": 51000, "50_ids": 81000}, 
    "solar": {"25_ids": 81000, "50_ids": 121000},
    "gold": {"25_ids": 121000, "50_ids": 221000}, 
    "silver": {"25_ids": 221000, "50_ids": 551000}
}

@api_router.get("/packages/list")
async def get_packages():
    return {"success": True, "packages": PACKAGES}

@api_router.get("/packages/upi-details/{package_id}")
async def get_upi_details(package_id: str, user = Depends(get_current_user)):
    package = next((p for p in PACKAGES if p["id"] == package_id), None)
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    settings = await db.settings.find_one({"type": "upi"})
    upi_id = settings.get("upi_id") if settings else os.environ.get("UPI_ID", "example@upi")
    payee = settings.get("payee_name") if settings else os.environ.get("PAYEE_NAME", "Growmore Exchange")
    
    # Generate QR
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(f"upi://pay?pa={upi_id}&pn={payee}&am={package['amount']}&cu=INR")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    
    return {
        "success": True, 
        "upi_id": upi_id,
        "qr_code_base64": f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}",
        "amount": package["amount"],
        "package_name": package["name"],
        "valid_for_minutes": 10
    }

@api_router.post("/packages/purchase")
async def purchase_package(data: PackagePurchase, user = Depends(get_current_user)):
    # Verify transaction password
    if not verify_password(data.transaction_password, user.get("transaction_password", "")):
        raise HTTPException(status_code=400, detail="Invalid transaction password")
    
    package = next((p for p in PACKAGES if p["id"] == data.package_id), None)
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    # Create deposit request
    await db.payments.insert_one({
        "user_id": str(user["_id"]),
        "user_mobile": user.get("mobile"),
        "user_name": user.get("full_name"),
        "package_id": data.package_id,
        "package_name": package["name"],
        "amount": package["amount"],
        "utr_number": data.utr_number,
        "screenshot_base64": data.screenshot_base64,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat()
    })
    
    return {"success": True, "message": "Deposit request submitted. Admin will verify within 24 hours."}

@api_router.get("/packages/deposit-history")
async def get_deposit_history(user = Depends(get_current_user)):
    deposits = await db.payments.find({"user_id": str(user["_id"])}).sort("created_at", -1).to_list(100)
    for d in deposits:
        d["id"] = str(d.pop("_id"))
        d.pop("screenshot_base64", None)
    return {"success": True, "deposits": deposits}

@api_router.get("/packages/my-packages")
async def get_my_packages(user = Depends(get_current_user)):
    packages = await db.user_packages.find({"user_id": str(user["_id"])}).to_list(100)
    for p in packages:
        p["id"] = str(p.pop("_id"))
    return {"success": True, "packages": packages}

# Wallet
@api_router.post("/wallet/withdraw")
async def request_withdrawal(data: WithdrawalRequest, user = Depends(get_current_user)):
    # Verify transaction password
    if not verify_password(data.transaction_password, user.get("transaction_password", "")):
        raise HTTPException(status_code=401, detail="Invalid transaction password")
    
    if user.get("wallet_balance", 0) < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    if data.amount < 500:
        raise HTTPException(status_code=400, detail="Minimum withdrawal is ₹500")
    
    admin_charge = data.amount * 0.1
    final_amount = data.amount - admin_charge
    
    await db.withdrawals.insert_one({
        "user_id": str(user["_id"]),
        "user_mobile": user.get("mobile"),
        "user_name": user.get("full_name"),
        "amount": data.amount,
        "admin_charge": admin_charge,
        "final_amount": final_amount,
        "withdrawal_type": data.withdrawal_type,
        "upi_id": data.upi_id,
        "bank_name": data.bank_name,
        "account_number": data.account_number,
        "ifsc_code": data.ifsc_code,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat()
    })
    
    await db.users.update_one({"_id": user["_id"]}, {"$inc": {"wallet_balance": -data.amount}})
    return {"success": True, "message": "Withdrawal request submitted", "final_amount": final_amount}

@api_router.get("/wallet/withdrawals")
async def get_withdrawals(user = Depends(get_current_user)):
    withdrawals = await db.withdrawals.find({"user_id": str(user["_id"])}).sort("created_at", -1).to_list(100)
    for w in withdrawals:
        w["id"] = str(w.pop("_id"))
    return {"success": True, "withdrawals": withdrawals}

# Rewards
@api_router.get("/rewards/eligible")
async def get_eligible_rewards(user = Depends(get_current_user)):
    referrals = await db.referrals.find({"referrer_id": str(user["_id"])}).to_list(1000)
    active = 0
    for ref in referrals:
        ref_user_pkg = await db.user_packages.find_one({"user_id": ref["referred_id"], "is_active": True})
        if ref_user_pkg:
            active += 1
    
    all_rewards = [{"package_id": k, "name": next((p["name"] for p in PACKAGES if p["id"]==k), k), "rewards": v} for k, v in REWARD_STRUCTURE.items()]
    return {"success": True, "eligible_rewards": [], "active_referrals": active, "all_rewards": all_rewards}

@api_router.post("/rewards/claim")
async def claim_reward(data: dict, user = Depends(get_current_user)):
    return {"success": True, "message": "Reward claim submitted"}

@api_router.get("/rewards/history")
async def rewards_history(user = Depends(get_current_user)):
    rewards = await db.rewards.find({"user_id": str(user["_id"])}).to_list(100)
    for r in rewards:
        r["id"] = str(r.pop("_id"))
    return {"success": True, "rewards": rewards}

# Referrals
@api_router.get("/referrals/list")
async def get_referrals(user = Depends(get_current_user)):
    referrals = await db.referrals.find({"referrer_id": str(user["_id"])}).to_list(100)
    referred_users = []
    for ref in referrals:
        ref_user = await db.users.find_one({"_id": ObjectId(ref["referred_id"])})
        if ref_user:
            referred_users.append({
                "full_name": ref_user.get("full_name"),
                "mobile": ref_user.get("mobile"),
                "is_active": ref_user.get("is_active", False),
                "joined_at": ref.get("created_at")
            })
    return {"success": True, "referrals": referred_users}

# Admin
@api_router.post("/admin/setup")
async def setup_admin(data: AdminSetup):
    if await db.admins.find_one({}):
        raise HTTPException(status_code=400, detail="Admin already exists")
    result = await db.admins.insert_one({
        "email": data.email.lower(), 
        "password": hash_password(data.password), 
        "name": data.name, 
        "role": "super_admin", 
        "created_at": datetime.utcnow().isoformat()
    })
    return {"success": True, "message": "Admin created", "admin_id": str(result.inserted_id)}

@api_router.post("/admin/login")
async def admin_login(data: AdminLogin):
    admin = await db.admins.find_one({"email": data.email.lower()})
    if not admin or not verify_password(data.password, admin.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"success": True, "token": create_token(str(admin["_id"])), "role": "admin", "name": admin.get("name")}

@api_router.post("/admin/change-password")
async def admin_change_password(data: AdminChangePassword, admin = Depends(get_current_admin)):
    if not verify_password(data.current_password, admin.get("password", "")):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    await db.admins.update_one({"_id": admin["_id"]}, {"$set": {"password": hash_password(data.new_password)}})
    return {"success": True, "message": "Password changed"}

@api_router.get("/admin/stats")
async def admin_stats(admin = Depends(get_current_admin)):
    approved_deposits = await db.payments.find({"status": "approved"}).to_list(1000)
    total_deposits = sum(d.get("amount", 0) for d in approved_deposits)
    
    completed_withdrawals = await db.withdrawals.find({"status": "successful"}).to_list(1000)
    total_withdrawals = sum(w.get("final_amount", 0) for w in completed_withdrawals)
    total_commission = sum(w.get("admin_charge", 0) for w in completed_withdrawals)
    
    return {
        "success": True, 
        "stats": {
            "total_users": await db.users.count_documents({}), 
            "active_users": await db.users.count_documents({"is_active": True}),
            "pending_deposits": await db.payments.count_documents({"status": "pending"}), 
            "pending_withdrawals": await db.withdrawals.count_documents({"status": "pending"}),
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_commission": total_commission
        }
    }

@api_router.get("/admin/pending-deposits")
async def get_pending_deposits(admin = Depends(get_current_admin)):
    deposits = await db.payments.find({}).sort("created_at", -1).to_list(200)
    for d in deposits:
        d["id"] = str(d.pop("_id"))
    return {"success": True, "deposits": deposits}

@api_router.get("/admin/pending-withdrawals")
async def get_pending_withdrawals(admin = Depends(get_current_admin)):
    withdrawals = await db.withdrawals.find({}).sort("created_at", -1).to_list(200)
    for w in withdrawals:
        w["id"] = str(w.pop("_id"))
    return {"success": True, "withdrawals": withdrawals}

@api_router.post("/admin/verify-payment")
async def verify_payment(data: dict, admin = Depends(get_current_admin)):
    payment = await db.payments.find_one({"_id": ObjectId(data.get("payment_id"))})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    status = data.get("status", data.get("action", ""))
    if status == "approve":
        status = "approved"
    elif status == "reject":
        status = "rejected"
    
    await db.payments.update_one({"_id": payment["_id"]}, {"$set": {"status": status, "verified_at": datetime.utcnow().isoformat()}})
    
    if status == "approved":
        # Create user package
        package = next((p for p in PACKAGES if p["id"] == payment.get("package_id")), None)
        if package:
            await db.user_packages.insert_one({
                "user_id": payment["user_id"],
                "package_id": package["id"],
                "package_name": package["name"],
                "amount": package["amount"],
                "daily_income": package["daily_income"],
                "is_active": True,
                "activated_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(days=package["duration_days"])).isoformat()
            })
            # Activate user
            await db.users.update_one({"_id": ObjectId(payment["user_id"])}, {"$set": {"is_active": True}})
    
    return {"success": True, "message": f"Payment {status}"}

@api_router.post("/admin/verify-withdrawal")
async def verify_withdrawal(data: dict, admin = Depends(get_current_admin)):
    withdrawal = await db.withdrawals.find_one({"_id": ObjectId(data.get("withdrawal_id"))})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    
    status = data.get("status")
    update = {"status": status, "processed_at": datetime.utcnow().isoformat()}
    
    if data.get("admin_utr"):
        update["admin_utr"] = data.get("admin_utr")
    if data.get("admin_screenshot"):
        update["admin_screenshot"] = data.get("admin_screenshot")
    
    await db.withdrawals.update_one({"_id": withdrawal["_id"]}, {"$set": update})
    
    if status == "rejected":
        await db.users.update_one({"_id": ObjectId(withdrawal["user_id"])}, {"$inc": {"wallet_balance": withdrawal["amount"]}})
    
    return {"success": True, "message": f"Withdrawal {status}"}

@api_router.get("/admin/users")
async def get_all_users(admin = Depends(get_current_admin)):
    users = await db.users.find({}).to_list(1000)
    for u in users:
        u["id"] = str(u.pop("_id"))
        u.pop("login_password", None)
        u.pop("transaction_password", None)
        u.pop("date_of_birth", None)
    return {"success": True, "users": users}

@api_router.post("/admin/update-wallet")
async def update_wallet(data: dict, admin = Depends(get_current_admin)):
    await db.users.update_one({"_id": ObjectId(data.get("user_id"))}, {"$set": {"wallet_balance": float(data.get("new_balance", 0))}})
    return {"success": True, "message": "Wallet updated"}

@api_router.get("/admin/settings")
async def get_settings(admin = Depends(get_current_admin)):
    settings = await db.settings.find_one({"type": "upi"})
    return {
        "success": True, 
        "settings": {
            "upi_id": settings.get("upi_id") if settings else os.environ.get("UPI_ID", ""), 
            "payee_name": settings.get("payee_name") if settings else os.environ.get("PAYEE_NAME", "Growmore Exchange")
        }
    }

@api_router.post("/admin/settings")
async def update_settings(data: dict, admin = Depends(get_current_admin)):
    await db.settings.update_one({"type": "upi"}, {"$set": {"upi_id": data.get("upi_id"), "payee_name": data.get("payee_name")}}, upsert=True)
    return {"success": True, "message": "Settings updated"}

# Startup
@app.on_event("startup")
async def startup():
    # Create default referrer
    if not await db.users.find_one({"referral_code": "ADMIN001"}):
        await db.users.insert_one({
            "full_name": "System",
            "mobile": "0000000000",
            "referral_code": "ADMIN001",
            "login_password": hash_password("admin123"),
            "transaction_password": hash_password("admin123"),
            "is_active": True,
            "wallet_balance": 0,
            "created_at": datetime.utcnow().isoformat()
        })

app.include_router(api_router)

@app.get("/")
async def root():
    return {"status": "ok", "message": "Growmore Exchange API"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
