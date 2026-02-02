from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
from pydantic import BaseModel
from typing import Optional, List
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

# ==================== MODELS ====================

class UserSignup(BaseModel):
    full_name: str
    mobile: str
    date_of_birth: str
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

# ==================== PACKAGES & REWARDS CONFIG ====================

PACKAGES = [
    {"id": "copper", "name": "Copper", "amount": 1500, "daily_income": 100, "duration_days": 30, "total_return": 3000, "color": "#B87333", "glow": "#8C4A1E"},
    {"id": "crypto", "name": "Crypto", "amount": 3000, "daily_income": 200, "duration_days": 30, "total_return": 6000, "color": "#00E5FF", "glow": "#006064"},
    {"id": "aipower", "name": "AI Power", "amount": 6000, "daily_income": 400, "duration_days": 30, "total_return": 12000, "color": "#7B61FF", "glow": "#2E1A47"},
    {"id": "solar", "name": "Solar Energy", "amount": 12000, "daily_income": 800, "duration_days": 30, "total_return": 24000, "color": "#FFC107", "glow": "#FF8F00"},
    {"id": "gold", "name": "Gold", "amount": 24000, "daily_income": 1600, "duration_days": 30, "total_return": 48000, "color": "#D4AF37", "glow": "#8E6F1E"},
    {"id": "silver", "name": "Silver", "amount": 48000, "daily_income": 3200, "duration_days": 30, "total_return": 96000, "color": "#C0C0C0", "glow": "#7A7A7A"},
]

REWARD_STRUCTURE = {
    "copper": {"25_ids": 11000, "50_ids": 21000},
    "crypto": {"25_ids": 21000, "50_ids": 51000},
    "aipower": {"25_ids": 51000, "50_ids": 81000},
    "solar": {"25_ids": 81000, "50_ids": 121000},
    "gold": {"25_ids": 121000, "50_ids": 221000},
    "silver": {"25_ids": 221000, "50_ids": 551000}
}

# ==================== HELPERS ====================

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

# ==================== AUTH ENDPOINTS ====================

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
        "date_of_birth": hash_password(data.date_of_birth),
        "user_id": generate_user_id(),
        "referral_code": generate_referral_code(),
        "referred_by": data.referral_code,
        "referrer_id": str(referrer["_id"]) if referrer else None,
        "wallet_balance": 0,
        "total_income": 0,
        "today_income": 0,
        "referral_income": 0,
        "reward_income": 0,
        "is_active": False,
        "active_package_id": None,
        "active_package_name": None,
        "created_at": datetime.utcnow().isoformat()
    }
    result = await db.users.insert_one(user)
    
    # Track referral
    if referrer:
        await db.referrals.insert_one({
            "referrer_id": str(referrer["_id"]),
            "referred_id": str(result.inserted_id),
            "referred_user_id": user["user_id"],
            "referred_name": user["full_name"],
            "referred_mobile": user["mobile"],
            "package_id": None,
            "package_name": None,
            "package_amount": 0,
            "commission_paid": False,
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
    
    stored_dob = user.get("date_of_birth")
    if not stored_dob or not verify_password(data.date_of_birth, stored_dob):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"login_password": hash_password(data.new_password)}})
    return {"success": True, "message": "Password updated"}

@api_router.post("/auth/reset-transaction-password")
async def reset_transaction_password(data: dict, user = Depends(get_current_user)):
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"transaction_password": hash_password(new_password)}})
    return {"success": True, "message": "Transaction password updated"}

# ==================== USER ENDPOINTS ====================

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
            "total_income": user.get("total_income", 0),
            "today_income": user.get("today_income", 0),
            "referral_income": user.get("referral_income", 0),
            "reward_income": user.get("reward_income", 0),
            "is_active": user.get("is_active", False),
            "active_package_id": user.get("active_package_id"),
            "active_package_name": user.get("active_package_name"),
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
    
    # Get referral count with same package
    referral_count = await db.referrals.count_documents({"referrer_id": str(user["_id"])})
    same_package_referrals = 0
    if user.get("active_package_id"):
        same_package_referrals = await db.referrals.count_documents({
            "referrer_id": str(user["_id"]),
            "package_id": user.get("active_package_id")
        })
    
    # Get total invested
    approved_deposits = await db.payments.find({"user_id": str(user["_id"]), "status": "approved"}).to_list(100)
    total_invested = sum(d.get("amount", 0) for d in approved_deposits)
    
    # Get package color
    package_color = "#22C55E"  # Default green
    if user.get("active_package_id"):
        pkg = next((p for p in PACKAGES if p["id"] == user.get("active_package_id")), None)
        if pkg:
            package_color = pkg["color"]
    
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
            "active_package_id": user.get("active_package_id"),
            "active_package_name": user.get("active_package_name"),
            "package_color": package_color,
            "referral_count": referral_count,
            "same_package_referrals": same_package_referrals,
            "my_referral_code": user.get("referral_code", ""),
            "can_withdraw": same_package_referrals >= 2  # 2 direct IDs required
        }
    }

# ==================== REFERRAL ENDPOINTS ====================

@api_router.get("/referrals/list")
async def get_referrals(user = Depends(get_current_user)):
    """Get list of referred members with package details"""
    referrals = await db.referrals.find({"referrer_id": str(user["_id"])}).to_list(1000)
    
    referred_users = []
    for ref in referrals:
        ref_user = await db.users.find_one({"_id": ObjectId(ref["referred_id"])})
        if ref_user:
            referred_users.append({
                "id": str(ref_user["_id"]),
                "full_name": ref_user.get("full_name"),
                "user_id": ref_user.get("user_id"),
                "mobile": ref_user.get("mobile"),
                "package_id": ref_user.get("active_package_id"),
                "package_name": ref_user.get("active_package_name") or "No Package",
                "package_amount": ref.get("package_amount", 0),
                "is_active": ref_user.get("is_active", False),
                "joined_at": ref.get("created_at")
            })
    
    return {"success": True, "referrals": referred_users, "total_count": len(referred_users)}

@api_router.get("/referrals/stats")
async def get_referral_stats(user = Depends(get_current_user)):
    """Get referral statistics for withdrawal eligibility"""
    total_referrals = await db.referrals.count_documents({"referrer_id": str(user["_id"])})
    
    # Count referrals with same package
    same_package_count = 0
    if user.get("active_package_id"):
        same_package_count = await db.referrals.count_documents({
            "referrer_id": str(user["_id"]),
            "package_id": user.get("active_package_id")
        })
    
    return {
        "success": True,
        "total_referrals": total_referrals,
        "same_package_referrals": same_package_count,
        "can_withdraw": same_package_count >= 2,
        "required_for_withdrawal": 2,
        "active_package_id": user.get("active_package_id")
    }

# ==================== PACKAGE ENDPOINTS ====================

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
    if not verify_password(data.transaction_password, user.get("transaction_password", "")):
        raise HTTPException(status_code=400, detail="Invalid transaction password")
    
    package = next((p for p in PACKAGES if p["id"] == data.package_id), None)
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
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

# ==================== WALLET & WITHDRAWAL ====================

@api_router.post("/wallet/withdraw")
async def request_withdrawal(data: WithdrawalRequest, user = Depends(get_current_user)):
    # Verify transaction password
    if not verify_password(data.transaction_password, user.get("transaction_password", "")):
        raise HTTPException(status_code=401, detail="Invalid transaction password")
    
    # Check 2 direct IDs requirement
    same_package_referrals = 0
    if user.get("active_package_id"):
        same_package_referrals = await db.referrals.count_documents({
            "referrer_id": str(user["_id"]),
            "package_id": user.get("active_package_id")
        })
    
    if same_package_referrals < 2:
        raise HTTPException(
            status_code=400, 
            detail=f"You need at least 2 direct referrals with the same package to withdraw. Current: {same_package_referrals}"
        )
    
    if user.get("wallet_balance", 0) < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    if data.amount < 500:
        raise HTTPException(status_code=400, detail="Minimum withdrawal is ₹500")
    
    admin_charge = data.amount * 0.10
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

@api_router.get("/wallet/withdrawal-eligibility")
async def check_withdrawal_eligibility(user = Depends(get_current_user)):
    """Check if user can withdraw based on 2 direct IDs rule"""
    same_package_referrals = 0
    if user.get("active_package_id"):
        same_package_referrals = await db.referrals.count_documents({
            "referrer_id": str(user["_id"]),
            "package_id": user.get("active_package_id")
        })
    
    return {
        "success": True,
        "can_withdraw": same_package_referrals >= 2,
        "same_package_referrals": same_package_referrals,
        "required": 2,
        "wallet_balance": user.get("wallet_balance", 0),
        "min_withdrawal": 500,
        "admin_charge_percent": 10
    }

# ==================== REWARDS SYSTEM ====================

@api_router.get("/rewards/eligible")
async def get_eligible_rewards(user = Depends(get_current_user)):
    """Get reward status for each package - Locked/Active/Unlocked"""
    user_package_id = user.get("active_package_id")
    
    # Count referrals per package
    referral_counts = {}
    for pkg in PACKAGES:
        count = await db.referrals.count_documents({
            "referrer_id": str(user["_id"]),
            "package_id": pkg["id"]
        })
        referral_counts[pkg["id"]] = count
    
    # Get claimed rewards
    claimed_rewards = await db.rewards.find({
        "user_id": str(user["_id"]),
        "status": {"$in": ["pending", "approved"]}
    }).to_list(100)
    claimed_set = set((r["package_id"], r["reward_type"]) for r in claimed_rewards)
    
    rewards_status = []
    for pkg in PACKAGES:
        pkg_referrals = referral_counts.get(pkg["id"], 0)
        pkg_rewards = REWARD_STRUCTURE.get(pkg["id"], {})
        
        # Determine status
        # Locked: No referrals with this package
        # Active: Has referrals but not reached 25/50 target
        # Unlocked: Reached 25 or 50 target
        
        status_25 = "locked"
        status_50 = "locked"
        
        if pkg_referrals >= 1:
            status_25 = "active"
            status_50 = "active"
        
        if pkg_referrals >= 25:
            if (pkg["id"], "25_ids") in claimed_set:
                status_25 = "claimed"
            else:
                status_25 = "unlocked"
        
        if pkg_referrals >= 50:
            if (pkg["id"], "50_ids") in claimed_set:
                status_50 = "claimed"
            else:
                status_50 = "unlocked"
        
        rewards_status.append({
            "package_id": pkg["id"],
            "package_name": pkg["name"],
            "package_color": pkg["color"],
            "package_glow": pkg["glow"],
            "referral_count": pkg_referrals,
            "reward_25_ids": {
                "amount": pkg_rewards.get("25_ids", 0),
                "status": status_25,
                "required": 25,
                "progress": min(pkg_referrals, 25)
            },
            "reward_50_ids": {
                "amount": pkg_rewards.get("50_ids", 0),
                "status": status_50,
                "required": 50,
                "progress": min(pkg_referrals, 50)
            }
        })
    
    return {
        "success": True,
        "rewards": rewards_status,
        "active_package_id": user_package_id
    }

@api_router.post("/rewards/claim")
async def claim_reward(data: dict, user = Depends(get_current_user)):
    package_id = data.get("package_id")
    reward_type = data.get("reward_type")  # "25_ids" or "50_ids"
    
    if reward_type not in ["25_ids", "50_ids"]:
        raise HTTPException(status_code=400, detail="Invalid reward type")
    
    # Check if already claimed
    existing = await db.rewards.find_one({
        "user_id": str(user["_id"]),
        "package_id": package_id,
        "reward_type": reward_type,
        "status": {"$in": ["pending", "approved"]}
    })
    if existing:
        raise HTTPException(status_code=400, detail="Reward already claimed")
    
    # Check eligibility
    required = 25 if reward_type == "25_ids" else 50
    referral_count = await db.referrals.count_documents({
        "referrer_id": str(user["_id"]),
        "package_id": package_id
    })
    
    if referral_count < required:
        raise HTTPException(status_code=400, detail=f"Need {required} referrals, have {referral_count}")
    
    reward_amount = REWARD_STRUCTURE.get(package_id, {}).get(reward_type, 0)
    
    await db.rewards.insert_one({
        "user_id": str(user["_id"]),
        "user_name": user.get("full_name"),
        "user_mobile": user.get("mobile"),
        "package_id": package_id,
        "reward_type": reward_type,
        "amount": reward_amount,
        "referral_count_at_claim": referral_count,
        "status": "pending",
        "claimed_at": datetime.utcnow().isoformat()
    })
    
    return {"success": True, "message": "Reward claim submitted", "amount": reward_amount}

@api_router.get("/rewards/history")
async def rewards_history(user = Depends(get_current_user)):
    rewards = await db.rewards.find({"user_id": str(user["_id"])}).sort("claimed_at", -1).to_list(100)
    for r in rewards:
        r["id"] = str(r.pop("_id"))
    return {"success": True, "rewards": rewards}

# ==================== SUPPORT ====================

@api_router.get("/support/contact")
async def get_support_contact():
    return {
        "success": True,
        "support": {
            "email": "support@growmoreexchange.com"
        }
    }

# ==================== ADMIN ENDPOINTS ====================

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
            "pending_rewards": await db.rewards.count_documents({"status": "pending"}),
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_commission": total_commission
        }
    }

@api_router.get("/admin/pending-deposits")
async def get_pending_deposits(admin = Depends(get_current_admin)):
    deposits = await db.payments.find({}).sort("created_at", -1).to_list(500)
    for d in deposits:
        d["id"] = str(d.pop("_id"))
    return {"success": True, "deposits": deposits}

@api_router.get("/admin/pending-withdrawals")
async def get_pending_withdrawals(admin = Depends(get_current_admin)):
    withdrawals = await db.withdrawals.find({}).sort("created_at", -1).to_list(500)
    for w in withdrawals:
        w["id"] = str(w.pop("_id"))
    return {"success": True, "withdrawals": withdrawals}

@api_router.get("/admin/pending-rewards")
async def get_pending_rewards(admin = Depends(get_current_admin)):
    rewards = await db.rewards.find({}).sort("claimed_at", -1).to_list(500)
    for r in rewards:
        r["id"] = str(r.pop("_id"))
    return {"success": True, "rewards": rewards}

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
        package = next((p for p in PACKAGES if p["id"] == payment.get("package_id")), None)
        if package:
            # Create user package
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
            
            # Activate user and set active package
            await db.users.update_one(
                {"_id": ObjectId(payment["user_id"])},
                {"$set": {
                    "is_active": True,
                    "active_package_id": package["id"],
                    "active_package_name": package["name"]
                }}
            )
            
            # Process referral income (10%)
            user = await db.users.find_one({"_id": ObjectId(payment["user_id"])})
            if user and user.get("referrer_id"):
                referrer = await db.users.find_one({"_id": ObjectId(user["referrer_id"])})
                if referrer:
                    referral_income = package["amount"] * 0.10
                    
                    # Credit to referrer
                    await db.users.update_one(
                        {"_id": referrer["_id"]},
                        {"$inc": {
                            "wallet_balance": referral_income,
                            "referral_income": referral_income,
                            "total_income": referral_income,
                            "today_income": referral_income
                        }}
                    )
                    
                    # Update referral record with package info
                    await db.referrals.update_one(
                        {"referred_id": payment["user_id"]},
                        {"$set": {
                            "package_id": package["id"],
                            "package_name": package["name"],
                            "package_amount": package["amount"],
                            "commission_paid": True,
                            "commission_amount": referral_income,
                            "commission_date": datetime.utcnow().isoformat()
                        }}
                    )
                    
                    # Record transaction
                    await db.transactions.insert_one({
                        "user_id": str(referrer["_id"]),
                        "type": "referral_income",
                        "amount": referral_income,
                        "from_user": user.get("full_name"),
                        "package_name": package["name"],
                        "description": f"10% referral commission from {user.get('full_name')}",
                        "created_at": datetime.utcnow().isoformat()
                    })
    
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

@api_router.post("/admin/verify-reward")
async def verify_reward(data: dict, admin = Depends(get_current_admin)):
    reward = await db.rewards.find_one({"_id": ObjectId(data.get("reward_id"))})
    if not reward:
        raise HTTPException(status_code=404, detail="Reward not found")
    
    action = data.get("action")
    
    if action == "approve":
        await db.rewards.update_one(
            {"_id": reward["_id"]},
            {"$set": {"status": "approved", "verified_at": datetime.utcnow().isoformat()}}
        )
        
        # Credit reward to user
        await db.users.update_one(
            {"_id": ObjectId(reward["user_id"])},
            {"$inc": {
                "wallet_balance": reward["amount"],
                "reward_income": reward["amount"],
                "total_income": reward["amount"]
            }}
        )
        
        return {"success": True, "message": "Reward approved and credited"}
    
    elif action == "reject":
        await db.rewards.update_one(
            {"_id": reward["_id"]},
            {"$set": {"status": "rejected", "verified_at": datetime.utcnow().isoformat()}}
        )
        return {"success": True, "message": "Reward rejected"}
    
    raise HTTPException(status_code=400, detail="Invalid action")

@api_router.get("/admin/users")
async def get_all_users(admin = Depends(get_current_admin)):
    users = await db.users.find({}).to_list(1000)
    for u in users:
        u["id"] = str(u.pop("_id"))
        u.pop("login_password", None)
        u.pop("transaction_password", None)
        u.pop("date_of_birth", None)
    return {"success": True, "users": users}

@api_router.get("/admin/referrals")
async def get_all_referrals(admin = Depends(get_current_admin)):
    """Get all referrals for admin with full details"""
    referrals = await db.referrals.find({}).sort("created_at", -1).to_list(1000)
    
    result = []
    for ref in referrals:
        referrer = await db.users.find_one({"_id": ObjectId(ref["referrer_id"])})
        referred = await db.users.find_one({"_id": ObjectId(ref["referred_id"])})
        
        result.append({
            "id": str(ref["_id"]),
            "referrer_name": referrer.get("full_name") if referrer else "Unknown",
            "referrer_id": referrer.get("user_id") if referrer else "Unknown",
            "referrer_mobile": referrer.get("mobile") if referrer else "Unknown",
            "referred_name": referred.get("full_name") if referred else "Unknown",
            "referred_user_id": referred.get("user_id") if referred else "Unknown",
            "referred_mobile": referred.get("mobile") if referred else "Unknown",
            "package_name": ref.get("package_name") or "No Package",
            "package_amount": ref.get("package_amount", 0),
            "commission_paid": ref.get("commission_paid", False),
            "commission_amount": ref.get("commission_amount", 0),
            "created_at": ref.get("created_at")
        })
    
    return {"success": True, "referrals": result}

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

# ==================== STARTUP ====================

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
    return {"status": "ok", "message": "Growmore Exchange API v3"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
