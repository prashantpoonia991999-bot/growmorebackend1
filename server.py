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

# Models
class UserSignup(BaseModel):
    full_name: str
    mobile: str
    password: str
    dob: str
    referral_code: Optional[str] = None

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
    dob: str
    new_password: str

class DepositRequest(BaseModel):
    amount: float
    utr: str

class WithdrawalRequest(BaseModel):
    amount: float
    withdrawal_type: str
    upi_id: Optional[str] = None
    bank_name: Optional[str] = None
    account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None

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
    if not all([data.full_name, data.mobile, data.password, data.dob]):
        raise HTTPException(status_code=400, detail="All fields required")
    if await db.users.find_one({"mobile": data.mobile}):
        raise HTTPException(status_code=400, detail="Mobile already registered")
    user = {
        "full_name": data.full_name, "mobile": data.mobile, "password": hash_password(data.password),
        "dob": data.dob, "user_id": generate_user_id(), "referral_code": generate_referral_code(),
        "referred_by": data.referral_code, "wallet_balance": 0, "total_investment": 0,
        "total_income": 0, "created_at": datetime.utcnow().isoformat()
    }
    result = await db.users.insert_one(user)
    return {"success": True, "token": create_token(str(result.inserted_id)), "user_id": user["user_id"]}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"mobile": data.mobile})
    if not user or not verify_password(data.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "token": create_token(str(user["_id"])), "user_id": user.get("user_id")}

@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPassword):
    user = await db.users.find_one({"mobile": data.mobile})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("dob") != data.dob:
        raise HTTPException(status_code=400, detail="DOB does not match")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"password": hash_password(data.new_password)}})
    return {"success": True, "message": "Password updated"}

# User
@api_router.get("/user/profile")
async def get_profile(user = Depends(get_current_user)):
    return {"success": True, "user": {"full_name": user.get("full_name"), "mobile": user.get("mobile"), "user_id": user.get("user_id"), "referral_code": user.get("referral_code"), "wallet_balance": user.get("wallet_balance", 0), "total_investment": user.get("total_investment", 0), "dob": user.get("dob")}}

@api_router.get("/user/dashboard")
async def get_dashboard(user = Depends(get_current_user)):
    investments = await db.investments.find({"user_id": str(user["_id"])}).to_list(100)
    return {"success": True, "wallet_balance": user.get("wallet_balance", 0), "total_investment": sum(i.get("amount", 0) for i in investments), "total_income": user.get("total_income", 0), "referral_code": user.get("referral_code"), "investments": investments}

@api_router.post("/user/deposit")
async def request_deposit(data: DepositRequest, user = Depends(get_current_user)):
    await db.payments.insert_one({"user_id": str(user["_id"]), "user_mobile": user.get("mobile"), "user_name": user.get("full_name"), "amount": data.amount, "utr": data.utr, "status": "pending", "created_at": datetime.utcnow().isoformat()})
    return {"success": True, "message": "Deposit request submitted"}

@api_router.post("/user/withdraw")
async def request_withdrawal(data: WithdrawalRequest, user = Depends(get_current_user)):
    if user.get("wallet_balance", 0) < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    await db.withdrawals.insert_one({"user_id": str(user["_id"]), "user_mobile": user.get("mobile"), "user_name": user.get("full_name"), "amount": data.amount, "withdrawal_type": data.withdrawal_type, "upi_id": data.upi_id, "bank_name": data.bank_name, "account_number": data.account_number, "ifsc_code": data.ifsc_code, "status": "pending", "admin_charge": data.amount * 0.1, "final_amount": data.amount * 0.9, "created_at": datetime.utcnow().isoformat()})
    await db.users.update_one({"_id": user["_id"]}, {"$inc": {"wallet_balance": -data.amount}})
    return {"success": True, "message": "Withdrawal request submitted"}

@api_router.get("/user/transactions")
async def get_transactions(user = Depends(get_current_user)):
    deposits = await db.payments.find({"user_id": str(user["_id"])}).to_list(100)
    withdrawals = await db.withdrawals.find({"user_id": str(user["_id"])}).to_list(100)
    for d in deposits: d["id"], d["type"] = str(d.pop("_id")), "deposit"
    for w in withdrawals: w["id"], w["type"] = str(w.pop("_id")), "withdrawal"
    return {"success": True, "deposits": deposits, "withdrawals": withdrawals}

# Packages
PACKAGES = [
    {"id": "copper", "name": "Copper", "price": 1000, "daily_income": 50, "total_days": 300},
    {"id": "crypto", "name": "Crypto", "price": 3000, "daily_income": 150, "total_days": 300},
    {"id": "aipower", "name": "AI Power", "price": 5000, "daily_income": 250, "total_days": 300},
    {"id": "solar", "name": "Solar", "price": 10000, "daily_income": 500, "total_days": 300},
    {"id": "gold", "name": "Gold", "price": 30000, "daily_income": 1500, "total_days": 300},
    {"id": "platinum", "name": "Platinum", "price": 50000, "daily_income": 2500, "total_days": 300}
]

REWARD_STRUCTURE = {
    "copper": {"25_ids": 11000, "50_ids": 21000}, "crypto": {"25_ids": 21000, "50_ids": 51000},
    "aipower": {"25_ids": 51000, "50_ids": 81000}, "solar": {"25_ids": 81000, "50_ids": 121000},
    "gold": {"25_ids": 121000, "50_ids": 221000}, "platinum": {"25_ids": 221000, "50_ids": 551000}
}

@api_router.get("/packages")
async def get_packages():
    return {"success": True, "packages": PACKAGES}

@api_router.post("/packages/purchase")
async def purchase_package(data: dict, user = Depends(get_current_user)):
    package = next((p for p in PACKAGES if p["id"] == data.get("package_id")), None)
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    if user.get("wallet_balance", 0) < package["price"]:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    await db.investments.insert_one({"user_id": str(user["_id"]), "package_id": package["id"], "package_name": package["name"], "amount": package["price"], "daily_income": package["daily_income"], "total_days": package["total_days"], "days_completed": 0, "status": "active", "created_at": datetime.utcnow().isoformat()})
    await db.users.update_one({"_id": user["_id"]}, {"$inc": {"wallet_balance": -package["price"], "total_investment": package["price"]}})
    return {"success": True, "message": "Package purchased"}

@api_router.get("/rewards/eligible")
async def get_eligible_rewards(user = Depends(get_current_user)):
    referrals = await db.users.find({"referred_by": user.get("referral_code")}).to_list(1000)
    active = len([r for r in referrals if r.get("total_investment", 0) > 0])
    all_rewards = [{"package_id": k, "package_name": next((p["name"] for p in PACKAGES if p["id"]==k), k), "rewards": v} for k, v in REWARD_STRUCTURE.items()]
    return {"success": True, "eligible_rewards": [], "active_referrals": active, "all_rewards": all_rewards}

@api_router.post("/rewards/claim")
async def claim_reward(data: dict, user = Depends(get_current_user)):
    return {"success": True, "message": "Reward claimed"}

@api_router.get("/rewards/history")
async def rewards_history(user = Depends(get_current_user)):
    rewards = await db.rewards.find({"user_id": str(user["_id"])}).to_list(100)
    return {"success": True, "rewards": rewards}

# Admin
@api_router.post("/admin/setup")
async def setup_admin(data: AdminSetup):
    if await db.admins.find_one({}):
        raise HTTPException(status_code=400, detail="Admin already exists")
    result = await db.admins.insert_one({"email": data.email.lower(), "password": hash_password(data.password), "name": data.name, "role": "super_admin", "created_at": datetime.utcnow().isoformat()})
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
    return {"success": True, "stats": {"total_users": await db.users.count_documents({}), "total_deposits": await db.payments.count_documents({}), "total_withdrawals": await db.withdrawals.count_documents({}), "pending_deposits": await db.payments.count_documents({"status": "pending"}), "pending_withdrawals": await db.withdrawals.count_documents({"status": "pending"})}}

@api_router.get("/admin/deposits")
async def get_deposits(admin = Depends(get_current_admin)):
    deposits = await db.payments.find({}).sort("created_at", -1).to_list(1000)
    for d in deposits: d["id"] = str(d.pop("_id"))
    return {"success": True, "deposits": deposits}

@api_router.get("/admin/withdrawals")
async def get_withdrawals(admin = Depends(get_current_admin)):
    withdrawals = await db.withdrawals.find({}).sort("created_at", -1).to_list(1000)
    for w in withdrawals: w["id"] = str(w.pop("_id"))
    return {"success": True, "withdrawals": withdrawals}

@api_router.post("/admin/verify-payment")
async def verify_payment(data: dict, admin = Depends(get_current_admin)):
    payment = await db.payments.find_one({"_id": ObjectId(data.get("payment_id"))})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    await db.payments.update_one({"_id": payment["_id"]}, {"$set": {"status": data.get("status")}})
    if data.get("status") == "approved":
        await db.users.update_one({"_id": ObjectId(payment["user_id"])}, {"$inc": {"wallet_balance": payment["amount"]}})
    return {"success": True, "message": f"Payment {data.get('status')}"}

@api_router.post("/admin/verify-withdrawal")
async def verify_withdrawal(data: dict, admin = Depends(get_current_admin)):
    withdrawal = await db.withdrawals.find_one({"_id": ObjectId(data.get("withdrawal_id"))})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    update = {"status": data.get("status")}
    if data.get("admin_utr"):
        update["admin_utr"] = data.get("admin_utr")
    await db.withdrawals.update_one({"_id": withdrawal["_id"]}, {"$set": update})
    if data.get("status") == "rejected":
        await db.users.update_one({"_id": ObjectId(withdrawal["user_id"])}, {"$inc": {"wallet_balance": withdrawal["amount"]}})
    return {"success": True, "message": f"Withdrawal {data.get('status')}"}

@api_router.get("/admin/users")
async def get_all_users(admin = Depends(get_current_admin)):
    users = await db.users.find({}).to_list(1000)
    for u in users:
        u["id"] = str(u.pop("_id"))
        u.pop("password", None)
    return {"success": True, "users": users}

@api_router.post("/admin/update-wallet")
async def update_wallet(data: dict, admin = Depends(get_current_admin)):
    await db.users.update_one({"_id": ObjectId(data.get("user_id"))}, {"$set": {"wallet_balance": data.get("new_balance")}})
    return {"success": True, "message": "Wallet updated"}

@api_router.get("/admin/settings")
async def get_settings(admin = Depends(get_current_admin)):
    settings = await db.settings.find_one({"type": "upi"})
    return {"success": True, "settings": {"upi_id": settings.get("upi_id") if settings else os.environ.get("UPI_ID", ""), "payee_name": settings.get("payee_name") if settings else os.environ.get("PAYEE_NAME", "Growmore Exchange")}}

@api_router.post("/admin/settings")
async def update_settings(data: dict, admin = Depends(get_current_admin)):
    await db.settings.update_one({"type": "upi"}, {"$set": {"upi_id": data.get("upi_id"), "payee_name": data.get("payee_name")}}, upsert=True)
    return {"success": True, "message": "Settings updated"}

@api_router.get("/payment/qr/{amount}")
async def get_qr_code(amount: float):
    settings = await db.settings.find_one({"type": "upi"})
    upi_id = settings.get("upi_id") if settings else os.environ.get("UPI_ID", "example@upi")
    payee = settings.get("payee_name") if settings else os.environ.get("PAYEE_NAME", "Growmore")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(f"upi://pay?pa={upi_id}&pn={payee}&am={amount}&cu=INR")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return {"success": True, "qr_code": f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}", "upi_id": upi_id}

app.include_router(api_router)

@app.get("/")
async def root():
    return {"status": "ok", "message": "Growmore Exchange API"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
