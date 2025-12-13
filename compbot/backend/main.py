# backend/main.py
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict
from pydantic import BaseModel, EmailStr, Field
import jwt
from uuid import uuid4
import logging
import math
import random

# ========== SETUP LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ugaeaekzhocwqdzdtrry.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVnYWVhZWt6aG9jd3FkemR0cnJ5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzM0MDQzMzMsImV4cCI6MjA0ODk4MDMzM30.3r7y8ryqpH7FBy-HwKN5TVpeL6hQsCFgC-nonBRkYFQ")
JWT_SECRET = os.getenv("JWT_SECRET", "xtourney-secret-key-2024")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us")

# Headers for Supabase
headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SUPABASE_KEY}"
}

# ========== APP INITIALIZATION ==========
app = FastAPI(title="XTourney API", version="1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== MODELS ==========
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=6)
    email: Optional[EmailStr] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TournamentCreate(BaseModel):
    name: str
    game: str
    max_teams: int = 16
    max_players: int = 5
    prize_pool: Optional[str] = None
    description: Optional[str] = None

# ========== SUPABASE HELPERS ==========
def supabase_request(method: str, endpoint: str, data: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{endpoint}"
    
    if method == "GET":
        response = requests.get(url, headers=headers)
    elif method == "POST":
        response = requests.post(url, json=data, headers=headers)
    elif method == "PATCH":
        response = requests.patch(url, json=data, headers=headers)
    elif method == "DELETE":
        response = requests.delete(url, headers=headers)
    elif method == "PUT":
        response = requests.put(url, json=data, headers=headers)
    else:
        raise ValueError(f"Invalid method: {method}")
    
    if response.status_code in [200, 201, 204]:
        try:
            return response.json()
        except:
            return {"success": True}
    elif response.status_code == 404:
        return []
    else:
        logger.error(f"Supabase error: {response.status_code} - {response.text}")
        raise HTTPException(status_code=500, detail="Database error")

# ========== AUTH HELPERS ==========
def create_token(user_data: dict) -> str:
    payload = {
        "sub": user_data.get("id"),
        "username": user_data.get("username"),
        "is_host": user_data.get("is_host", False),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    users = supabase_request("GET", f"users?id=eq.{user_id}")
    
    if not users or len(users) == 0:
        raise HTTPException(status_code=401, detail="User not found")
    
    return users[0]

# ========== ROUTES ==========
@app.get("/")
async def root():
    return {"message": "XTourney API", "status": "running"}

@app.post("/api/register")
async def register(user: UserRegister):
    """Register new user"""
    try:
        # Check if username exists
        existing = supabase_request("GET", f"users?username=eq.{user.username}")
        if existing and len(existing) > 0:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Hash password
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        # Create user
        user_id = str(uuid4())
        user_data = {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "password_hash": password_hash,
            "is_host": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("POST", "users", user_data)
        
        # Create token
        token = create_token(user_data)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "id": user_id,
                "username": user.username,
                "email": user.email,
                "is_host": False,
                "is_admin": False
            }
        }
        
    except Exception as e:
        logger.error(f"Register error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login")
async def login(user: UserLogin):
    """Login user"""
    try:
        # Find user
        users = supabase_request("GET", f"users?username=eq.{user.username}")
        if not users or len(users) == 0:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        db_user = users[0]
        
        # Verify password
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        if password_hash != db_user.get("password_hash"):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        supabase_request("PATCH", f"users?id=eq.{db_user['id']}", {
            "last_login": datetime.utcnow().isoformat()
        })
        
        # Create token
        token = create_token(db_user)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "id": db_user["id"],
                "username": db_user["username"],
                "email": db_user.get("email"),
                "is_host": db_user.get("is_host", False),
                "is_admin": db_user.get("is_admin", False)
            }
        }
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/tournaments")
async def get_tournaments():
    """Get all tournaments"""
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        
        # Get team counts for each tournament
        for tournament in tournaments:
            teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament['id']}")
            tournament["team_count"] = len(teams) if teams else 0
        
        return {
            "success": True,
            "tournaments": tournaments,
            "count": len(tournaments)
        }
        
    except Exception as e:
        logger.error(f"Get tournaments error: {e}")
        return {"success": True, "tournaments": [], "count": 0}

@app.post("/api/tournaments")
async def create_tournament(tournament: TournamentCreate, current_user: Dict = Depends(get_current_user)):
    """Create tournament"""
    try:
        if not current_user.get("is_host") and not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Only hosts can create tournaments")
        
        # Generate tournament pass
        tournament_pass = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        
        # Create tournament
        tournament_id = str(uuid4())
        tournament_data = {
            "id": tournament_id,
            "name": tournament.name,
            "game": tournament.game,
            "description": tournament.description,
            "max_teams": tournament.max_teams,
            "max_players": tournament.max_players,
            "prize_pool": tournament.prize_pool,
            "status": "registration",
            "created_by": current_user["id"],
            "host_id": current_user["id"],
            "tournament_pass": tournament_pass,
            "created_at": datetime.utcnow().isoformat(),
            "current_teams": 0,
            "total_rounds": math.ceil(math.log2(tournament.max_teams))
        }
        
        supabase_request("POST", "tournaments", tournament_data)
        
        return {
            "success": True,
            "tournament": tournament_data,
            "tournament_pass": tournament_pass
        }
        
    except Exception as e:
        logger.error(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.get("/api/stats")
async def get_stats():
    """Get platform statistics"""
    try:
        # Get counts from Supabase
        tournaments = supabase_request("GET", "tournaments?status=in.(registration,ongoing)")
        teams = supabase_request("GET", "teams")
        servers = supabase_request("GET", "bot_servers")
        
        return {
            "success": True,
            "stats": {
                "active_tournaments": len(tournaments) if tournaments else 0,
                "total_teams": len(teams) if teams else 0,
                "connected_servers": len(servers) if servers else 0,
                "live_matches": 0  # You'll need to implement this
            }
        }
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {
            "success": True,
            "stats": {
                "active_tournaments": 0,
                "total_teams": 0,
                "connected_servers": 0,
                "live_matches": 0
            }
        }

@app.post("/api/bot/server-stats")
async def update_server_stats(request: Request):
    """Update server stats from bot"""
    try:
        data = await request.json()
        
        server_id = data.get("server_id")
        server_name = data.get("server_name")
        member_count = data.get("member_count", 0)
        icon_url = data.get("icon_url")
        
        if not server_id:
            raise HTTPException(status_code=400, detail="Server ID required")
        
        # Check if server exists
        servers = supabase_request("GET", f"bot_servers?server_id=eq.{server_id}")
        
        server_data = {
            "server_id": server_id,
            "server_name": server_name,
            "member_count": member_count,
            "icon_url": icon_url,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        if servers and len(servers) > 0:
            # Update existing
            supabase_request("PATCH", f"bot_servers?server_id=eq.{server_id}", server_data)
        else:
            # Create new
            server_data["created_at"] = datetime.utcnow().isoformat()
            supabase_request("POST", "bot_servers", server_data)
        
        return {"success": True, "message": "Server stats updated"}
        
    except Exception as e:
        logger.error(f"Server stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update server stats")

@app.get("/api/bot/servers")
async def get_servers():
    """Get all bot servers"""
    try:
        servers = supabase_request("GET", "bot_servers")
        return {
            "success": True,
            "servers": servers if servers else [],
            "count": len(servers) if servers else 0
        }
    except Exception as e:
        logger.error(f"Get servers error: {e}")
        return {"success": True, "servers": [], "count": 0}

# ========== RUN APP ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
