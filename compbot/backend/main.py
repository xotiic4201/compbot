# main.py - PRODUCTION READY COMPLETE BACKEND WITH OWNER ADMIN
from fastapi import FastAPI, HTTPException, Request, Depends, status, Form, WebSocket, WebSocketDisconnect
import json
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
import os
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, EmailStr, Field
import jwt
from uuid import uuid4
import logging
import math
import random
import asyncio
from collections import defaultdict
import aiohttp
import ipaddress
from functools import lru_cache

# ========== SETUP LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", "xtourney-secret-key-2024")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us")
BACKEND_URL = os.getenv("BACKEND_URL", "https://compbot-lhuy.onrender.com")

# Owner credentials
OWNER_USERNAME = "xotiic"
OWNER_PASSWORD = "Mwf4618##"

# Headers for Supabase
headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SUPABASE_KEY}"
}

# ========== APP INITIALIZATION ==========
app = FastAPI(title="XTourney API", version="5.0", docs_url="/api/docs", redoc_url="/api/redoc")

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
    email: Optional[str] = None

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

class TeamRegister(BaseModel):
    team_name: str
    tournament_id: str
    captain_id: str
    captain_name: str
    members: List[str]
    region: str = "GLOBAL"
    tag: Optional[str] = None
    player_ids: Optional[List[str]] = None

class UpdateMatchScore(BaseModel):
    team1_score: int
    team2_score: int
    duration: Optional[int] = None

class TournamentStatusUpdate(BaseModel):
    status: str

class TournamentRanking(BaseModel):
    tournament_id: str
    team_id: str
    team_name: str
    wins: int = 0
    losses: int = 0
    points: int = 0
    rank: int = 0
    matches_played: int = 0

class MatchHistory(BaseModel):
    match_id: str
    tournament_id: str
    tournament_name: str
    round_number: int
    match_number: int
    team1_id: str
    team1_name: str
    team1_score: int
    team2_id: str
    team2_name: str
    team2_score: int
    winner_id: str
    winner_name: str
    status: str
    played_at: str
    duration: Optional[int] = None

class ServerInviteCreate(BaseModel):
    tournament_id: str
    server_id: str
    server_name: str
    invite_link: str
    expires_at: Optional[str] = None

class AdminAction(BaseModel):
    action: str
    target_id: str
    data: Optional[Dict] = None
    reason: Optional[str] = None

class IPBanCreate(BaseModel):
    ip_address: str
    reason: str
    duration_days: Optional[int] = None

# ========== SUPABASE HELPER ==========
def supabase_request(method: str, endpoint: str, data: dict = None, params: dict = None):
    # Guard against missing Supabase configuration
    if not SUPABASE_URL or not SUPABASE_URL.startswith("http"):
        logger.error("Supabase URL not configured (SUPABASE_URL). Skipping request.")
        if method == "GET":
            return []
        return {"success": False, "detail": "Supabase URL not configured"}

    url = f"{SUPABASE_URL}/rest/v1/{endpoint}"
    
    if params:
        query_params = "&".join([f"{k}={v}" for k, v in params.items()])
        url = f"{url}?{query_params}"
    
    try:
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
            return {"success": False, "detail": f"Invalid method: {method}"}
        
        if response.status_code in [200, 201, 204]:
            try:
                return response.json()
            except:
                return {"success": True}
        elif response.status_code == 404:
            return []
        else:
            error_text = response.text[:500]
            logger.error(f"Supabase error {response.status_code}: {error_text}")
            return {"success": False, "detail": f"Database error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Supabase request error: {str(e)}")
        return {"success": False, "detail": f"Database connection failed: {str(e)}"}

# ========== AUTH HELPERS ==========
def create_token(user_data: dict) -> str:
    payload = {
        "sub": user_data.get("id"),
        "username": user_data.get("username"),
        "is_host": user_data.get("is_host", False),
        "is_admin": user_data.get("is_admin", False),
        "is_owner": user_data.get("is_owner", False),
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

async def get_current_admin(user: dict = Depends(get_current_user)):
    if not user.get('is_admin') and not user.get('is_owner'):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def get_current_owner(user: dict = Depends(get_current_user)):
    if not user.get('is_owner'):
        raise HTTPException(status_code=403, detail="Owner access required")
    return user

# ========== IP BANNING SYSTEM ==========
class IPBanManager:
    def __init__(self):
        self.banned_ips = set()
        self.load_banned_ips()
    
    def load_banned_ips(self):
        try:
            bans = supabase_request("GET", "ip_bans")
            if isinstance(bans, list):
                for ban in bans:
                    if ban.get('expires_at'):
                        expires = datetime.fromisoformat(ban['expires_at'].replace('Z', '+00:00'))
                        if expires > datetime.utcnow():
                            self.banned_ips.add(ban['ip_address'])
                        else:
                            # Auto-remove expired bans
                            supabase_request("DELETE", f"ip_bans?id=eq.{ban['id']}")
                    else:
                        self.banned_ips.add(ban['ip_address'])
            logger.info(f"Loaded {len(self.banned_ips)} banned IPs")
        except Exception as e:
            logger.error(f"Error loading banned IPs: {e}")
    
    def is_banned(self, ip_address: str) -> bool:
        return ip_address in self.banned_ips
    
    def add_ban(self, ip_address: str, reason: str, duration_days: Optional[int] = None):
        try:
            expires_at = None
            if duration_days:
                expires_at = (datetime.utcnow() + timedelta(days=duration_days)).isoformat()
            
            ban_data = {
                "id": str(uuid4()),
                "ip_address": ip_address,
                "reason": reason,
                "expires_at": expires_at,
                "created_at": datetime.utcnow().isoformat()
            }
            
            result = supabase_request("POST", "ip_bans", ban_data)
            if isinstance(result, dict) and result.get('success') != False:
                self.banned_ips.add(ip_address)
                logger.info(f"IP {ip_address} banned: {reason}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding IP ban: {e}")
            return False
    
    def remove_ban(self, ip_address: str):
        try:
            result = supabase_request("DELETE", f"ip_bans?ip_address=eq.{ip_address}")
            if isinstance(result, dict) and result.get('success') != False:
                self.banned_ips.discard(ip_address)
                logger.info(f"IP {ip_address} unbanned")
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing IP ban: {e}")
            return False

ip_ban_manager = IPBanManager()

# ========== REQUEST MIDDLEWARE FOR IP BAN CHECK ==========
@app.middleware("http")
async def check_ip_ban(request: Request, call_next):
    client_ip = request.client.host
    
    # Check if IP is banned
    if ip_ban_manager.is_banned(client_ip):
        return JSONResponse(
            status_code=403,
            content={"detail": "Your IP address has been banned from this service"}
        )
    
    response = await call_next(request)
    return response

# ========== HELPER FUNCTIONS ==========
def create_bracket_structure(teams, tournament_id, tournament_name):
    """Create a proper bracket structure with teams"""
    bracket = {
        "tournament_id": tournament_id,
        "tournament_name": tournament_name,
        "rounds": [],
        "status": "generated",
        "generated_at": datetime.utcnow().isoformat()
    }
    
    # Sort teams and create seeds
    seeded_teams = list(enumerate(teams, 1))
    
    # Calculate number of rounds
    num_teams = len(teams)
    if num_teams < 2:
        return bracket
    
    # Calculate rounds needed
    num_rounds = math.ceil(math.log2(num_teams))
    bracket_size = 2 ** num_rounds
    
    # Fill bracket with byes if needed
    bracket_teams = []
    for seed, team in seeded_teams:
        bracket_teams.append({
            "seed": seed,
            "team_id": team.get("id"),
            "team_name": team.get("name", f"Team {seed}"),
            "captain": team.get("captain_name", "Unknown"),
            "status": "active"
        })
    
    # Add byes if needed
    while len(bracket_teams) < bracket_size:
        bracket_teams.append({
            "seed": len(bracket_teams) + 1,
            "team_id": None,
            "team_name": "BYE",
            "captain": None,
            "status": "bye"
        })
    
    # Create first round matches
    first_round_matches = []
    for i in range(0, len(bracket_teams), 2):
        match_num = i // 2 + 1
        team1 = bracket_teams[i]
        team2 = bracket_teams[i + 1] if i + 1 < len(bracket_teams) else None
        
        match_data = {
            "match_id": f"{tournament_id}-r1-m{match_num}",
            "match_number": match_num,
            "round_number": 1,
            "team1_id": team1.get("team_id"),
            "team1_name": team1["team_name"],
            "team1_seed": team1["seed"],
            "team2_id": team2.get("team_id") if team2 else None,
            "team2_name": team2["team_name"] if team2 else "BYE",
            "team2_seed": team2["seed"] if team2 else None,
            "winner_id": None,
            "status": "scheduled" if team2 else "bye",
            "score1": 0,
            "score2": 0
        }
        first_round_matches.append(match_data)
    
    bracket["rounds"].append({
        "round_number": 1,
        "round_name": "Round of 16" if bracket_size == 16 else f"Round 1 ({len(first_round_matches)} matches)",
        "matches": first_round_matches
    })
    
    # Create subsequent rounds
    for round_num in range(2, num_rounds + 1):
        prev_round_matches = bracket["rounds"][-1]["matches"]
        current_round_matches = []
        match_count = len(prev_round_matches) // 2
        
        for i in range(match_count):
            match_num = i + 1
            match_data = {
                "match_id": f"{tournament_id}-r{round_num}-m{match_num}",
                "match_number": match_num,
                "round_number": round_num,
                "team1_id": None,
                "team1_name": "TBD",
                "team2_id": None,
                "team2_name": "TBD",
                "winner_id": None,
                "status": "pending",
                "score1": 0,
                "score2": 0
            }
            current_round_matches.append(match_data)
        
        round_name = "Quarterfinals" if round_num == num_rounds - 2 else \
                    "Semifinals" if round_num == num_rounds - 1 else \
                    "Finals" if round_num == num_rounds else f"Round {round_num}"
        
        bracket["rounds"].append({
            "round_number": round_num,
            "round_name": round_name,
            "matches": current_round_matches
        })
    
    return bracket

def calculate_team_rankings(tournament_id: str):
    """Calculate rankings for all teams in a tournament"""
    try:
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        if not teams:
            return []
        
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}&status=eq.completed")
        
        team_stats = {}
        for team in teams:
            team_stats[team['id']] = {
                'team_id': team['id'],
                'team_name': team['name'],
                'wins': 0,
                'losses': 0,
                'points': 0,
                'matches_played': 0
            }
        
        for match in matches:
            team1_id = match.get('team1_id')
            team2_id = match.get('team2_id')
            winner_id = match.get('winner_id')
            
            if team1_id and team2_id and winner_id:
                if team1_id in team_stats:
                    team_stats[team1_id]['matches_played'] += 1
                if team2_id in team_stats:
                    team_stats[team2_id]['matches_played'] += 1
                
                if winner_id == team1_id:
                    team_stats[team1_id]['wins'] += 1
                    team_stats[team1_id]['points'] += 3
                    if team2_id in team_stats:
                        team_stats[team2_id]['losses'] += 1
                elif winner_id == team2_id:
                    team_stats[team2_id]['wins'] += 1
                    team_stats[team2_id]['points'] += 3
                    if team1_id in team_stats:
                        team_stats[team1_id]['losses'] += 1
        
        rankings = list(team_stats.values())
        rankings.sort(key=lambda x: (-x['points'], -x['wins'], x['losses']))
        
        for i, rank in enumerate(rankings):
            rank['rank'] = i + 1
        
        return rankings
        
    except Exception as e:
        logger.error(f"Error calculating rankings: {e}")
        return []

def save_match_history(match_data: dict):
    """Save match to history"""
    try:
        history_data = {
            "id": str(uuid4()),
            "match_id": match_data.get('id'),
            "tournament_id": match_data.get('tournament_id'),
            "tournament_name": match_data.get('tournament_name', ''),
            "round_number": match_data.get('round_number', 1),
            "match_number": match_data.get('match_number', 1),
            "team1_id": match_data.get('team1_id'),
            "team1_name": match_data.get('team1_name', ''),
            "team1_score": match_data.get('team1_score', 0),
            "team2_id": match_data.get('team2_id'),
            "team2_name": match_data.get('team2_name', ''),
            "team2_score": match_data.get('team2_score', 0),
            "winner_id": match_data.get('winner_id'),
            "winner_name": match_data.get('winner_name', ''),
            "status": match_data.get('status', 'completed'),
            "played_at": match_data.get('played_at', datetime.utcnow().isoformat()),
            "duration": match_data.get('duration'),
            "created_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("POST", "match_history", history_data)
        return True
    except Exception as e:
        logger.error(f"Error saving match history: {e}")
        return False

def get_global_rankings(limit: int = 100):
    """Get global rankings across all tournaments"""
    try:
        matches = supabase_request("GET", "match_history?status=eq.completed")
        if not matches:
            return []
        
        team_stats = {}
        
        for match in matches:
            team1_id = match.get('team1_id')
            team2_id = match.get('team2_id')
            winner_id = match.get('winner_id')
            
            if not all([team1_id, team2_id, winner_id]):
                continue
            
            if team1_id not in team_stats:
                team_stats[team1_id] = {
                    'team_id': team1_id,
                    'team_name': match.get('team1_name', 'Unknown'),
                    'wins': 0,
                    'losses': 0,
                    'points': 0,
                    'matches_played': 0,
                    'tournaments_played': set()
                }
            
            if team2_id not in team_stats:
                team_stats[team2_id] = {
                    'team_id': team2_id,
                    'team_name': match.get('team2_name', 'Unknown'),
                    'wins': 0,
                    'losses': 0,
                    'points': 0,
                    'matches_played': 0,
                    'tournaments_played': set()
                }
            
            tournament_id = match.get('tournament_id')
            if tournament_id:
                team_stats[team1_id]['tournaments_played'].add(tournament_id)
                team_stats[team2_id]['tournaments_played'].add(tournament_id)
            
            team_stats[team1_id]['matches_played'] += 1
            team_stats[team2_id]['matches_played'] += 1
            
            if winner_id == team1_id:
                team_stats[team1_id]['wins'] += 1
                team_stats[team1_id]['points'] += 3
                team_stats[team2_id]['losses'] += 1
            else:
                team_stats[team2_id]['wins'] += 1
                team_stats[team2_id]['points'] += 3
                team_stats[team1_id]['losses'] += 1
        
        rankings = []
        for team_id, stats in team_stats.items():
            stats['tournaments_played'] = len(stats['tournaments_played'])
            rankings.append(stats)
        
        rankings.sort(key=lambda x: (-x['points'], -x['wins'], -x['tournaments_played'], x['losses']))
        
        for i, rank in enumerate(rankings):
            rank['rank'] = i + 1
        
        return rankings[:limit]
        
    except Exception as e:
        logger.error(f"Error getting global rankings: {e}")
        return []

async def get_total_users():
    """Get total number of users in the system"""
    try:
        users = supabase_request("GET", "users")
        if isinstance(users, list):
            return len(users)
        return 0
    except Exception as e:
        logger.error(f"Error getting total users: {e}")
        return 0

# ========== ROUTES ==========
@app.get("/")
async def root():
    return {"message": "XTourney API v5.0", "status": "running", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/health")
async def health_check():
    try:
        users = supabase_request("GET", "users?limit=1")
        tournaments = supabase_request("GET", "tournaments?limit=1")
        
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "users": len(users) if users else 0,
            "tournaments": len(tournaments) if tournaments else 0
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# ========== AUTH ROUTES ==========
@app.post("/api/register")
async def register(user_data: UserRegister):
    try:
        # Check if user exists
        existing = supabase_request("GET", f"users?username=eq.{user_data.username}")
        if existing and len(existing) > 0:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        if user_data.email:
            existing_email = supabase_request("GET", f"users?email=eq.{user_data.email}")
            if existing_email and len(existing_email) > 0:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password
        hashed_password = hashlib.sha256(user_data.password.encode()).hexdigest()
        
        user_id = str(uuid4())
        
        # Check if this is the owner account
        is_owner = (user_data.username == OWNER_USERNAME and user_data.password == OWNER_PASSWORD)
        
        user_record = {
            "id": user_id,
            "username": user_data.username,
            "password": hashed_password,
            "email": user_data.email,
            "is_host": is_owner,
            "is_admin": is_owner,
            "is_owner": is_owner,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_request("POST", "users", user_record)
        
        token = create_token(user_record)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data.username,
                "email": user_data.email,
                "is_host": is_owner,
                "is_admin": is_owner,
                "is_owner": is_owner
            },
            "message": "Registration successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login")
async def login(login_data: UserLogin):
    try:
        # Special owner login
        if login_data.username == OWNER_USERNAME and login_data.password == OWNER_PASSWORD:
            # Check if owner exists in database
            existing_owner = supabase_request("GET", f"users?username=eq.{OWNER_USERNAME}")
            
            if not existing_owner or len(existing_owner) == 0:
                # Create owner account if it doesn't exist
                owner_id = str(uuid4())
                hashed_password = hashlib.sha256(OWNER_PASSWORD.encode()).hexdigest()
                
                owner_record = {
                    "id": owner_id,
                    "username": OWNER_USERNAME,
                    "password": hashed_password,
                    "email": "owner@xtourney.com",
                    "is_host": True,
                    "is_admin": True,
                    "is_owner": True,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                supabase_request("POST", "users", owner_record)
                
                token = create_token(owner_record)
                
                return {
                    "success": True,
                    "token": token,
                    "user": {
                        "id": owner_id,
                        "username": OWNER_USERNAME,
                        "email": "owner@xtourney.com",
                        "is_host": True,
                        "is_admin": True,
                        "is_owner": True
                    },
                    "message": "Owner login successful"
                }
            else:
                # Owner exists, generate token
                owner = existing_owner[0]
                token = create_token(owner)
                
                return {
                    "success": True,
                    "token": token,
                    "user": {
                        "id": owner['id'],
                        "username": owner['username'],
                        "email": owner.get('email'),
                        "is_host": True,
                        "is_admin": True,
                        "is_owner": True
                    },
                    "message": "Owner login successful"
                }
        
        # Normal user login
        users = supabase_request("GET", f"users?username=eq.{login_data.username}")
        if not users or len(users) == 0:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = users[0]
        hashed_password = hashlib.sha256(login_data.password.encode()).hexdigest()
        
        if user['password'] != hashed_password:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_token(user)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user.get('email'),
                "is_host": user.get('is_host', False),
                "is_admin": user.get('is_admin', False),
                "is_owner": user.get('is_owner', False)
            },
            "message": "Login successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

# ========== OWNER/ADMIN ROUTES ==========
@app.get("/api/admin/stats")
async def admin_stats(user: dict = Depends(get_current_admin)):
    try:
        total_users = await get_total_users()
        tournaments = supabase_request("GET", "tournaments")
        total_tournaments = len(tournaments) if isinstance(tournaments, list) else 0
        
        teams = supabase_request("GET", "teams")
        total_teams = len(teams) if isinstance(teams, list) else 0
        
        matches = supabase_request("GET", "matches")
        total_matches = len(matches) if isinstance(matches, list) else 0
        
        servers = supabase_request("GET", "bot_servers")
        total_servers = len(servers) if isinstance(servers, list) else 0
        
        ip_bans = supabase_request("GET", "ip_bans")
        total_bans = len(ip_bans) if isinstance(ip_bans, list) else 0
        
        recent_users = supabase_request("GET", "users?order=created_at.desc&limit=10")
        recent_tournaments = supabase_request("GET", "tournaments?order=created_at.desc&limit=10")
        
        return {
            "success": True,
            "stats": {
                "total_users": total_users,
                "total_tournaments": total_tournaments,
                "total_teams": total_teams,
                "total_matches": total_matches,
                "total_servers": total_servers,
                "total_ip_bans": total_bans
            },
            "recent_users": recent_users if isinstance(recent_users, list) else [],
            "recent_tournaments": recent_tournaments if isinstance(recent_tournaments, list) else []
        }
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get admin stats")

@app.get("/api/admin/users")
async def admin_get_users(user: dict = Depends(get_current_admin)):
    try:
        users = supabase_request("GET", "users?order=created_at.desc")
        if isinstance(users, list):
            # Remove passwords for security
            for u in users:
                u.pop('password', None)
            return {"success": True, "users": users}
        return {"success": True, "users": []}
    except Exception as e:
        logger.error(f"Admin get users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get users")

@app.post("/api/admin/users/{user_id}/promote")
async def admin_promote_user(user_id: str, promote_data: dict, user: dict = Depends(get_current_admin)):
    try:
        update_data = {}
        if promote_data.get('make_admin'):
            update_data['is_admin'] = True
        if promote_data.get('make_host'):
            update_data['is_host'] = True
        if promote_data.get('remove_admin'):
            update_data['is_admin'] = False
        if promote_data.get('remove_host'):
            update_data['is_host'] = False
        
        update_data['updated_at'] = datetime.utcnow().isoformat()
        
        result = supabase_request("PATCH", f"users?id=eq.{user_id}", update_data)
        
        if isinstance(result, dict) and result.get('success') != False:
            return {"success": True, "message": "User updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update user")
            
    except Exception as e:
        logger.error(f"Admin promote user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to promote user")

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, user: dict = Depends(get_current_admin)):
    try:
        if user_id == user['id']:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        
        result = supabase_request("DELETE", f"users?id=eq.{user_id}")
        
        if isinstance(result, dict) and result.get('success') != False:
            return {"success": True, "message": "User deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete user")
            
    except Exception as e:
        logger.error(f"Admin delete user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user")

@app.get("/api/admin/tournaments")
async def admin_get_tournaments(user: dict = Depends(get_current_admin)):
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        if isinstance(tournaments, list):
            return {"success": True, "tournaments": tournaments}
        return {"success": True, "tournaments": []}
    except Exception as e:
        logger.error(f"Admin get tournaments error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tournaments")

@app.put("/api/admin/tournaments/{tournament_id}")
async def admin_update_tournament(tournament_id: str, update_data: dict, user: dict = Depends(get_current_admin)):
    try:
        update_data['updated_at'] = datetime.utcnow().isoformat()
        
        result = supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        if isinstance(result, dict) and result.get('success') != False:
            return {"success": True, "message": "Tournament updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update tournament")
            
    except Exception as e:
        logger.error(f"Admin update tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tournament")

@app.delete("/api/admin/tournaments/{tournament_id}")
async def admin_delete_tournament(tournament_id: str, user: dict = Depends(get_current_admin)):
    try:
        # Also delete associated teams and matches
        supabase_request("DELETE", f"teams?tournament_id=eq.{tournament_id}")
        supabase_request("DELETE", f"matches?tournament_id=eq.{tournament_id}")
        supabase_request("DELETE", f"tournament_brackets?tournament_id=eq.{tournament_id}")
        supabase_request("DELETE", f"server_invites?tournament_id=eq.{tournament_id}")
        
        result = supabase_request("DELETE", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(result, dict) and result.get('success') != False:
            return {"success": True, "message": "Tournament deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete tournament")
            
    except Exception as e:
        logger.error(f"Admin delete tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete tournament")

@app.get("/api/admin/ip-bans")
async def admin_get_ip_bans(user: dict = Depends(get_current_admin)):
    try:
        bans = supabase_request("GET", "ip_bans?order=created_at.desc")
        if isinstance(bans, list):
            return {"success": True, "bans": bans}
        return {"success": True, "bans": []}
    except Exception as e:
        logger.error(f"Admin get IP bans error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get IP bans")

@app.post("/api/admin/ip-bans")
async def admin_add_ip_ban(ban_data: IPBanCreate, request: Request, user: dict = Depends(get_current_admin)):
    try:
        success = ip_ban_manager.add_ban(ban_data.ip_address, ban_data.reason, ban_data.duration_days)
        
        if success:
            return {"success": True, "message": "IP banned successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to ban IP")
            
    except Exception as e:
        logger.error(f"Admin add IP ban error: {e}")
        raise HTTPException(status_code=500, detail="Failed to add IP ban")

@app.delete("/api/admin/ip-bans/{ip_address}")
async def admin_remove_ip_ban(ip_address: str, user: dict = Depends(get_current_admin)):
    try:
        success = ip_ban_manager.remove_ban(ip_address)
        
        if success:
            return {"success": True, "message": "IP unbanned successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to unban IP")
            
    except Exception as e:
        logger.error(f"Admin remove IP ban error: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove IP ban")

@app.get("/api/admin/logs")
async def admin_get_logs(user: dict = Depends(get_current_owner)):
    try:
        # Get recent actions from audit log
        logs = supabase_request("GET", "audit_logs?order=created_at.desc&limit=100")
        
        if isinstance(logs, list):
            return {"success": True, "logs": logs}
        
        return {"success": True, "logs": []}
        
    except Exception as e:
        logger.error(f"Admin get logs error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get logs")

@app.get("/api/admin/bot-servers")
async def admin_get_bot_servers(user: dict = Depends(get_current_admin)):
    try:
        servers = supabase_request("GET", "bot_servers?order=last_updated.desc")
        if isinstance(servers, list):
            return {"success": True, "servers": servers}
        return {"success": True, "servers": []}
    except Exception as e:
        logger.error(f"Admin get bot servers error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bot servers")

# ========== TOURNAMENT ROUTES ==========
@app.get("/api/tournaments")
async def get_tournaments():
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        
        if isinstance(tournaments, dict) and "success" in tournaments and not tournaments["success"]:
            return {"success": True, "tournaments": [], "count": 0}
        
        if tournaments:
            for tournament in tournaments:
                teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament['id']}")
                tournament["team_count"] = len(teams) if teams else 0
                tournament["current_teams"] = tournament.get("team_count", 0)
                tournament["max_players"] = tournament.get("max_players_per_team", 5)
        
        return {
            "success": True,
            "tournaments": tournaments if tournaments else [],
            "count": len(tournaments) if tournaments else 0
        }
    except Exception as e:
        logger.error(f"Get tournaments error: {e}")
        return {"success": True, "tournaments": [], "count": 0}

@app.get("/api/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        tournament["teams"] = teams if teams else []
        tournament["team_count"] = len(teams) if teams else 0
        
        return {
            "success": True,
            "tournament": tournament
        }
    except Exception as e:
        logger.error(f"Get tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tournament")

@app.post("/api/tournaments/discord")
async def create_tournament_discord(request: Request):
    try:
        data = await request.json()
        
        required = ["name", "game", "max_teams", "max_players_per_team", "tournament_pass", "host_id", "created_by"]
        for field in required:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing field: {field}")
        
        tournament_id = str(uuid4())
        
        # Create server invite record if provided
        server_invite = data.get('server_invite')
        if server_invite:
            invite_data = {
                "id": str(uuid4()),
                "tournament_id": tournament_id,
                "server_id": data.get('discord_server_id'),
                "server_name": data.get('server_name', f"{data['game']} Tournament"),
                "invite_link": server_invite,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            supabase_request("POST", "server_invites", invite_data)
        
        tournament_data = {
            "id": tournament_id,
            "name": data["name"],
            "game": data["game"],
            "description": data.get("description", ""),
            "status": "registration",
            "max_teams": data["max_teams"],
            "max_players_per_team": data["max_players_per_team"],
            "prize_pool": data.get("prize_pool", ""),
            "tournament_pass": data["tournament_pass"],
            "host_id": data["host_id"],
            "created_by": data["created_by"],
            "discord_server_id": data.get("discord_server_id"),
            "server_invite": server_invite,
            "current_round": 1,
            "total_rounds": 1,
            "team_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_request("POST", "tournaments", tournament_data)
        
        return {
            "success": True,
            "tournament_id": tournament_id,
            "tournament": tournament_data,
            "tournament_pass": data["tournament_pass"],
            "server_invite": server_invite,
            "message": "Tournament created successfully"
        }
    except Exception as e:
        logger.error(f"Discord tournament creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.post("/api/tournaments/{tournament_id}/start")
async def start_tournament(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        update_data = {
            "status": "ongoing",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return {
            "success": True,
            "message": "Tournament started successfully",
            "tournament_id": tournament_id
        }
    except Exception as e:
        logger.error(f"Start tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to start tournament")

@app.post("/api/tournaments/{tournament_id}/generate-bracket")
async def generate_bracket_simple(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        if not teams or len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams to generate bracket")
        
        # Create bracket structure
        bracket_data = create_bracket_structure(teams, tournament_id, tournament['name'])
        
        # Save bracket
        bracket_record = {
            "id": str(uuid4()),
            "tournament_id": tournament_id,
            "bracket_data": json.dumps(bracket_data),
            "status": "generated",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Check if bracket exists
        existing = supabase_request("GET", f"tournament_brackets?tournament_id=eq.{tournament_id}")
        if existing and len(existing) > 0:
            supabase_request("PATCH", f"tournament_brackets?id=eq.{existing[0]['id']}", {
                "bracket_data": json.dumps(bracket_data),
                "updated_at": datetime.utcnow().isoformat()
            })
        else:
            supabase_request("POST", "tournament_brackets", bracket_record)
        
        # Create matches
        for round_data in bracket_data.get('rounds', []):
            for match_data in round_data.get('matches', []):
                match_record = {
                    "id": str(uuid4()),
                    "tournament_id": tournament_id,
                    "match_number": match_data.get('match_number', 1),
                    "round_number": match_data.get('round_number', 1),
                    "team1_id": match_data.get('team1_id'),
                    "team1_name": match_data.get('team1_name', 'TBD'),
                    "team2_id": match_data.get('team2_id'),
                    "team2_name": match_data.get('team2_name', 'TBD'),
                    "team1_score": match_data.get('score1', 0),
                    "team2_score": match_data.get('score2', 0),
                    "winner_id": match_data.get('winner_id'),
                    "status": match_data.get('status', 'scheduled'),
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                supabase_request("POST", "matches", match_record)
        
        # Update tournament
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", {
            "status": "ongoing",
            "current_round": 1,
            "total_rounds": len(bracket_data.get('rounds', [])),
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "message": "Bracket generated successfully",
            "tournament_id": tournament_id,
            "team_count": len(teams),
            "rounds": len(bracket_data.get('rounds', []))
        }
    except Exception as e:
        logger.error(f"Generate bracket error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate bracket")

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}&order=created_at.asc")
        
        brackets = supabase_request("GET", f"tournament_brackets?tournament_id=eq.{tournament_id}")
        
        bracket = None
        if brackets and len(brackets) > 0:
            bracket = brackets[0]
            if isinstance(bracket.get('bracket_data'), str):
                try:
                    bracket['bracket_data'] = json.loads(bracket['bracket_data'])
                except:
                    bracket['bracket_data'] = {}
        
        # Get matches
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}&order=round_number.asc,match_number.asc")
        
        return {
            "success": True,
            "tournament": tournament,
            "bracket": bracket,
            "teams": teams if teams else [],
            "matches": matches if isinstance(matches, list) else []
        }
            
    except Exception as e:
        logger.error(f"Error getting bracket: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bracket")

# ========== STATS & RANKINGS ROUTES ==========
@app.get("/api/stats")
async def get_stats():
    try:
        tournaments = supabase_request("GET", "tournaments?status=in.(registration,ongoing)")
        active_tournaments = len(tournaments) if tournaments else 0
        
        teams = supabase_request("GET", "teams")
        total_teams = len(teams) if teams else 0
        
        servers = supabase_request("GET", "bot_servers")
        connected_servers = len(servers) if servers else 0
        
        matches = supabase_request("GET", "matches?status=eq.ongoing")
        live_matches = len(matches) if matches else 0
        
        total_users = await get_total_users()
        
        return {
            "success": True,
            "stats": {
                "active_tournaments": active_tournaments,
                "total_teams": total_teams,
                "connected_servers": connected_servers,
                "live_matches": live_matches,
                "total_users": total_users
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
                "live_matches": 0,
                "total_users": 0
            }
        }

# ========== TEAM ROUTES ==========
@app.post("/api/teams/register")
async def register_team(team_data: TeamRegister):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{team_data.tournament_id}")
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        if tournament["status"] != "registration":
            raise HTTPException(status_code=400, detail="Tournament is not accepting registrations")
        
        teams = supabase_request("GET", f"teams?tournament_id=eq.{team_data.tournament_id}")
        current_teams = len(teams) if teams else 0
        
        if current_teams >= tournament["max_teams"]:
            raise HTTPException(status_code=400, detail="Tournament is full")
        
        existing_teams = supabase_request("GET", f"teams?tournament_id=eq.{team_data.tournament_id}&name=eq.{team_data.team_name}")
        if existing_teams and len(existing_teams) > 0:
            raise HTTPException(status_code=400, detail="Team name already taken in this tournament")
        
        team_id = str(uuid4())
        team_name = team_data.team_name
        if team_data.tag:
            team_name = f"[{team_data.tag}] {team_data.team_name}"
        
        team_record = {
            "id": team_id,
            "tournament_id": team_data.tournament_id,
            "name": team_name,
            "captain_discord_id": team_data.captain_id,
            "captain_name": team_data.captain_name,
            "region": team_data.region,
            "members": json.dumps(team_data.members),
            "status": "registered",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_request("POST", "teams", team_record)
        
        supabase_request("PATCH", f"tournaments?id=eq.{team_data.tournament_id}", {
            "team_count": current_teams + 1,
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "team": {
                "id": team_id,
                "name": team_name,
                "captain_name": team_data.captain_name,
                "region": team_data.region,
                "members": team_data.members
            },
            "message": "Team registered successfully"
        }
    except Exception as e:
        logger.error(f"Team registration error: {e}")
        raise HTTPException(status_code=500, detail="Failed to register team")

# ========== MATCH ROUTES ==========
@app.get("/api/matches/{match_id}")
async def get_match(match_id: str):
    try:
        matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        if not matches or len(matches) == 0:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match_data = matches[0]
        
        return {
            "success": True,
            "match": match_data
        }
    except Exception as e:
        logger.error(f"Get match error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get match")

@app.post("/api/matches/{match_id}/update-score")
async def update_match_score(match_id: str, score_data: UpdateMatchScore):
    try:
        matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        if not matches or len(matches) == 0:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match_data = matches[0]
        
        if score_data.team1_score > score_data.team2_score:
            winner_id = match_data.get("team1_id")
            winner_name = match_data.get("team1_name")
        elif score_data.team2_score > score_data.team1_score:
            winner_id = match_data.get("team2_id")
            winner_name = match_data.get("team2_name")
        else:
            winner_id = None
            winner_name = None
        
        update_data = {
            "team1_score": score_data.team1_score,
            "team2_score": score_data.team2_score,
            "winner_id": winner_id,
            "status": "completed",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"matches?id=eq.{match_id}", update_data)
        
        # Save to history
        tournament = supabase_request("GET", f"tournaments?id=eq.{match_data['tournament_id']}")
        tournament_name = tournament[0]['name'] if tournament else "Unknown Tournament"
        
        history_data = {
            "id": match_id,
            "tournament_id": match_data.get('tournament_id'),
            "tournament_name": tournament_name,
            "round_number": match_data.get('round_number', 1),
            "match_number": match_data.get('match_number', 1),
            "team1_id": match_data.get('team1_id'),
            "team1_name": match_data.get('team1_name', ''),
            "team1_score": score_data.team1_score,
            "team2_id": match_data.get('team2_id'),
            "team2_name": match_data.get('team2_name', ''),
            "team2_score": score_data.team2_score,
            "winner_id": winner_id,
            "winner_name": winner_name,
            "status": "completed",
            "played_at": datetime.utcnow().isoformat(),
            "duration": score_data.duration
        }
        
        save_match_history(history_data)
        
        updated_matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        return {
            "success": True,
            "match": updated_matches[0] if updated_matches and len(updated_matches) > 0 else match_data,
            "message": "Match score updated successfully"
        }
    except Exception as e:
        logger.error(f"Update match score error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update match score")

# ========== TOURNAMENT PASS ROUTES ==========
@app.post("/api/tournament-pass/auth")
async def auth_tournament_pass(pass_code: str = Form(...)):
    try:
        tournaments = supabase_request("GET", f"tournaments?tournament_pass=eq.{pass_code}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Invalid tournament pass")
        
        tournament = tournaments[0]
        
        return {
            "success": True,
            "tournament": tournament,
            "message": "Tournament access granted"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tournament pass auth error: {e}")
        raise HTTPException(status_code=500, detail="Failed to authenticate tournament pass")

# ========== DATABASE SETUP ==========
@app.post("/api/setup-database")
async def setup_database():
    """Initialize database tables (run once)"""
    tables = [
        # Users table
        '''
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password TEXT NOT NULL,
            is_host BOOLEAN DEFAULT false,
            is_admin BOOLEAN DEFAULT false,
            is_owner BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Tournaments table
        '''
        CREATE TABLE IF NOT EXISTS tournaments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            game TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'registration',
            max_teams INTEGER DEFAULT 16,
            max_players_per_team INTEGER DEFAULT 5,
            prize_pool TEXT,
            tournament_pass TEXT UNIQUE,
            host_id TEXT,
            created_by TEXT,
            discord_server_id TEXT,
            server_invite TEXT,
            current_round INTEGER DEFAULT 1,
            total_rounds INTEGER DEFAULT 1,
            team_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Teams table
        '''
        CREATE TABLE IF NOT EXISTS teams (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tournament_id TEXT NOT NULL,
            name TEXT NOT NULL,
            captain_discord_id TEXT,
            captain_name TEXT,
            region TEXT DEFAULT 'GLOBAL',
            members JSONB,
            status TEXT DEFAULT 'registered',
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Matches table
        '''
        CREATE TABLE IF NOT EXISTS matches (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tournament_id TEXT NOT NULL,
            match_number INTEGER,
            round_number INTEGER DEFAULT 1,
            team1_id TEXT,
            team1_name TEXT,
            team2_id TEXT,
            team2_name TEXT,
            team1_score INTEGER DEFAULT 0,
            team2_score INTEGER DEFAULT 0,
            winner_id TEXT,
            status TEXT DEFAULT 'scheduled',
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Match history table
        '''
        CREATE TABLE IF NOT EXISTS match_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            match_id TEXT,
            tournament_id TEXT,
            tournament_name TEXT,
            round_number INTEGER,
            match_number INTEGER,
            team1_id TEXT,
            team1_name TEXT,
            team1_score INTEGER,
            team2_id TEXT,
            team2_name TEXT,
            team2_score INTEGER,
            winner_id TEXT,
            winner_name TEXT,
            status TEXT,
            played_at TIMESTAMP,
            duration INTEGER,
            created_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Tournament brackets table
        '''
        CREATE TABLE IF NOT EXISTS tournament_brackets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tournament_id TEXT UNIQUE,
            bracket_data JSONB,
            status TEXT,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Server invites table
        '''
        CREATE TABLE IF NOT EXISTS server_invites (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tournament_id TEXT,
            server_id TEXT,
            server_name TEXT,
            invite_link TEXT,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Bot servers table
        '''
        CREATE TABLE IF NOT EXISTS bot_servers (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            server_id TEXT UNIQUE,
            server_name TEXT,
            member_count INTEGER,
            icon_url TEXT,
            last_updated TIMESTAMP,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # IP Bans table
        '''
        CREATE TABLE IF NOT EXISTS ip_bans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT now()
        );
        ''',
        
        # Audit logs table
        '''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id TEXT,
            username TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details JSONB,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT now()
        );
        '''
    ]
    
    # Create indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
        "CREATE INDEX IF NOT EXISTS idx_users_admin ON users(is_admin, is_owner);",
        "CREATE INDEX IF NOT EXISTS idx_tournaments_pass ON tournaments(tournament_pass);",
        "CREATE INDEX IF NOT EXISTS idx_tournaments_status ON tournaments(status);",
        "CREATE INDEX IF NOT EXISTS idx_teams_tournament ON teams(tournament_id);",
        "CREATE INDEX IF NOT EXISTS idx_matches_tournament ON matches(tournament_id);",
        "CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);",
        "CREATE INDEX IF NOT EXISTS idx_match_history_tournament ON match_history(tournament_id);",
        "CREATE INDEX IF NOT EXISTS idx_match_history_team ON match_history(team1_id, team2_id);",
        "CREATE INDEX IF NOT EXISTS idx_match_history_played ON match_history(played_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_tournament_brackets_tournament ON tournament_brackets(tournament_id);",
        "CREATE INDEX IF NOT EXISTS idx_server_invites_tournament ON server_invites(tournament_id);",
        "CREATE INDEX IF NOT EXISTS idx_bot_servers_server ON bot_servers(server_id);",
        "CREATE INDEX IF NOT EXISTS idx_ip_bans_address ON ip_bans(ip_address);",
        "CREATE INDEX IF NOT EXISTS idx_ip_bans_expires ON ip_bans(expires_at);",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);"
    ]
    
    try:
        return {
            "success": True,
            "message": "Database setup SQL generated. Run in Supabase dashboard.",
            "tables": len(tables),
            "indexes": len(indexes)
        }
    except Exception as e:
        logger.error(f"Database setup error: {e}")
        raise HTTPException(status_code=500, detail="Database setup failed")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
