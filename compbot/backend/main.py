# backend/main.py - COMPLETE FIXED VERSION
from fastapi import FastAPI, HTTPException, Request, Depends, status, Form
import json
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
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
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

class DiscordTournamentCreate(BaseModel):
    name: str
    game: str
    max_teams: int = 16
    max_players_per_team: int = 5
    prize_pool: Optional[str] = None
    description: Optional[str] = None
    tournament_pass: str
    host_id: str
    created_by: str
    discord_server_id: Optional[str] = None

# ========== SUPABASE HELPERS ==========
def supabase_request(method: str, endpoint: str, data: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{endpoint}"
    
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
            raise ValueError(f"Invalid method: {method}")
        
        logger.debug(f"Supabase {method} to {endpoint}: {response.status_code}")
        
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
            
            # Check for schema errors
            if "has no field" in error_text:
                logger.error(f"SCHEMA MISMATCH: {error_text}")
                
            raise HTTPException(status_code=500, detail=f"Database error: {response.status_code}")
            
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Supabase request error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# ========== AUTH HELPERS ==========
def create_token(user_data: dict) -> str:
    payload = {
        "sub": user_data.get("id"),
        "username": user_data.get("username"),
        "is_host": user_data.get("is_host", False),
        "is_admin": user_data.get("is_admin", False),
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

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        users = supabase_request("GET", "users?limit=1")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.post("/api/register")
async def register(user: UserRegister):
    """Register new user - FIXED FOR YOUR SQL SCHEMA"""
    try:
        # Check if username exists
        existing = supabase_request("GET", f"users?username=eq.{user.username}")
        if existing and len(existing) > 0:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check if email exists (if provided)
        if user.email:
            existing_email = supabase_request("GET", f"users?email=eq.{user.email}")
            if existing_email and len(existing_email) > 0:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password - using SHA256 to match SQL schema
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        # Create user - MATCHING YOUR SQL SCHEMA
        user_id = str(uuid4())
        user_data = {
            "id": user_id,
            "username": user.username,
            "email": user.email if user.email else None,
            "password_hash": password_hash,
            "account_type": "email",
            "is_verified": False,
            "is_host": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Creating user: {user.username}")
        result = supabase_request("POST", "users", user_data)
        
        # Create token without sensitive data
        token_data = {
            "id": user_id,
            "username": user.username,
            "email": user.email if user.email else None,
            "is_host": False,
            "is_admin": False
        }
        
        token = create_token(token_data)
        
        return {
            "success": True,
            "token": token,
            "user": token_data
        }
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Register error: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        raise HTTPException(status_code=500, detail="Registration failed. Please try again.")

@app.post("/api/login")
async def login(user: UserLogin):
    """Login user - FIXED FOR YOUR SQL SCHEMA"""
    try:
        # Find user by username
        users = supabase_request("GET", f"users?username=eq.{user.username}")
        if not users or len(users) == 0:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        db_user = users[0]
        
        # Verify password
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        if password_hash != db_user.get("password_hash"):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login - using correct field names
        update_data = {
            "last_login": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"users?id=eq.{db_user['id']}", update_data)
        
        # Create token without sensitive data
        token_data = {
            "id": db_user["id"],
            "username": db_user["username"],
            "email": db_user.get("email"),
            "is_host": db_user.get("is_host", False),
            "is_admin": db_user.get("is_admin", False)
        }
        
        token = create_token(token_data)
        
        return {
            "success": True,
            "token": token,
            "user": token_data
        }
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed. Please check credentials.")

@app.get("/api/tournaments")
async def get_tournaments():
    """Get all tournaments"""
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        
        if tournaments:
            for tournament in tournaments:
                # Get team counts for each tournament
                teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament['id']}")
                tournament["team_count"] = len(teams) if teams else 0
                
                # Make sure fields exist for frontend
                tournament["current_teams"] = tournament.get("team_count", 0)
                tournament["currentTeams"] = tournament.get("team_count", 0)
        
        return {
            "success": True,
            "tournaments": tournaments if tournaments else [],
            "count": len(tournaments) if tournaments else 0
        }
        
    except Exception as e:
        logger.error(f"Get tournaments error: {e}")
        return {"success": True, "tournaments": [], "count": 0}

@app.post("/api/tournaments")
async def create_tournament(tournament: TournamentCreate, current_user: Dict = Depends(get_current_user)):
    """Create tournament from website"""
    try:
        if not current_user.get("is_host") and not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Only hosts can create tournaments")
        
        # Generate tournament pass
        tournament_pass = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        
        # Calculate total rounds
        total_rounds = calculate_total_rounds(tournament.max_teams)
        
        # Create tournament - MATCHING YOUR SQL SCHEMA
        tournament_id = str(uuid4())
        tournament_data = {
            "id": tournament_id,
            "name": tournament.name,
            "game": tournament.game,
            "description": tournament.description if tournament.description else "",
            "status": "registration",
            "max_teams": tournament.max_teams,
            "max_players_per_team": tournament.max_players,
            "prize_pool": tournament.prize_pool if tournament.prize_pool else "",
            "tournament_pass": tournament_pass,
            "host_id": current_user["id"],  # This should be text, not UUID
            "created_by": current_user["username"],  # Using username as text
            "created_by_uuid": current_user["id"],  # Also store UUID reference
            "current_round": 1,
            "total_rounds": total_rounds,
            "team_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_request("POST", "tournaments", tournament_data)
        
        return {
            "success": True,
            "tournament": tournament_data,
            "tournament_pass": tournament_pass
        }
        
    except Exception as e:
        logger.error(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.post("/api/tournaments/discord")
async def create_tournament_discord(request: Request):
    """Create tournament from Discord bot (no auth required)"""
    try:
        data = await request.json()
        
        # Validate required fields
        required = ["name", "game", "max_teams", "max_players_per_team", "tournament_pass", "host_id", "created_by"]
        for field in required:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing field: {field}")
        
        # Calculate total rounds
        total_rounds = calculate_total_rounds(data["max_teams"])
        
        # Create tournament - MATCHING YOUR SQL SCHEMA
        tournament_id = str(uuid4())
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
            "host_id": data["host_id"],  # Discord user ID as text
            "created_by": data["created_by"],  # Discord username as text
            "discord_server_id": data.get("discord_server_id"),
            "current_round": 1,
            "total_rounds": total_rounds,
            "team_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_request("POST", "tournaments", tournament_data)
        
        return {
            "success": True,
            "tournament_id": tournament_id,
            "tournament_pass": data["tournament_pass"],
            "message": "Tournament created successfully"
        }
        
    except Exception as e:
        logger.error(f"Discord tournament creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.post("/api/tournament-pass/auth")
async def auth_tournament_pass(pass_code: str = Form(...), current_user: Dict = Depends(get_current_user)):
    """Authenticate with tournament pass"""
    try:
        # Find tournament with this pass
        tournaments = supabase_request("GET", f"tournaments?tournament_pass=eq.{pass_code}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Invalid tournament pass")
        
        tournament = tournaments[0]
        
        # Check if user is already host (by ID or Discord ID)
        is_owner = False
        if tournament.get('host_id') == current_user['id']:
            is_owner = True
        elif current_user.get('discord_id') and tournament.get('host_id') == current_user['discord_id']:
            is_owner = True
        
        return {
            "success": True,
            "message": "Tournament pass accepted",
            "tournament": tournament,
            "is_owner": is_owner
        }
        
    except Exception as e:
        logger.error(f"Tournament pass auth error: {e}")
        raise HTTPException(status_code=500, detail="Failed to authenticate tournament pass")

@app.get("/api/tournament-pass/{tournament_id}/manage")
async def get_tournament_manage(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Get tournament management data"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if user can manage this tournament
        can_manage = False
        if tournament.get('host_id') == current_user['id']:
            can_manage = True
        elif current_user.get('discord_id') and tournament.get('host_id') == current_user['discord_id']:
            can_manage = True
        
        if not can_manage:
            raise HTTPException(status_code=403, detail="Not authorized to manage this tournament")
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        
        # Get matches
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}")
        
        # Get bracket if exists
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        bracket = brackets[0] if brackets and len(brackets) > 0 else None
        
        return {
            "success": True,
            "tournament": tournament,
            "teams": teams if teams else [],
            "matches": matches if matches else [],
            "bracket": bracket
        }
        
    except Exception as e:
        logger.error(f"Get tournament manage error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tournament data")

@app.post("/api/tournament-pass/{tournament_id}/update-bracket")
async def update_tournament_bracket(tournament_id: str, request: Request, current_user: Dict = Depends(get_current_user)):
    """Update tournament bracket"""
    try:
        data = await request.json()
        
        # Verify user can manage this tournament
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check permissions
        can_manage = False
        if tournament.get('host_id') == current_user['id']:
            can_manage = True
        elif current_user.get('discord_id') and tournament.get('host_id') == current_user['discord_id']:
            can_manage = True
        
        if not can_manage:
            raise HTTPException(status_code=403, detail="Not authorized to manage this tournament")
        
        # Update bracket data
        bracket_data = {
            "tournament_id": tournament_id,
            "bracket_data": json.dumps(data.get('bracket', {})),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Check if bracket exists
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        
        if brackets and len(brackets) > 0:
            supabase_request("PATCH", f"brackets?tournament_id=eq.{tournament_id}", bracket_data)
        else:
            bracket_data["created_at"] = datetime.utcnow().isoformat()
            supabase_request("POST", "brackets", bracket_data)
        
        # Update tournament status if needed
        if data.get('status'):
            update_data = {
                "status": data['status'],
                "updated_at": datetime.utcnow().isoformat()
            }
            supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return {
            "success": True,
            "message": "Bracket updated successfully"
        }
        
    except Exception as e:
        logger.error(f"Update bracket error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update bracket")

@app.post("/api/tournament-pass/{tournament_id}/generate-bracket")
async def generate_tournament_bracket(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Generate bracket for tournament"""
    try:
        # Verify user can manage this tournament
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check permissions
        can_manage = False
        if tournament.get('host_id') == current_user['id']:
            can_manage = True
        elif current_user.get('discord_id') and tournament.get('host_id') == current_user['discord_id']:
            can_manage = True
        
        if not can_manage:
            raise HTTPException(status_code=403, detail="Not authorized to manage this tournament")
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        
        if not teams or len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams to generate bracket")
        
        # Generate bracket
        bracket = generate_bracket_structure(teams, tournament)
        
        # Save bracket
        bracket_data = {
            "tournament_id": tournament_id,
            "bracket_data": json.dumps(bracket),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        
        if brackets and len(brackets) > 0:
            supabase_request("PATCH", f"brackets?tournament_id=eq.{tournament_id}", bracket_data)
        else:
            supabase_request("POST", "brackets", bracket_data)
        
        # Create matches in database
        await create_matches_from_bracket(tournament_id, bracket)
        
        # Update tournament status
        update_data = {
            "status": "ongoing",
            "current_round": 1,
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return {
            "success": True,
            "message": "Bracket generated successfully",
            "bracket": bracket
        }
        
    except Exception as e:
        logger.error(f"Generate bracket error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate bracket")

def generate_bracket_structure(teams, tournament):
    """Generate bracket structure"""
    total_rounds = tournament.get('total_rounds', 1)
    bracket = {
        "tournament_id": tournament['id'],
        "tournament_name": tournament['name'],
        "total_rounds": total_rounds,
        "current_round": 1,
        "rounds": []
    }
    
    # Shuffle teams for random seeding
    shuffled_teams = list(teams)
    random.shuffle(shuffled_teams)
    
    # Create first round matches
    round_matches = []
    match_num = 1
    
    for i in range(0, len(shuffled_teams), 2):
        team1 = shuffled_teams[i] if i < len(shuffled_teams) else None
        team2 = shuffled_teams[i+1] if i+1 < len(shuffled_teams) else None
        
        match = {
            "match_id": f"match_{tournament['id']}_r1_m{match_num}",
            "match_number": match_num,
            "team1_id": team1['id'] if team1 else None,
            "team1_name": team1['name'] if team1 else "BYE",
            "team2_id": team2['id'] if team2 else None,
            "team2_name": team2['name'] if team2 else "BYE",
            "winner_id": None,
            "status": "scheduled"
        }
        
        round_matches.append(match)
        match_num += 1
    
    bracket["rounds"].append({
        "round_number": 1,
        "matches": round_matches
    })
    
    # Create empty rounds for future
    for round_num in range(2, total_rounds + 1):
        matches_in_round = max(1, len(shuffled_teams) // (2 ** round_num))
        round_matches = []
        
        for match_num in range(1, matches_in_round + 1):
            match = {
                "match_id": f"match_{tournament['id']}_r{round_num}_m{match_num}",
                "match_number": match_num,
                "team1_id": None,
                "team1_name": "TBD",
                "team2_id": None,
                "team2_name": "TBD",
                "winner_id": None,
                "status": "pending"
            }
            
            round_matches.append(match)
        
        bracket["rounds"].append({
            "round_number": round_num,
            "matches": round_matches
        })
    
    return bracket

async def create_matches_from_bracket(tournament_id, bracket):
    """Create match records from bracket"""
    for round_data in bracket.get('rounds', []):
        round_number = round_data['round_number']
        
        for match in round_data.get('matches', []):
            match_data = {
                "id": match['match_id'],
                "tournament_id": tournament_id,
                "round_number": round_number,
                "match_number": match['match_number'],
                "team1_id": match.get('team1_id'),
                "team2_id": match.get('team2_id'),
                "team1_name": match['team1_name'],
                "team2_name": match['team2_name'],
                "status": match['status'],
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            # Check if match exists
            existing = supabase_request("GET", f"matches?id=eq.{match['match_id']}")
            
            if not existing or len(existing) == 0:
                supabase_request("POST", "matches", match_data)

@app.get("/api/stats")
async def get_stats():
    """Get platform statistics"""
    try:
        # Get counts from Supabase
        tournaments = supabase_request("GET", "tournaments?status=in.(registration,ongoing)")
        teams = supabase_request("GET", "teams")
        servers = supabase_request("GET", "bot_servers")
        
        # Count live matches
        matches = supabase_request("GET", "matches?status=eq.ongoing")
        
        return {
            "success": True,
            "stats": {
                "active_tournaments": len(tournaments) if tournaments else 0,
                "total_teams": len(teams) if teams else 0,
                "connected_servers": len(servers) if servers else 0,
                "live_matches": len(matches) if matches else 0
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
            "last_updated": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
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

# ========== UTILITY FUNCTIONS ==========
def calculate_total_rounds(max_teams: int) -> int:
    """Calculate total rounds based on max teams"""
    if max_teams <= 2:
        return 1
    elif max_teams <= 4:
        return 2
    elif max_teams <= 8:
        return 3
    elif max_teams <= 16:
        return 4
    elif max_teams <= 32:
        return 5
    else:
        return 6

# ========== DEBUG ENDPOINTS ==========
@app.get("/api/debug/users")
async def debug_users():
    """Debug endpoint to check users table"""
    try:
        users = supabase_request("GET", "users")
        return {
            "success": True,
            "count": len(users) if users else 0,
            "users": users if users else []
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "users": []
        }

@app.get("/api/debug/tables")
async def debug_tables():
    """Debug endpoint to check table structure"""
    try:
        tables = ["users", "tournaments", "teams", "matches", "bot_servers", "brackets"]
        results = {}
        
        for table in tables:
            try:
                data = supabase_request("GET", f"{table}?limit=1")
                results[table] = {
                    "exists": True,
                    "sample": data[0] if data and len(data) > 0 else "No data"
                }
            except Exception as e:
                results[table] = {
                    "exists": False,
                    "error": str(e)
                }
        
        return {
            "success": True,
            "tables": results
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ========== RUN APP ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

