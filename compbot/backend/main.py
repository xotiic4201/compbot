# backend/main.py - COMPLETE UPDATED VERSION
from fastapi import FastAPI, HTTPException, Request, Depends, status, Form, WebSocket, WebSocketDisconnect
import json
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
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

# ========== SETUP LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", "xtourney-secret-key-2024")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")

# Headers for Supabase
headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SUPABASE_KEY}"
}

# ========== APP INITIALIZATION ==========
app = FastAPI(title="XTourney API", version="2.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = defaultdict(list)
    
    async def connect(self, websocket: WebSocket, tournament_id: str):
        await websocket.accept()
        self.active_connections[tournament_id].append(websocket)
        logger.info(f"WebSocket connected for tournament {tournament_id}")
    
    def disconnect(self, websocket: WebSocket, tournament_id: str):
        if tournament_id in self.active_connections:
            self.active_connections[tournament_id].remove(websocket)
    
    async def broadcast(self, tournament_id: str, message: dict):
        if tournament_id in self.active_connections:
            for connection in self.active_connections[tournament_id]:
                try:
                    await connection.send_json(message)
                except:
                    pass

manager = ConnectionManager()

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
    discord_invite_code: Optional[str] = None  # NEW: Auto-created invite

class BracketUpdate(BaseModel):
    bracket_data: Dict[str, Any]
    status: Optional[str] = None

class MatchResult(BaseModel):
    match_id: str
    winner_id: Optional[str] = None
    team1_score: Optional[int] = 0
    team2_score: Optional[int] = 0
    round_number: int
    match_number: int

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
            raise HTTPException(status_code=500, detail=f"Database error: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Supabase request error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# ========== DISCORD INVITE HELPER ==========
async def create_discord_invite(server_id: str) -> Optional[str]:
    """Create Discord invite using Discord API"""
    if not DISCORD_BOT_TOKEN or not server_id:
        return None
    
    try:
        headers = {
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # Get guild channels
        channels_url = f"https://discord.com/api/v10/guilds/{server_id}/channels"
        channels_response = requests.get(channels_url, headers=headers, timeout=10)
        
        if channels_response.status_code != 200:
            logger.error(f"Failed to get channels: {channels_response.status_code}")
            return None
        
        channels = channels_response.json()
        
        # Find first text channel
        text_channels = [c for c in channels if c.get('type') == 0]  # Type 0 = text channel
        
        if not text_channels:
            logger.error("No text channels found")
            return None
        
        channel_id = text_channels[0]['id']
        
        # Create invite
        invite_data = {
            "max_age": 604800,  # 7 days
            "max_uses": 0,      # Unlimited
            "temporary": False,
            "unique": True
        }
        
        invite_url = f"https://discord.com/api/v10/channels/{channel_id}/invites"
        invite_response = requests.post(invite_url, headers=headers, json=invite_data, timeout=10)
        
        if invite_response.status_code == 200:
            invite = invite_response.json()
            invite_code = invite.get('code')
            return f"https://discord.gg/{invite_code}"
        else:
            logger.error(f"Failed to create invite: {invite_response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Discord invite error: {e}")
        return None

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

# ========== BRACKET HELPER FUNCTIONS ==========
def generate_bracket_structure(teams: List[Dict], tournament: Dict) -> Dict:
    """Generate complete bracket structure"""
    total_teams = len(teams)
    if total_teams < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 teams")
    
    # Calculate rounds (power of 2)
    next_power_of_two = 2 ** math.ceil(math.log2(total_teams))
    total_rounds = int(math.log2(next_power_of_two))
    
    # Shuffle teams for random seeding
    shuffled_teams = teams.copy()
    random.shuffle(shuffled_teams)
    
    # Add BYEs if needed
    while len(shuffled_teams) < next_power_of_two:
        shuffled_teams.append({
            "id": f"bye_{uuid4().hex[:8]}",
            "name": "BYE",
            "is_bye": True
        })
    
    bracket = {
        "tournament_id": tournament["id"],
        "tournament_name": tournament["name"],
        "total_rounds": total_rounds,
        "current_round": 1,
        "teams_count": total_teams,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "rounds": []
    }
    
    # Generate first round matches
    round1_matches = []
    match_number = 1
    
    for i in range(0, len(shuffled_teams), 2):
        team1 = shuffled_teams[i]
        team2 = shuffled_teams[i + 1] if i + 1 < len(shuffled_teams) else {"id": "bye", "name": "BYE", "is_bye": True}
        
        match_id = f"match_{tournament['id']}_r1_m{match_number}"
        
        match = {
            "match_id": match_id,
            "round_number": 1,
            "match_number": match_number,
            "team1_id": team1["id"],
            "team1_name": team1["name"],
            "team1_seed": i + 1,
            "team2_id": team2["id"],
            "team2_name": team2["name"],
            "team2_seed": i + 2,
            "winner_id": None,
            "team1_score": 0,
            "team2_score": 0,
            "status": "pending",
            "is_bye": team1.get("is_bye") or team2.get("is_bye"),
            "next_match": None,
            "next_team_slot": None
        }
        
        round1_matches.append(match)
        match_number += 1
    
    bracket["rounds"].append({
        "round_number": 1,
        "matches": round1_matches
    })
    
    # Generate empty future rounds with connections
    for round_num in range(2, total_rounds + 1):
        matches_in_round = next_power_of_two // (2 ** round_num)
        round_matches = []
        
        for match_num in range(1, matches_in_round + 1):
            match_id = f"match_{tournament['id']}_r{round_num}_m{match_num}"
            
            # Calculate which matches from previous round feed into this one
            prev_match1_num = (match_num * 2) - 1
            prev_match2_num = match_num * 2
            
            match = {
                "match_id": match_id,
                "round_number": round_num,
                "match_number": match_num,
                "team1_id": None,
                "team1_name": "TBD",
                "team1_seed": None,
                "team2_id": None,
                "team2_name": "TBD",
                "team2_seed": None,
                "winner_id": None,
                "team1_score": 0,
                "team2_score": 0,
                "status": "pending",
                "is_bye": False,
                "next_match": None,
                "next_team_slot": None,
                "source_matches": [
                    f"match_{tournament['id']}_r{round_num-1}_m{prev_match1_num}",
                    f"match_{tournament['id']}_r{round_num-1}_m{prev_match2_num}"
                ]
            }
            
            # Update previous matches to point to this one
            if round_num > 1:
                prev_round = bracket["rounds"][round_num - 2]
                if prev_match1_num <= len(prev_round["matches"]):
                    prev_round["matches"][prev_match1_num - 1]["next_match"] = match_id
                    prev_round["matches"][prev_match1_num - 1]["next_team_slot"] = "team1"
                if prev_match2_num <= len(prev_round["matches"]):
                    prev_round["matches"][prev_match2_num - 1]["next_match"] = match_id
                    prev_round["matches"][prev_match2_num - 1]["next_team_slot"] = "team2"
            
            round_matches.append(match)
        
        bracket["rounds"].append({
            "round_number": round_num,
            "matches": round_matches
        })
    
    return bracket

def update_bracket_with_result(bracket: Dict, match_result: MatchResult) -> Dict:
    """Update bracket with match result and propagate winners"""
    for round_data in bracket["rounds"]:
        if round_data["round_number"] == match_result.round_number:
            for match in round_data["matches"]:
                if match["match_number"] == match_result.match_number:
                    # Update match result
                    match["winner_id"] = match_result.winner_id
                    match["team1_score"] = match_result.team1_score
                    match["team2_score"] = match_result.team2_score
                    match["status"] = "completed"
                    
                    # Propagate winner to next round if applicable
                    if match["next_match"] and match["winner_id"]:
                        winner_team_id = match["winner_id"]
                        winner_team_name = match["team1_name"] if winner_team_id == match["team1_id"] else match["team2_name"]
                        
                        # Find next match and update team slot
                        for next_round in bracket["rounds"]:
                            if next_round["round_number"] == match["round_number"] + 1:
                                for next_match in next_round["matches"]:
                                    if next_match["match_id"] == match["next_match"]:
                                        if match["next_team_slot"] == "team1":
                                            next_match["team1_id"] = winner_team_id
                                            next_match["team1_name"] = winner_team_name
                                        else:
                                            next_match["team2_id"] = winner_team_id
                                            next_match["team2_name"] = winner_team_name
                                        
                                        # If both teams are set, mark as ready
                                        if next_match["team1_id"] and next_match["team2_id"]:
                                            next_match["status"] = "ready"
                                        break
                                break
                    
                    break
    
    bracket["updated_at"] = datetime.utcnow().isoformat()
    return bracket

# ========== ROUTES ==========
@app.get("/")
async def root():
    return {"message": "XTourney API v2.0", "status": "running"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# User routes (same as before)
@app.post("/api/register")
async def register(user: UserRegister):
    """Register new user"""
    try:
        existing = supabase_request("GET", f"users?username=eq.{user.username}")
        if existing and len(existing) > 0:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        if user.email:
            existing_email = supabase_request("GET", f"users?email=eq.{user.email}")
            if existing_email and len(existing_email) > 0:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
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
        
        result = supabase_request("POST", "users", user_data)
        
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
        
    except Exception as e:
        logger.error(f"Register error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login")
async def login(user: UserLogin):
    """Login user"""
    try:
        users = supabase_request("GET", f"users?username=eq.{user.username}")
        if not users or len(users) == 0:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        db_user = users[0]
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        if password_hash != db_user.get("password_hash"):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        update_data = {
            "last_login": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"users?id=eq.{db_user['id']}", update_data)
        
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
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

# Tournament routes with auto-invite creation
@app.get("/api/tournaments")
async def get_tournaments():
    """Get all tournaments"""
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        
        if tournaments:
            for tournament in tournaments:
                teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament['id']}")
                tournament["team_count"] = len(teams) if teams else 0
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

@app.post("/api/tournaments/discord")
async def create_tournament_discord(request: Request):
    """Create tournament from Discord bot WITH AUTO-INVITE"""
    try:
        data = await request.json()
        
        required = ["name", "game", "max_teams", "max_players_per_team", "tournament_pass", "host_id", "created_by"]
        for field in required:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing field: {field}")
        
        # AUTO-CREATE DISCORD INVITE
        discord_invite_url = None
        if data.get("discord_server_id"):
            discord_invite_url = await create_discord_invite(data["discord_server_id"])
            logger.info(f"Created Discord invite: {discord_invite_url}")
        
        total_rounds = calculate_total_rounds(data["max_teams"])
        
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
            "host_id": data["host_id"],
            "created_by": data["created_by"],
            "discord_server_id": data.get("discord_server_id"),
            "discord_invite_url": discord_invite_url,  # Store the auto-created invite
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
            "discord_invite_url": discord_invite_url,
            "message": "Tournament created with auto-invite" if discord_invite_url else "Tournament created"
        }
        
    except Exception as e:
        logger.error(f"Discord tournament creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.get("/api/tournament/{tournament_id}/discord-invite")
async def get_tournament_discord_invite(tournament_id: str):
    """Get Discord invite for tournament"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Return stored invite or try to create new one
        if tournament.get("discord_invite_url"):
            return {
                "success": True,
                "invite_url": tournament["discord_invite_url"],
                "invite_code": tournament["discord_invite_url"].replace("https://discord.gg/", "")
            }
        
        # Try to create new invite if server ID exists
        if tournament.get("discord_server_id"):
            discord_invite_url = await create_discord_invite(tournament["discord_server_id"])
            if discord_invite_url:
                # Update tournament with new invite
                update_data = {
                    "discord_invite_url": discord_invite_url,
                    "updated_at": datetime.utcnow().isoformat()
                }
                supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
                
                return {
                    "success": True,
                    "invite_url": discord_invite_url,
                    "invite_code": discord_invite_url.replace("https://discord.gg/", "")
                }
        
        return {
            "success": False,
            "message": "No Discord invite available"
        }
        
    except Exception as e:
        logger.error(f"Get Discord invite error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Discord invite")

# BRACKET MANAGEMENT ENDPOINTS
@app.post("/api/tournament-pass/{tournament_id}/generate-bracket")
async def generate_tournament_bracket(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Generate bracket for tournament"""
    try:
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
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        
        if not teams or len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams")
        
        # Generate bracket structure
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
        for round_data in bracket["rounds"]:
            for match in round_data["matches"]:
                match_record = {
                    "id": match["match_id"],
                    "tournament_id": tournament_id,
                    "round_number": match["round_number"],
                    "match_number": match["match_number"],
                    "team1_id": match["team1_id"],
                    "team2_id": match["team2_id"],
                    "team1_name": match["team1_name"],
                    "team2_name": match["team2_name"],
                    "status": match["status"],
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                existing = supabase_request("GET", f"matches?id=eq.{match['match_id']}")
                if not existing or len(existing) == 0:
                    supabase_request("POST", "matches", match_record)
        
        # Update tournament status
        update_data = {
            "status": "ongoing",
            "current_round": 1,
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        # Broadcast to WebSocket clients
        await manager.broadcast(tournament_id, {
            "type": "bracket_generated",
            "tournament_id": tournament_id,
            "bracket": bracket
        })
        
        return {
            "success": True,
            "message": "Bracket generated successfully",
            "bracket": bracket
        }
        
    except Exception as e:
        logger.error(f"Generate bracket error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate bracket")

@app.post("/api/tournament-pass/{tournament_id}/update-match")
async def update_match_result(
    tournament_id: str, 
    match_result: MatchResult,
    current_user: Dict = Depends(get_current_user)
):
    """Update match result and propagate through bracket"""
    try:
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
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get bracket
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        if not brackets or len(brackets) == 0:
            raise HTTPException(status_code=404, detail="Bracket not found")
        
        bracket = json.loads(brackets[0]["bracket_data"])
        
        # Update bracket with result
        updated_bracket = update_bracket_with_result(bracket, match_result)
        
        # Update bracket in database
        bracket_update = {
            "bracket_data": json.dumps(updated_bracket),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"brackets?tournament_id=eq.{tournament_id}", bracket_update)
        
        # Update match record
        match_update = {
            "winner_id": match_result.winner_id,
            "team1_score": match_result.team1_score,
            "team2_score": match_result.team2_score,
            "status": "completed",
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"matches?id=eq.{match_result.match_id}", match_update)
        
        # Update tournament current round if needed
        all_matches_completed = True
        for round_data in updated_bracket["rounds"]:
            if round_data["round_number"] == updated_bracket["current_round"]:
                for match in round_data["matches"]:
                    if match["status"] != "completed" and not match.get("is_bye"):
                        all_matches_completed = False
                        break
                break
        
        if all_matches_completed and updated_bracket["current_round"] < updated_bracket["total_rounds"]:
            # Advance to next round
            tournament_update = {
                "current_round": updated_bracket["current_round"] + 1,
                "updated_at": datetime.utcnow().isoformat()
            }
            supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", tournament_update)
            updated_bracket["current_round"] += 1
        
        # Broadcast update
        await manager.broadcast(tournament_id, {
            "type": "match_updated",
            "tournament_id": tournament_id,
            "match_result": match_result.dict(),
            "bracket": updated_bracket
        })
        
        return {
            "success": True,
            "message": "Match result updated",
            "bracket": updated_bracket
        }
        
    except Exception as e:
        logger.error(f"Update match error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update match")

@app.get("/api/tournament-pass/{tournament_id}/manage")
async def get_tournament_manage(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Get tournament management data"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if user can manage
        can_manage = False
        if tournament.get('host_id') == current_user['id']:
            can_manage = True
        elif current_user.get('discord_id') and tournament.get('host_id') == current_user['discord_id']:
            can_manage = True
        
        if not can_manage:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get bracket
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        bracket = brackets[0] if brackets and len(brackets) > 0 else None
        
        if bracket and bracket.get("bracket_data"):
            bracket["bracket_data"] = json.loads(bracket["bracket_data"])
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        
        # Get matches
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}&order=round_number.asc,match_number.asc")
        
        return {
            "success": True,
            "tournament": tournament,
            "bracket": bracket,
            "teams": teams if teams else [],
            "matches": matches if matches else [],
            "can_manage": True
        }
        
    except Exception as e:
        logger.error(f"Get tournament manage error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tournament data")

@app.post("/api/tournament-pass/{tournament_id}/advance-round")
async def advance_tournament_round(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Manually advance tournament to next round"""
    try:
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
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get bracket
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        if not brackets or len(brackets) == 0:
            raise HTTPException(status_code=404, detail="Bracket not found")
        
        bracket = json.loads(brackets[0]["bracket_data"])
        
        # Check if we can advance
        if bracket["current_round"] >= bracket["total_rounds"]:
            raise HTTPException(status_code=400, detail="Tournament is already at final round")
        
        # Advance round
        new_round = bracket["current_round"] + 1
        bracket["current_round"] = new_round
        
        # Update bracket
        bracket_update = {
            "bracket_data": json.dumps(bracket),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"brackets?tournament_id=eq.{tournament_id}", bracket_update)
        
        # Update tournament
        tournament_update = {
            "current_round": new_round,
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", tournament_update)
        
        # Broadcast
        await manager.broadcast(tournament_id, {
            "type": "round_advanced",
            "tournament_id": tournament_id,
            "new_round": new_round,
            "bracket": bracket
        })
        
        return {
            "success": True,
            "message": f"Advanced to round {new_round}",
            "current_round": new_round
        }
        
    except Exception as e:
        logger.error(f"Advance round error: {e}")
        raise HTTPException(status_code=500, detail="Failed to advance round")

# WEBSOCKET FOR REAL-TIME UPDATES
@app.websocket("/ws/tournament/{tournament_id}")
async def websocket_endpoint(websocket: WebSocket, tournament_id: str):
    await manager.connect(websocket, tournament_id)
    try:
        while True:
            data = await websocket.receive_json()
            # Handle client messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket, tournament_id)

# Tournament pass auth (same as before)
@app.post("/api/tournament-pass/auth")
async def auth_tournament_pass(pass_code: str = Form(...), current_user: Dict = Depends(get_current_user)):
    try:
        tournaments = supabase_request("GET", f"tournaments?tournament_pass=eq.{pass_code}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Invalid tournament pass")
        
        tournament = tournaments[0]
        
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
        raise HTTPException(status_code=500, detail="Failed to authenticate")

# Stats endpoint (same as before)
@app.get("/api/stats")
async def get_stats():
    try:
        tournaments = supabase_request("GET", "tournaments?status=in.(registration,ongoing)")
        teams = supabase_request("GET", "teams")
        servers = supabase_request("GET", "bot_servers")
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

# Server stats endpoint (same as before)
@app.post("/api/bot/server-stats")
async def update_server_stats(request: Request):
    try:
        data = await request.json()
        
        server_id = data.get("server_id")
        server_name = data.get("server_name")
        member_count = data.get("member_count", 0)
        icon_url = data.get("icon_url")
        
        if not server_id:
            raise HTTPException(status_code=400, detail="Server ID required")
        
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
            supabase_request("PATCH", f"bot_servers?server_id=eq.{server_id}", server_data)
        else:
            server_data["created_at"] = datetime.utcnow().isoformat()
            supabase_request("POST", "bot_servers", server_data)
        
        return {"success": True, "message": "Server stats updated"}
        
    except Exception as e:
        logger.error(f"Server stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update server stats")

# ========== UTILITY FUNCTIONS ==========
def calculate_total_rounds(max_teams: int) -> int:
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

# ========== RUN APP ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
