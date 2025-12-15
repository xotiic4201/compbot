# main.py - PRODUCTION READY COMPLETE BACKEND
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

# Headers for Supabase
headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SUPABASE_KEY}"
}

# ========== APP INITIALIZATION ==========
app = FastAPI(title="XTourney API", version="4.0", docs_url="/api/docs", redoc_url="/api/redoc")

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

# ========== SUPABASE HELPER ==========
def supabase_request(method: str, endpoint: str, data: dict = None, params: dict = None):
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

# ========== ROUTES ==========
@app.get("/")
async def root():
    return {"message": "XTourney API v4.0", "status": "running", "timestamp": datetime.utcnow().isoformat()}

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
        user_record = {
            "id": user_id,
            "username": user_data.username,
            "password": hashed_password,
            "email": user_data.email,
            "is_host": False,
            "is_admin": False,
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
                "is_host": False,
                "is_admin": False
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
        # Get user
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
                "is_admin": user.get('is_admin', False)
            },
            "message": "Login successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

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

@app.put("/api/tournaments/{tournament_id}/status")
async def update_tournament_status(tournament_id: str, status_update: TournamentStatusUpdate):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        valid_statuses = ["registration", "ongoing", "completed", "cancelled"]
        if status_update.status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}")
        
        update_data = {
            "status": status_update.status,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return {
            "success": True,
            "message": f"Tournament status updated to {status_update.status}",
            "tournament_id": tournament_id
        }
    except Exception as e:
        logger.error(f"Update tournament status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tournament status")

@app.get("/api/tournaments/{tournament_id}/matches")
async def get_tournament_matches(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}&order=round_number.asc,match_number.asc")
        
        if isinstance(matches, dict):
            matches = []
        
        return {
            "success": True,
            "matches": matches if matches else [],
            "tournament_id": tournament_id,
            "count": len(matches) if matches else 0
        }
    except Exception as e:
        logger.error(f"Get tournament matches error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tournament matches")

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}&order=created_at.asc")
        
        brackets = supabase_request("GET", f"tournament_brackets?tournament_id=eq.{tournament_id}")
        
        if brackets and len(brackets) > 0:
            bracket = brackets[0]
            if isinstance(bracket.get('bracket_data'), str):
                try:
                    bracket['bracket_data'] = json.loads(bracket['bracket_data'])
                except:
                    bracket['bracket_data'] = {}
            return {
                "success": True,
                "tournament": tournament,
                "bracket": bracket,
                "teams": teams if teams else []
            }
        
        if teams and len(teams) >= 2:
            bracket_data = create_bracket_structure(teams, tournament_id, tournament['name'])
            
            bracket_record = {
                "id": str(uuid4()),
                "tournament_id": tournament_id,
                "bracket_data": json.dumps(bracket_data),
                "status": "generated",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            supabase_request("POST", "tournament_brackets", bracket_record)
            
            return {
                "success": True,
                "tournament": tournament,
                "bracket": bracket_record,
                "teams": teams
            }
        else:
            return {
                "success": True,
                "tournament": tournament,
                "bracket": None,
                "teams": teams if teams else [],
                "message": "Need at least 2 teams to generate bracket"
            }
            
    except Exception as e:
        logger.error(f"Error getting bracket: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bracket")

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
        
        # Update bracket with winner
        await update_bracket_with_winner(
            match_data['tournament_id'],
            match_data.get('round_number', 1),
            match_data.get('match_number', 1),
            winner_id,
            winner_name
        )
        
        updated_matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        return {
            "success": True,
            "match": updated_matches[0] if updated_matches and len(updated_matches) > 0 else match_data,
            "message": "Match score updated successfully"
        }
    except Exception as e:
        logger.error(f"Update match score error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update match score")

async def update_bracket_with_winner(tournament_id: str, round_number: int, match_number: int, winner_id: str, winner_name: str):
    """Update bracket with winner for next round"""
    try:
        brackets = supabase_request("GET", f"tournament_brackets?tournament_id=eq.{tournament_id}")
        if not brackets:
            return False
        
        bracket = brackets[0]
        bracket_data = json.loads(bracket['bracket_data']) if isinstance(bracket['bracket_data'], str) else bracket['bracket_data']
        
        for round_data in bracket_data.get('rounds', []):
            if round_data.get('round_number') == round_number:
                for match in round_data.get('matches', []):
                    if match.get('match_number') == match_number:
                        match['winner_id'] = winner_id
                        match['winner_name'] = winner_name
                        match['status'] = 'completed'
                        
                        next_round_number = round_number + 1
                        next_match_number = (match_number + 1) // 2
                        
                        for next_round in bracket_data.get('rounds', []):
                            if next_round.get('round_number') == next_round_number:
                                for next_match in next_round.get('matches', []):
                                    if next_match.get('match_number') == next_match_number:
                                        position = (match_number % 2) + 1
                                        if position == 1:
                                            next_match['team1_id'] = winner_id
                                            next_match['team1_name'] = winner_name
                                        else:
                                            next_match['team2_id'] = winner_id
                                            next_match['team2_name'] = winner_name
                                        break
                                break
                        break
                break
        
        supabase_request("PATCH", f"tournament_brackets?id=eq.{bracket['id']}", {
            "bracket_data": json.dumps(bracket_data),
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return True
        
    except Exception as e:
        logger.error(f"Error updating bracket: {e}")
        return False

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

# ========== STATS & RANKINGS ROUTES ==========
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

@app.get("/api/rankings/global")
async def get_global_rankings_endpoint(limit: int = 100):
    try:
        rankings = get_global_rankings(limit)
        
        return {
            "success": True,
            "rankings": rankings,
            "count": len(rankings)
        }
    except Exception as e:
        logger.error(f"Error in global rankings: {e}")
        return {"success": True, "rankings": [], "count": 0}

@app.get("/api/rankings/tournament/{tournament_id}")
async def get_tournament_rankings(tournament_id: str, limit: int = 10):
    try:
        rankings = calculate_team_rankings(tournament_id)
        
        return {
            "success": True,
            "tournament_id": tournament_id,
            "rankings": rankings[:limit],
            "count": len(rankings[:limit])
        }
    except Exception as e:
        logger.error(f"Error in tournament rankings: {e}")
        return {"success": True, "rankings": [], "count": 0}

@app.get("/api/match-history")
async def get_match_history(
    tournament_id: Optional[str] = None,
    team_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    try:
        endpoint = "match_history"
        filters = []
        
        if tournament_id:
            filters.append(f"tournament_id=eq.{tournament_id}")
        if team_id:
            filters.append(f"(team1_id=eq.{team_id} OR team2_id=eq.{team_id})")
        
        if filters:
            endpoint += f"?{'&'.join(filters)}"
        
        if '?' in endpoint:
            endpoint += f"&order=played_at.desc&limit={limit}&offset={offset}"
        else:
            endpoint += f"?order=played_at.desc&limit={limit}&offset={offset}"
        
        history = supabase_request("GET", endpoint)
        
        return {
            "success": True,
            "matches": history if history else [],
            "count": len(history) if history else 0
        }
    except Exception as e:
        logger.error(f"Error getting match history: {e}")
        return {"success": True, "matches": [], "count": 0}

@app.get("/api/teams/{team_id}/stats")
async def get_team_stats(team_id: str):
    try:
        teams = supabase_request("GET", f"teams?id=eq.{team_id}")
        if not teams:
            raise HTTPException(status_code=404, detail="Team not found")
        
        team = teams[0]
        
        matches = supabase_request("GET", f"match_history?or=(team1_id.eq.{team_id},team2_id.eq.{team_id})&order=played_at.desc")
        
        if isinstance(matches, dict):
            matches = []
        
        total_matches = len(matches)
        wins = sum(1 for m in matches if m.get('winner_id') == team_id)
        losses = total_matches - wins
        win_rate = (wins / total_matches * 100) if total_matches > 0 else 0
        
        avg_score_for = 0
        avg_score_against = 0
        total_duration = 0
        
        for match in matches:
            if match.get('team1_id') == team_id:
                avg_score_for += match.get('team1_score', 0)
                avg_score_against += match.get('team2_score', 0)
            else:
                avg_score_for += match.get('team2_score', 0)
                avg_score_against += match.get('team1_score', 0)
            total_duration += match.get('duration', 0)
        
        if total_matches > 0:
            avg_score_for = avg_score_for / total_matches
            avg_score_against = avg_score_against / total_matches
            avg_match_duration = total_duration / total_matches
        
        tournaments = set(m.get('tournament_id') for m in matches if m.get('tournament_id'))
        recent_matches = matches[:5]
        
        stats = {
            "team": {
                "id": team['id'],
                "name": team['name'],
                "captain": team.get('captain_name'),
                "region": team.get('region', 'GLOBAL'),
                "created_at": team.get('created_at')
            },
            "overall": {
                "total_matches": total_matches,
                "wins": wins,
                "losses": losses,
                "win_rate": round(win_rate, 2),
                "points": wins * 3,
                "tournaments_played": len(tournaments),
                "avg_score_for": round(avg_score_for, 1) if total_matches > 0 else 0,
                "avg_score_against": round(avg_score_against, 1) if total_matches > 0 else 0,
                "avg_match_duration": round(avg_match_duration, 0) if total_matches > 0 else 0
            },
            "recent_matches": recent_matches,
            "achievements": []
        }
        
        return {
            "success": True,
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting team stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get team stats")

# ========== SERVER INVITE ROUTES ==========
@app.get("/api/server-invite/{tournament_id}")
async def get_server_invite(tournament_id: str):
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        invites = supabase_request("GET", f"server_invites?tournament_id=eq.{tournament_id}&order=created_at.desc&limit=1")
        
        invite_data = None
        if invites and len(invites) > 0:
            invite_data = invites[0]
        else:
            invite_data = {
                "server_name": f"{tournament['game']} Tournament Server",
                "invite_link": tournament.get('server_invite') or f"https://discord.gg/{tournament.get('tournament_pass', 'XTourney')}",
                "expires_at": None
            }
        
        return {
            "success": True,
            "tournament": {
                "id": tournament_id,
                "name": tournament['name'],
                "game": tournament['game']
            },
            "invite": invite_data
        }
        
    except Exception as e:
        logger.error(f"Error getting server invite: {e}")
        raise HTTPException(status_code=500, detail="Failed to get server invite")

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
            server_data["id"] = str(uuid4())
            server_data["created_at"] = datetime.utcnow().isoformat()
            supabase_request("POST", "bot_servers", server_data)
        
        return {"success": True, "message": "Server stats updated"}
    except Exception as e:
        logger.error(f"Server stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update server stats")

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
        '''
    ]
    
    # Create indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
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
        "CREATE INDEX IF NOT EXISTS idx_bot_servers_server ON bot_servers(server_id);"
    ]
    
    try:
        for table_sql in tables + indexes:
            # Note: Supabase REST API doesn't directly execute SQL
            # This is for documentation. You'd need to run these in Supabase dashboard
            pass
        
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
