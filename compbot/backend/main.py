# backend/main.py
from fastapi import FastAPI, HTTPException, Request, Depends, status, Form
import json  # Add this import
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

# Add these new routes to your existing backend

@app.post("/api/tournament-pass/auth")
async def auth_tournament_pass(pass_code: str = Form(...), current_user: Dict = Depends(get_current_user)):
    """Authenticate with tournament pass"""
    try:
        # Find tournament with this pass
        tournaments = supabase_request("GET", f"tournaments?tournament_pass=eq.{pass_code}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Invalid tournament pass")
        
        tournament = tournaments[0]
        
        # Check if user is already host
        if tournament.get('host_id') == current_user['id']:
            return {
                "success": True,
                "message": "You are already the host of this tournament",
                "tournament": tournament,
                "is_owner": True
            }
        
        # Check if user has permission to manage this tournament
        # For now, allow anyone with the pass
        return {
            "success": True,
            "message": "Tournament pass accepted",
            "tournament": tournament,
            "is_owner": False
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
        
        # Check if user is host
        if tournament.get('host_id') != current_user['id']:
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
        
        if tournament.get('host_id') != current_user['id']:
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
            supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", {
                "status": data['status'],
                "updated_at": datetime.utcnow().isoformat()
            })
        
        return {
            "success": True,
            "message": "Bracket updated successfully"
        }
        
    except Exception as e:
        logger.error(f"Update bracket error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update bracket")

@app.post("/api/tournament-pass/{tournament_id}/update-match")
async def update_tournament_match(tournament_id: str, request: Request, current_user: Dict = Depends(get_current_user)):
    """Update match result"""
    try:
        data = await request.json()
        match_id = data.get('match_id')
        
        if not match_id:
            raise HTTPException(status_code=400, detail="Match ID required")
        
        # Verify user can manage this tournament
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        if tournament.get('host_id') != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to manage this tournament")
        
        # Update match
        match_update = {
            "team1_score": data.get('team1_score', 0),
            "team2_score": data.get('team2_score', 0),
            "status": data.get('status', 'completed'),
            "winner_id": data.get('winner_id'),
            "winner_name": data.get('winner_name'),
            "completed_at": datetime.utcnow().isoformat() if data.get('status') == 'completed' else None
        }
        
        supabase_request("PATCH", f"matches?id=eq.{match_id}", match_update)
        
        # If match is completed and there's a winner, update team stats
        if data.get('status') == 'completed' and data.get('winner_id'):
            # Get the match to find teams
            matches = supabase_request("GET", f"matches?id=eq.{match_id}")
            if matches and len(matches) > 0:
                match = matches[0]
                
                # Update winning team
                if match.get('team1_id') == data['winner_id']:
                    # Update team1 wins
                    teams = supabase_request("GET", f"teams?id=eq.{match['team1_id']}")
                    if teams and len(teams) > 0:
                        team = teams[0]
                        supabase_request("PATCH", f"teams?id=eq.{match['team1_id']}", {
                            "wins": (team.get('wins', 0) or 0) + 1
                        })
                    
                    # Update team2 losses
                    if match.get('team2_id'):
                        teams2 = supabase_request("GET", f"teams?id=eq.{match['team2_id']}")
                        if teams2 and len(teams2) > 0:
                            team2 = teams2[0]
                            supabase_request("PATCH", f"teams?id=eq.{match['team2_id']}", {
                                "losses": (team2.get('losses', 0) or 0) + 1
                            })
                
                elif match.get('team2_id') == data['winner_id']:
                    # Update team2 wins
                    teams = supabase_request("GET", f"teams?id=eq.{match['team2_id']}")
                    if teams and len(teams) > 0:
                        team = teams[0]
                        supabase_request("PATCH", f"teams?id=eq.{match['team2_id']}", {
                            "wins": (team.get('wins', 0) or 0) + 1
                        })
                    
                    # Update team1 losses
                    if match.get('team1_id'):
                        teams1 = supabase_request("GET", f"teams?id=eq.{match['team1_id']}")
                        if teams1 and len(teams1) > 0:
                            team1 = teams1[0]
                            supabase_request("PATCH", f"teams?id=eq.{match['team1_id']}", {
                                "losses": (team1.get('losses', 0) or 0) + 1
                            })
        
        return {
            "success": True,
            "message": "Match updated successfully"
        }
        
    except Exception as e:
        logger.error(f"Update match error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update match")

@app.post("/api/tournament-pass/{tournament_id}/generate-bracket")
async def generate_tournament_bracket(tournament_id: str, current_user: Dict = Depends(get_current_user)):
    """Generate bracket for tournament"""
    try:
        # Verify user can manage this tournament
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        if tournament.get('host_id') != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to manage this tournament")
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}&order=seed.asc")
        
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
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", {
            "status": "ongoing",
            "current_round": 1,
            "updated_at": datetime.utcnow().isoformat()
        })
        
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
    import random
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
                "created_at": datetime.utcnow().isoformat()
            }
            
            # Check if match exists
            existing = supabase_request("GET", f"matches?id=eq.{match['match_id']}")
            
            if not existing or len(existing) == 0:
                supabase_request("POST", "matches", match_data)

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

# backend/main.py - Fix the server stats update function

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
            # Update existing - remove updated_at if field doesn't exist
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



