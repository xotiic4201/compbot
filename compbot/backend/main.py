# main.py - FastAPI with Pydantic v1 (NO RUST)
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
app = FastAPI(title="XTourney API", version="3.0")

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

class TournamentStatusUpdate(BaseModel):
    status: str

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

# ========== ROUTES ==========
@app.get("/")
async def root():
    return {"message": "XTourney API v3.0", "status": "running"}

@app.get("/api/health")
async def health_check():
    try:
        users = supabase_request("GET", "users?limit=1")
        tournaments = supabase_request("GET", "tournaments?limit=1")
        
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

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
        
        return {
            "success": True,
            "message": "Bracket generation endpoint (stub)",
            "tournament_id": tournament_id
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
        elif score_data.team2_score > score_data.team1_score:
            winner_id = match_data.get("team2_id")
        else:
            winner_id = None
        
        update_data = {
            "team1_score": score_data.team1_score,
            "team2_score": score_data.team2_score,
            "winner_id": winner_id,
            "status": "completed",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"matches?id=eq.{match_id}", update_data)
        
        updated_matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        return {
            "success": True,
            "match": updated_matches[0] if updated_matches and len(updated_matches) > 0 else match_data,
            "message": "Match score updated successfully"
        }
    except Exception as e:
        logger.error(f"Update match score error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update match score")

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
        team_record = {
            "id": team_id,
            "tournament_id": team_data.tournament_id,
            "name": team_data.team_name,
            "captain_discord_id": team_data.captain_id,
            "captain_name": team_data.captain_name,
            "region": team_data.region,
            "members": json.dumps(team_data.members),
            "status": "registered",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if team_data.tag:
            team_record["name"] = f"[{team_data.tag}] {team_data.team_name}"
        
        result = supabase_request("POST", "teams", team_record)
        
        supabase_request("PATCH", f"tournaments?id=eq.{team_data.tournament_id}", {
            "team_count": current_teams + 1,
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "team": {
                "id": team_id,
                "name": team_record["name"],
                "captain_name": team_data.captain_name,
                "region": team_data.region,
                "members": team_data.members
            },
            "message": "Team registered successfully"
        }
    except Exception as e:
        logger.error(f"Team registration error: {e}")
        raise HTTPException(status_code=500, detail="Failed to register team")

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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
