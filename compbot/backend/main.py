# main.py - Production FastAPI Backend with Supabase (FIXED VERSION)
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timedelta
import jwt
import uuid
import random
import string
import os
import json
from dotenv import load_dotenv
from passlib.context import CryptContext
import asyncio
from supabase import create_client, Client
from postgrest.exceptions import APIError

# Load environment variables
load_dotenv()

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY environment variables are required")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ========== SUPABASE SETUP ==========
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY) if SUPABASE_SERVICE_KEY else supabase

# ========== FASTAPI SETUP ==========
app = FastAPI(
    title="XTourney API",
    description="Production Tournament Management Backend with Supabase",
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.xotiicsplaza.us",
        "https://xotiicsplaza.us",
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== SECURITY ==========
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ========== MODELS ==========
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[str] = Field(None, max_length=100)
    discord_id: Optional[str] = Field(None, max_length=50)

class UserLogin(BaseModel):
    username: str
    password: str

class TournamentCreate(BaseModel):
    name: str = Field(..., max_length=100)
    game: str = Field(..., max_length=50)
    max_teams: int = Field(..., ge=2, le=128)
    max_players_per_team: int = Field(..., ge=1, le=10)
    description: Optional[str] = Field(None, max_length=500)
    tournament_pass: str = Field(..., max_length=50)
    host_id: str
    created_by: str = Field(..., max_length=100)
    discord_server_id: Optional[str] = None

class TournamentUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    game: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, pattern="^(registration|ongoing|completed|cancelled)$")
    description: Optional[str] = Field(None, max_length=500)
    team_count: Optional[int] = Field(None, ge=0)
    current_round: Optional[int] = Field(None, ge=0)

class TeamCreate(BaseModel):
    team_name: str = Field(..., max_length=100)
    tournament_id: str
    captain_id: str
    captain_name: str = Field(..., max_length=100)
    members: List[str]
    region: str = Field(..., pattern="^(NA|EU|ASIA|OCE|SA|GLOBAL)$")
    tag: Optional[str] = Field(None, max_length=10)
    player_ids: List[str]

class MatchCreate(BaseModel):
    tournament_id: str
    round_number: int = Field(..., ge=1)
    match_number: int = Field(..., ge=1)
    team1_id: Optional[str] = None
    team2_id: Optional[str] = None
    team1_name: Optional[str] = Field(None, max_length=100)
    team2_name: Optional[str] = Field(None, max_length=100)
    winner_id: Optional[str] = None
    score1: int = Field(0, ge=0)
    score2: int = Field(0, ge=0)
    status: str = Field("scheduled", pattern="^(scheduled|ongoing|completed|cancelled)$")

class BracketCreate(BaseModel):
    tournament_id: str
    bracket_data: Dict[str, Any]
    total_rounds: int = Field(..., ge=1)
    current_round: int = Field(1, ge=1)

class ServerStatsUpdate(BaseModel):
    server_id: str
    server_name: str = Field(..., max_length=100)
    member_count: int = Field(..., ge=0)
    icon_url: Optional[str] = None

class TournamentPassAuth(BaseModel):
    pass_code: str

# ========== AUTH FUNCTIONS ==========
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user exists in Supabase
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return response.data[0]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error fetching user",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ========== DATABASE HELPER FUNCTIONS ==========
async def check_tournament_pass(pass_code: str):
    """Check if tournament pass exists and get tournament"""
    try:
        response = supabase.table("tournaments").select("*").eq("tournament_pass", pass_code).execute()
        if not response.data:
            return None
        return response.data[0]
    except Exception as e:
        print(f"Error checking tournament pass: {e}")
        return None

# ========== API ENDPOINTS ==========
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "XTourney API",
        "version": "3.0.0",
        "database": "Supabase PostgreSQL",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    try:
        # Test database connection
        supabase.table("users").select("count", count="exact").limit(1).execute()
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

# ========== AUTH ENDPOINTS ==========
@app.post("/api/register", response_model=Dict[str, Any])
async def register(user: UserCreate):
    try:
        # Check if username exists
        existing = supabase.table("users").select("id").eq("username", user.username).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check if email exists
        if user.email:
            existing_email = supabase.table("users").select("id").eq("email", user.email).execute()
            if existing_email.data:
                raise HTTPException(status_code=400, detail="Email already exists")
        
        # Hash password
        hashed_password = get_password_hash(user.password)
        
        # Create user
        user_data = {
            "username": user.username,
            "email": user.email,
            "password_hash": hashed_password,
            "discord_id": user.discord_id,
            "is_host": False
        }
        
        response = supabase.table("users").insert(user_data).execute()
        
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to create user")
        
        new_user = response.data[0]
        
        # Create JWT token
        access_token = create_access_token(data={"sub": user.username})
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "id": new_user["id"],
                "username": new_user["username"],
                "email": new_user["email"],
                "is_host": new_user["is_host"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/login", response_model=Dict[str, Any])
async def login(user: UserLogin):
    try:
        # Get user
        response = supabase.table("users").select("*").eq("username", user.username).execute()
        
        if not response.data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        db_user = response.data[0]
        
        # Verify password
        if not verify_password(user.password, db_user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create JWT token
        access_token = create_access_token(data={"sub": user.username})
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "id": db_user["id"],
                "username": db_user["username"],
                "email": db_user["email"],
                "is_host": db_user["is_host"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

# ========== TOURNAMENT ENDPOINTS ==========
@app.post("/api/tournaments/discord", response_model=Dict[str, Any])
async def create_tournament_discord(tournament: TournamentCreate):
    try:
        # Check if tournament pass already exists
        existing = supabase.table("tournaments").select("id").eq("tournament_pass", tournament.tournament_pass).execute()
        if existing.data:
            # Generate new pass if duplicate
            tournament.tournament_pass = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        # Create tournament
        tournament_data = {
            "name": tournament.name,
            "game": tournament.game,
            "max_teams": tournament.max_teams,
            "max_players_per_team": tournament.max_players_per_team,
            "description": tournament.description,
            "tournament_pass": tournament.tournament_pass,
            "host_id": tournament.host_id,
            "created_by": tournament.created_by,
            "discord_server_id": tournament.discord_server_id,
            "status": "registration",
            "team_count": 0,
            "current_round": 0,
            "total_rounds": 0
        }
        
        response = supabase.table("tournaments").insert(tournament_data).execute()
        
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to create tournament")
        
        new_tournament = response.data[0]
        
        return {
            "success": True,
            "tournament_id": new_tournament["id"],
            "tournament_pass": new_tournament["tournament_pass"],
            "message": "Tournament created successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create tournament: {str(e)}")

@app.get("/api/tournaments", response_model=Dict[str, Any])
async def get_tournaments(status: Optional[str] = None, limit: int = 50, offset: int = 0):
    try:
        query = supabase.table("tournaments").select("*", count="exact")
        
        if status:
            query = query.eq("status", status)
        
        query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
        response = query.execute()
        
        tournaments = response.data
        total_count = response.count or 0
        
        # Get team counts for each tournament
        for tournament in tournaments:
            teams_response = supabase.table("teams").select("id", count="exact").eq("tournament_id", tournament["id"]).execute()
            tournament["team_count"] = teams_response.count or 0
            
            # Get bracket info if exists
            bracket_response = supabase.table("brackets").select("*").eq("tournament_id", tournament["id"]).execute()
            if bracket_response.data:
                tournament["has_bracket"] = True
                tournament["current_round"] = bracket_response.data[0]["current_round"]
                tournament["total_rounds"] = bracket_response.data[0]["total_rounds"]
            else:
                tournament["has_bracket"] = False
                tournament["current_round"] = 0
                tournament["total_rounds"] = 0
        
        return {
            "success": True,
            "tournaments": tournaments,
            "total": total_count,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch tournaments: {str(e)}")

@app.get("/api/tournaments/{tournament_id}", response_model=Dict[str, Any])
async def get_tournament(tournament_id: str):
    try:
        # Get tournament
        response = supabase.table("tournaments").select("*").eq("id", tournament_id).execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = response.data[0]
        
        # Get teams
        teams_response = supabase.table("teams").select("*").eq("tournament_id", tournament_id).execute()
        tournament["teams"] = teams_response.data
        tournament["team_count"] = len(teams_response.data)
        
        # Get bracket if exists
        bracket_response = supabase.table("brackets").select("*").eq("tournament_id", tournament_id).execute()
        if bracket_response.data:
            tournament["bracket"] = bracket_response.data[0]
            tournament["has_bracket"] = True
        else:
            tournament["has_bracket"] = False
        
        # Get matches if bracket exists
        if bracket_response.data:
            matches_response = supabase.table("matches").select("*").eq("tournament_id", tournament_id).order("round_number").order("match_number").execute()
            tournament["matches"] = matches_response.data
        
        return {
            "success": True,
            "tournament": tournament
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch tournament: {str(e)}")

@app.put("/api/tournaments/{tournament_id}", response_model=Dict[str, Any])
async def update_tournament(tournament_id: str, update: TournamentUpdate, current_user: dict = Depends(get_current_user)):
    try:
        # Get tournament first
        tournament_response = supabase.table("tournaments").select("*").eq("id", tournament_id).execute()
        
        if not tournament_response.data:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament_response.data[0]
        
        # Check permission (only host can update)
        # You might want to add more sophisticated permission checks
        
        # Prepare update data
        update_data = {k: v for k, v in update.dict(exclude_unset=True).items() if v is not None}
        
        if not update_data:
            return {"success": True, "message": "No changes provided"}
        
        update_data["updated_at"] = datetime.utcnow().isoformat()
        
        # Update tournament
        response = supabase.table("tournaments").update(update_data).eq("id", tournament_id).execute()
        
        return {
            "success": True,
            "message": "Tournament updated successfully",
            "tournament": response.data[0] if response.data else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update tournament: {str(e)}")

# ========== TEAM ENDPOINTS ==========
@app.post("/api/teams/register", response_model=Dict[str, Any])
async def register_team(team: TeamCreate):
    try:
        # Check if tournament exists and is accepting registrations
        tournament_response = supabase.table("tournaments").select("*").eq("id", team.tournament_id).execute()
        
        if not tournament_response.data:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament_response.data[0]
        
        if tournament["status"] != "registration":
            raise HTTPException(status_code=400, detail="Tournament is not accepting registrations")
        
        # Check team count
        teams_response = supabase.table("teams").select("id", count="exact").eq("tournament_id", team.tournament_id).execute()
        current_teams = teams_response.count or 0
        
        if current_teams >= tournament["max_teams"]:
            raise HTTPException(status_code=400, detail="Tournament is full")
        
        # Check if team name already exists in this tournament
        existing_team = supabase.table("teams").select("id").eq("tournament_id", team.tournament_id).eq("name", team.team_name).execute()
        if existing_team.data:
            raise HTTPException(status_code=400, detail="Team name already taken in this tournament")
        
        # Create team
        team_data = {
            "tournament_id": team.tournament_id,
            "name": team.team_name,
            "tag": team.tag,
            "captain_id": team.captain_id,
            "captain_name": team.captain_name,
            "members": json.dumps(team.members),
            "player_ids": json.dumps(team.player_ids),
            "region": team.region,
            "wins": 0,
            "losses": 0
        }
        
        response = supabase.table("teams").insert(team_data).execute()
        
        if not response.data:
            raise HTTPException(status_code=500, detail="Failed to register team")
        
        # Update tournament team count
        supabase.table("tournaments").update({"team_count": current_teams + 1}).eq("id", team.tournament_id).execute()
        
        return {
            "success": True,
            "team": response.data[0],
            "message": "Team registered successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register team: {str(e)}")

# ========== TOURNAMENT PASS ENDPOINTS ==========
@app.post("/api/tournament-pass/auth", response_model=Dict[str, Any])
async def auth_tournament_pass(pass_data: TournamentPassAuth, current_user: dict = Depends(get_current_user)):
    try:
        tournament = await check_tournament_pass(pass_data.pass_code)
        
        if not tournament:
            raise HTTPException(status_code=404, detail="Invalid tournament pass")
        
        # Check if user is the host
        if tournament["host_id"] != current_user.get("id") and tournament["host_id"] != current_user.get("discord_id"):
            # You might want to add admin checks here
            pass
        
        return {
            "success": True,
            "message": "Tournament access granted",
            "tournament": tournament
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to authenticate pass: {str(e)}")

@app.get("/api/tournament-pass/{tournament_id}/manage", response_model=Dict[str, Any])
async def manage_tournament(tournament_id: str, current_user: dict = Depends(get_current_user)):
    try:
        # Get tournament with all related data
        tournament_response = await get_tournament(tournament_id)
        
        if not tournament_response["success"]:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament_response["tournament"]
        
        # Permission check - you might want to verify the user has access
        # For now, we'll trust the frontend to only show this to authorized users
        
        return {
            "success": True,
            "tournament": tournament,
            "teams": tournament.get("teams", []),
            "bracket": tournament.get("bracket", None),
            "matches": tournament.get("matches", [])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tournament data: {str(e)}")

@app.post("/api/tournament-pass/{tournament_id}/generate-bracket", response_model=Dict[str, Any])
async def generate_bracket(tournament_id: str, current_user: dict = Depends(get_current_user)):
    try:
        # Get tournament and teams
        tournament_response = supabase.table("tournaments").select("*").eq("id", tournament_id).execute()
        
        if not tournament_response.data:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament_response.data[0]
        
        # Check if tournament has enough teams
        teams_response = supabase.table("teams").select("*").eq("tournament_id", tournament_id).execute()
        teams = teams_response.data
        
        if len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams to generate bracket")
        
        # Check if bracket already exists
        existing_bracket = supabase.table("brackets").select("*").eq("tournament_id", tournament_id).execute()
        if existing_bracket.data:
            # Update existing bracket
            return {
                "success": True,
                "message": "Bracket already exists",
                "bracket_id": existing_bracket.data[0]["id"]
            }
        
        # Calculate total rounds (power of 2 bracket)
        team_count = len(teams)
        total_rounds = 1
        while (2 ** total_rounds) < team_count:
            total_rounds += 1
        
        # Create bracket structure
        bracket_data = {
            "tournament_id": tournament_id,
            "teams": teams,
            "total_rounds": total_rounds,
            "current_round": 1,
            "rounds": []
        }
        
        # Create rounds and matches
        for round_num in range(1, total_rounds + 1):
            round_data = {
                "round_number": round_num,
                "name": f"Round {round_num}",
                "matches": []
            }
            
            # Calculate number of matches for this round
            if round_num == 1:
                # First round
                matches_in_round = (team_count + 1) // 2
                for match_num in range(1, matches_in_round + 1):
                    team1_idx = (match_num - 1) * 2
                    team2_idx = team1_idx + 1
                    
                    match_data = {
                        "match_number": match_num,
                        "team1_id": teams[team1_idx]["id"] if team1_idx < len(teams) else None,
                        "team2_id": teams[team2_idx]["id"] if team2_idx < len(teams) else None,
                        "team1_name": teams[team1_idx]["name"] if team1_idx < len(teams) else "BYE",
                        "team2_name": teams[team2_idx]["name"] if team2_idx < len(teams) else "BYE",
                        "winner_id": None,
                        "score1": 0,
                        "score2": 0,
                        "status": "scheduled"
                    }
                    
                    # Create match in database
                    match_response = supabase.table("matches").insert({
                        "tournament_id": tournament_id,
                        "round_number": round_num,
                        "match_number": match_num,
                        "team1_id": match_data["team1_id"],
                        "team2_id": match_data["team2_id"],
                        "team1_name": match_data["team1_name"],
                        "team2_name": match_data["team2_name"],
                        "status": "scheduled"
                    }).execute()
                    
                    if match_response.data:
                        match_data["id"] = match_response.data[0]["id"]
                    
                    round_data["matches"].append(match_data)
            else:
                # Later rounds (will be filled as winners advance)
                matches_in_round = matches_in_round // 2
                for match_num in range(1, matches_in_round + 1):
                    round_data["matches"].append({
                        "match_number": match_num,
                        "team1_id": None,
                        "team2_id": None,
                        "team1_name": "TBD",
                        "team2_name": "TBD",
                        "winner_id": None,
                        "score1": 0,
                        "score2": 0,
                        "status": "pending"
                    })
            
            bracket_data["rounds"].append(round_data)
        
        # Create bracket record
        bracket_response = supabase.table("brackets").insert({
            "tournament_id": tournament_id,
            "bracket_data": json.dumps(bracket_data),
            "total_rounds": total_rounds,
            "current_round": 1
        }).execute()
        
        # Update tournament status
        supabase.table("tournaments").update({
            "status": "ongoing",
            "current_round": 1,
            "total_rounds": total_rounds
        }).eq("id", tournament_id).execute()
        
        return {
            "success": True,
            "message": "Bracket generated successfully",
            "bracket_id": bracket_response.data[0]["id"] if bracket_response.data else None,
            "total_rounds": total_rounds
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate bracket: {str(e)}")

@app.post("/api/tournament-pass/{tournament_id}/update-bracket", response_model=Dict[str, Any])
async def update_bracket(tournament_id: str, bracket_update: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    try:
        # Get existing bracket
        bracket_response = supabase.table("brackets").select("*").eq("tournament_id", tournament_id).execute()
        
        if not bracket_response.data:
            raise HTTPException(status_code=404, detail="Bracket not found")
        
        bracket = bracket_response.data[0]
        
        # Update bracket data
        update_data = {
            "bracket_data": json.dumps(bracket_update.get("bracket", {})),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if "current_round" in bracket_update:
            update_data["current_round"] = bracket_update["current_round"]
            
            # Update tournament current round
            supabase.table("tournaments").update({
                "current_round": bracket_update["current_round"]
            }).eq("id", tournament_id).execute()
        
        # Update bracket
        response = supabase.table("brackets").update(update_data).eq("id", bracket["id"]).execute()
        
        return {
            "success": True,
            "message": "Bracket updated successfully",
            "bracket": response.data[0] if response.data else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update bracket: {str(e)}")

# ========== STATISTICS ENDPOINTS ==========
@app.get("/api/stats", response_model=Dict[str, Any])
async def get_stats():
    try:
        # Get tournament stats
        tournaments_response = supabase.table("tournaments").select("status", count="exact").execute()
        
        # Count by status
        status_counts = {}
        if tournaments_response.count:
            all_tournaments = supabase.table("tournaments").select("*").execute()
            for tournament in all_tournaments.data:
                status = tournament["status"]
                status_counts[status] = status_counts.get(status, 0) + 1
        
        # Get total teams
        teams_response = supabase.table("teams").select("id", count="exact").execute()
        total_teams = teams_response.count or 0
        
        # Get active matches (ongoing status)
        matches_response = supabase.table("matches").select("id", count="exact").eq("status", "ongoing").execute()
        live_matches = matches_response.count or 0
        
        # Get server stats
        servers_response = supabase.table("server_stats").select("*").execute()
        connected_servers = len(servers_response.data) if servers_response.data else 0
        
        # Calculate total members across all servers
        total_members = sum(server.get("member_count", 0) for server in (servers_response.data or []))
        
        return {
            "success": True,
            "stats": {
                "active_tournaments": status_counts.get("ongoing", 0) + status_counts.get("registration", 0),
                "total_teams": total_teams,
                "connected_servers": connected_servers,
                "live_matches": live_matches,
                "total_members": total_members,
                "tournament_status": status_counts
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

# ========== DISCORD BOT ENDPOINTS ==========
@app.post("/api/bot/server-stats", response_model=Dict[str, Any])
async def update_server_stats(stats: ServerStatsUpdate):
    try:
        # Check if server exists
        existing_response = supabase.table("server_stats").select("*").eq("server_id", stats.server_id).execute()
        
        if existing_response.data:
            # Update existing
            response = supabase.table("server_stats").update({
                "server_name": stats.server_name,
                "member_count": stats.member_count,
                "icon_url": stats.icon_url,
                "last_updated": datetime.utcnow().isoformat()
            }).eq("server_id", stats.server_id).execute()
        else:
            # Insert new
            response = supabase.table("server_stats").insert({
                "server_id": stats.server_id,
                "server_name": stats.server_name,
                "member_count": stats.member_count,
                "icon_url": stats.icon_url
            }).execute()
        
        return {
            "success": True,
            "message": "Server stats updated",
            "server": response.data[0] if response.data else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update server stats: {str(e)}")

@app.get("/api/bot/servers", response_model=Dict[str, Any])
async def get_bot_servers():
    try:
        response = supabase.table("server_stats").select("*").order("last_updated", desc=True).execute()
        
        return {
            "success": True,
            "servers": response.data or [],
            "total": len(response.data) if response.data else 0
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get servers: {str(e)}")

# ========== ERROR HANDLERS ==========
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "detail": "Internal server error",
            "error": str(exc)
        }
    )

# ========== STARTUP ==========
@app.on_event("startup")
async def startup_event():
    print("🚀 XTourney API starting up...")
    print(f"📊 Database: Supabase PostgreSQL")
    print(f"🔗 Supabase URL: {SUPABASE_URL[:30]}...")
    print("✅ API is ready to receive requests")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

