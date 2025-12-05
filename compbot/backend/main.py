from fastapi import FastAPI, HTTPException, Request, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import requests
import secrets
import hashlib
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel, EmailStr, Field, validator
import jwt
from uuid import uuid4
import re
import logging
import math
from contextlib import asynccontextmanager
from fastapi_limiter import FastAPILimiter
import redis.asyncio as redis
import random
from enum import Enum

# ========== SETUP LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== ENUMS ==========
class TournamentStatus(str, Enum):
    REGISTRATION = "registration"
    ONGOING = "ongoing"
    COMPLETED = "completed"

class MatchStatus(str, Enum):
    SCHEDULED = "scheduled"
    ONGOING = "ongoing"
    COMPLETED = "completed"
    PENDING = "pending"

class ProofStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"

class BracketType(str, Enum):
    SINGLE_ELIMINATION = "single_elimination"
    DOUBLE_ELIMINATION = "double_elimination"

# ========== LIFECYCLE MANAGEMENT ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    logger.info("🚀 Starting XTourney API v2.0")
    logger.info(f"📊 Environment: {os.getenv('ENVIRONMENT', 'development')}")
    
    # Initialize Redis for rate limiting
    try:
        redis_client = redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379"),
            encoding="utf-8",
            decode_responses=True
        )
        await FastAPILimiter.init(redis_client)
        logger.info("✅ Redis connected for rate limiting")
    except Exception as e:
        logger.warning(f"❌ Redis connection failed: {e}. Rate limiting disabled.")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down XTourney API")

# ========== APP INITIALIZATION ==========
app = FastAPI(
    title="XTourney API v2.0", 
    version="2.0.0",
    description="Professional Esports Tournament Platform with Auto Bracket Progression",
    lifespan=lifespan
)

# ========== SECURITY MIDDLEWARE ==========
security = HTTPBearer()

# CORS Configuration
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://www.xotiicsplaza.us",
    "https://xotiicsplaza.us",
    "https://*.xotiicsplaza.us"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# ========== CONFIGURATION ==========
class Config:
    """Configuration management"""
    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
    
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
    
    FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us/")
    JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_DAYS = 30
    
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    API_VERSION = "v2"
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE = 60
    
    @classmethod
    def validate(cls):
        """Validate required environment variables"""
        required = ["SUPABASE_URL", "SUPABASE_KEY", "DISCORD_CLIENT_SECRET"]
        missing = [var for var in required if not getattr(cls, var, None)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")
        
        logger.info("✅ Configuration validated successfully")
        return True

# Validate config
try:
    Config.validate()
except ValueError as e:
    logger.error(f"❌ Configuration error: {e}")
    raise

# Headers for Supabase requests
headers = {
    "apikey": Config.SUPABASE_KEY,
    "Authorization": f"Bearer {Config.SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

admin_headers = {
    "apikey": Config.SUPABASE_KEY,
    "Authorization": f"Bearer {Config.SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

# ========== PYDANTIC MODELS ==========
class DiscordAuthRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class EmailRegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=8)
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v

class EmailLoginRequest(BaseModel):
    email: EmailStr
    password: str

class LinkEmailRequest(BaseModel):
    email: EmailStr

class TournamentCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    game: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = Field(default="", max_length=1000)
    max_teams: int = Field(default=16, ge=2, le=128)
    start_date: str
    discord_server_id: Optional[str] = None
    bracket_type: str = Field(default=BracketType.SINGLE_ELIMINATION)
    max_players_per_team: int = Field(default=5, ge=1, le=10)
    region_lock: bool = Field(default=False)
    region: str = Field(default="global")
    prize_pool: Optional[str] = Field(default="", max_length=200)
    auto_matchmaking: bool = Field(default=True)
    
    @validator('start_date')
    def validate_start_date(cls, v):
        try:
            start_date = datetime.fromisoformat(v.replace('Z', '+00:00'))
            if start_date < datetime.utcnow():
                raise ValueError("Start date must be in the future")
            return v
        except:
            raise ValueError("Invalid date format. Use ISO format")

class TeamRegister(BaseModel):
    tournament_id: str
    name: str = Field(..., min_length=2, max_length=50)
    captain_discord_id: str
    region: Optional[str] = Field(default="global")
    members: Optional[List[str]] = Field(default_factory=list)

class ProofSubmission(BaseModel):
    tournament_id: str
    match_id: str
    description: Optional[str] = ""
    image_url: str
    team_name: str

class MatchUpdate(BaseModel):
    team1_score: int = Field(ge=0)
    team2_score: int = Field(ge=0)
    winner_name: Optional[str] = None

class TournamentStart(BaseModel):
    tournament_id: str

class TournamentAutoCompleteConfig(BaseModel):
    auto_start_matches: bool = Field(default=True)
    match_duration_minutes: int = Field(default=120, ge=30, le=300)
    auto_progress_rounds: bool = Field(default=True)
    round_interval_minutes: int = Field(default=15, ge=5, le=60)

# ========== DATABASE SERVICE ==========
class DatabaseService:
    """Database service with retry logic and error handling"""
    
    @staticmethod
    def execute_query(table: str, method: str = "GET", data: dict = None, 
                     query: str = "", admin: bool = False):
        """Execute a database query with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = f"{Config.SUPABASE_URL}/rest/v1/{table}"
                if query:
                    url += f"?{query}"
                
                headers_to_use = admin_headers if admin else headers
                
                if method == "GET":
                    response = requests.get(url, headers=headers_to_use, timeout=10)
                elif method == "POST":
                    response = requests.post(url, json=data, headers=headers_to_use, timeout=10)
                elif method == "PATCH":
                    response = requests.patch(url, json=data, headers=headers_to_use, timeout=10)
                elif method == "DELETE":
                    response = requests.delete(url, headers=headers_to_use, timeout=10)
                elif method == "PUT":
                    response = requests.put(url, json=data, headers=headers_to_use, timeout=10)
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
                    logger.error(f"Database error {response.status_code}: {response.text[:200]}")
                    if attempt < max_retries - 1:
                        continue
                    return None
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Database timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    continue
                raise HTTPException(status_code=504, detail="Database timeout")
            except Exception as e:
                logger.error(f"Database exception: {str(e)}")
                if attempt < max_retries - 1:
                    continue
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    @staticmethod
    def insert(table: str, data: dict, admin: bool = False):
        return DatabaseService.execute_query(table, "POST", data, admin=admin)
    
    @staticmethod
    def select(table: str, query: str = "", admin: bool = False):
        return DatabaseService.execute_query(table, "GET", query=query, admin=admin)
    
    @staticmethod
    def update(table: str, data: dict, column: str, value: str, admin: bool = False):
        query = f"{column}=eq.{value}"
        return DatabaseService.execute_query(table, "PATCH", data, query=query, admin=admin)
    
    @staticmethod
    def delete(table: str, column: str, value: str, admin: bool = False):
        query = f"{column}=eq.{value}"
        return DatabaseService.execute_query(table, "DELETE", query=query, admin=admin)
    
    @staticmethod
    def raw_sql(query: str, params: dict = None):
        """Execute raw SQL query"""
        try:
            url = f"{Config.SUPABASE_URL}/rest/v1/rpc/execute_sql"
            data = {"query": query}
            if params:
                data["params"] = params
            
            response = requests.post(url, json=data, headers=admin_headers, timeout=10)
            
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Raw SQL error {response.status_code}: {response.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"Raw SQL exception: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# ========== AUTH SERVICE ==========
class AuthService:
    """Authentication and authorization service"""
    
    @staticmethod
    def create_tokens(user_data: dict) -> Dict[str, str]:
        """Create access and refresh tokens"""
        access_payload = {
            "sub": user_data.get("id"),
            "username": user_data.get("username"),
            "discord_id": user_data.get("discord_id"),
            "email": user_data.get("email"),
            "account_type": user_data.get("account_type"),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        
        refresh_payload = {
            "sub": user_data.get("id"),
            "type": "refresh",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=Config.JWT_EXPIRE_DAYS)
        }
        
        access_token = jwt.encode(access_payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
        refresh_token = jwt.encode(refresh_payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 7 * 24 * 60 * 60
        }
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    @staticmethod
    async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
        """Get current authenticated user"""
        token = credentials.credentials
        payload = AuthService.verify_token(token)
        
        if not payload or payload.get("type") == "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        user_id = payload.get("sub")
        users = DatabaseService.select("users", f"id=eq.'{user_id}'")
        
        if not users:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return users[0]

# ========== TOURNAMENT SERVICE ==========
class TournamentService:
    """Service for tournament management and bracket generation"""
    
    @staticmethod
    def calculate_total_rounds(team_count: int) -> int:
        """Calculate total rounds needed for tournament"""
        rounds = 0
        teams = team_count
        while teams > 1:
            teams //= 2
            rounds += 1
        return max(rounds, 1)
    
    @staticmethod
    def get_round_name(round_num: int, total_rounds: int) -> str:
        """Get human-readable round name"""
        if round_num == total_rounds:
            return "Finals"
        elif round_num == total_rounds - 1:
            return "Semi-Finals"
        elif round_num == total_rounds - 2:
            return "Quarter-Finals"
        else:
            return f"Round {round_num}"
    
    @staticmethod
    def group_teams_by_region(teams: List[Dict]) -> Dict[str, List[Dict]]:
        """Group teams by region"""
        teams_by_region = {}
        for team in teams:
            region = team.get('region', 'GLOBAL')
            if region not in teams_by_region:
                teams_by_region[region] = []
            teams_by_region[region].append(team)
        return teams_by_region
    
    @staticmethod
    def generate_region_bracket(teams: List[Dict], tournament_id: str, region: str, round_number: int = 1) -> List[Dict]:
        """Generate bracket matches for a specific region"""
        random.shuffle(teams)
        matches = []
        
        # Create first round matches
        for i in range(0, len(teams), 2):
            match_num = (i // 2) + 1
            team1 = teams[i] if i < len(teams) else None
            team2 = teams[i + 1] if i + 1 < len(teams) else None
            
            match_id = str(uuid4())
            match_data = {
                "id": match_id,
                "tournament_id": tournament_id,
                "round_number": round_number,
                "match_number": match_num,
                "team1_id": team1.get('id') if team1 else None,
                "team2_id": team2.get('id') if team2 else None,
                "team1_name": team1.get('name') if team1 else "BYE",
                "team2_name": team2.get('name') if team2 else "BYE",
                "region": region,
                "team1_score": 0,
                "team2_score": 0,
                "winner_id": None,
                "status": MatchStatus.SCHEDULED if team1 and team2 else MatchStatus.COMPLETED,
                "is_live": False,
                "scheduled_time": (datetime.utcnow() + timedelta(minutes=30 * match_num)).isoformat(),
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            # Auto-win for bye
            if team1 and not team2:
                match_data["team1_score"] = 1
                match_data["winner_id"] = team1.get('id')
            
            matches.append(match_data)
        
        return matches
    
    @staticmethod
    def generate_region_locked_bracket(teams: List[Dict], tournament_id: str, max_teams: int) -> Dict[str, Any]:
        """Generate region-locked bracket with separate region tournaments"""
        teams_by_region = TournamentService.group_teams_by_region(teams)
        region_brackets = {}
        
        # Generate bracket for each region
        for region, region_teams in teams_by_region.items():
            if len(region_teams) >= 2:
                # Calculate rounds for this region
                region_rounds = TournamentService.calculate_total_rounds(len(region_teams))
                
                # Generate first round matches
                first_round_matches = TournamentService.generate_region_bracket(
                    region_teams, tournament_id, region, 1
                )
                
                region_brackets[region] = {
                    "teams": region_teams,
                    "matches": first_round_matches,
                    "total_rounds": region_rounds,
                    "current_round": 1,
                    "region_champion": None
                }
        
        return {
            "region_brackets": region_brackets,
            "has_region_lock": True,
            "region_count": len(region_brackets),
            "combined_rounds": TournamentService.calculate_total_rounds(max_teams)
        }
    
    @staticmethod
    def generate_global_bracket(teams: List[Dict], tournament_id: str, max_teams: int, auto_matchmaking: bool = True) -> List[Dict]:
        """Generate global bracket with optional region matchmaking"""
        if auto_matchmaking:
            # Try to match teams from same region first
            teams_by_region = TournamentService.group_teams_by_region(teams)
            
            # Sort regions by team count
            sorted_regions = sorted(teams_by_region.items(), key=lambda x: len(x[1]), reverse=True)
            
            all_matches = []
            used_teams = set()
            
            # Create matches within regions first
            for region, region_teams in sorted_regions:
                if len(region_teams) >= 2:
                    random.shuffle(region_teams)
                    for i in range(0, len(region_teams), 2):
                        if i + 1 < len(region_teams):
                            team1 = region_teams[i]
                            team2 = region_teams[i + 1]
                            all_matches.append((team1, team2, region))
                            used_teams.add(team1['id'])
                            used_teams.add(team2['id'])
            
            # Add remaining teams (mixed regions)
            remaining_teams = [t for t in teams if t['id'] not in used_teams]
            for i in range(0, len(remaining_teams), 2):
                if i + 1 < len(remaining_teams):
                    all_matches.append((remaining_teams[i], remaining_teams[i + 1], 'MIXED'))
            
            # Convert to match data
            matches = []
            for i, (team1, team2, region) in enumerate(all_matches[:max_teams//2]):
                match_id = str(uuid4())
                matches.append({
                    "id": match_id,
                    "tournament_id": tournament_id,
                    "round_number": 1,
                    "match_number": i + 1,
                    "team1_id": team1.get('id'),
                    "team2_id": team2.get('id'),
                    "team1_name": team1.get('name'),
                    "team2_name": team2.get('name'),
                    "region": region,
                    "team1_score": 0,
                    "team2_score": 0,
                    "winner_id": None,
                    "status": MatchStatus.SCHEDULED,
                    "is_live": False,
                    "scheduled_time": (datetime.utcnow() + timedelta(minutes=30 * (i + 1))).isoformat(),
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                })
            
            return matches
        
        else:
            # Simple random bracket
            random.shuffle(teams)
            matches = []
            
            for i in range(0, min(len(teams), max_teams), 2):
                if i + 1 < len(teams):
                    team1 = teams[i]
                    team2 = teams[i + 1]
                    match_num = (i // 2) + 1
                    
                    match_id = str(uuid4())
                    matches.append({
                        "id": match_id,
                        "tournament_id": tournament_id,
                        "round_number": 1,
                        "match_number": match_num,
                        "team1_id": team1.get('id'),
                        "team2_id": team2.get('id'),
                        "team1_name": team1.get('name'),
                        "team2_name": team2.get('name'),
                        "region": 'GLOBAL',
                        "team1_score": 0,
                        "team2_score": 0,
                        "winner_id": None,
                        "status": MatchStatus.SCHEDULED,
                        "is_live": False,
                        "scheduled_time": (datetime.utcnow() + timedelta(minutes=30 * match_num)).isoformat(),
                        "created_at": datetime.utcnow().isoformat(),
                        "updated_at": datetime.utcnow().isoformat()
                    })
            
            return matches
    
    @staticmethod
    def generate_empty_rounds(tournament_id: str, current_round: int, total_rounds: int, match_count: int, region: str = 'GLOBAL') -> List[Dict]:
        """Generate empty matches for future rounds"""
        matches = []
        
        for round_num in range(current_round + 1, total_rounds + 1):
            matches_in_round = max(1, match_count // (2 ** (round_num - 1)))
            
            for match_num in range(1, matches_in_round + 1):
                match_id = str(uuid4())
                matches.append({
                    "id": match_id,
                    "tournament_id": tournament_id,
                    "round_number": round_num,
                    "match_number": match_num,
                    "team1_id": None,
                    "team2_id": None,
                    "team1_name": "TBD",
                    "team2_name": "TBD",
                    "region": region,
                    "team1_score": 0,
                    "team2_score": 0,
                    "winner_id": None,
                    "status": MatchStatus.PENDING,
                    "is_live": False,
                    "scheduled_time": None,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                })
        
        return matches
    
    @staticmethod
    def progress_winners_to_next_round(tournament_id: str, completed_round: int) -> bool:
        """Progress winners from completed round to next round"""
        try:
            # Get completed matches from the round
            completed_matches = DatabaseService.select(
                "matches",
                f"tournament_id=eq.'{tournament_id}'&round_number=eq.{completed_round}&status=eq.completed&order=match_number.asc"
            )
            
            if not completed_matches:
                return False
            
            # Get next round matches
            next_round = completed_round + 1
            next_round_matches = DatabaseService.select(
                "matches",
                f"tournament_id=eq.'{tournament_id}'&round_number=eq.{next_round}&order=match_number.asc"
            )
            
            if not next_round_matches:
                return False
            
            # Pair winners for next round
            winners = []
            for match in completed_matches:
                if match.get('winner_id'):
                    winners.append(match.get('winner_id'))
            
            # Fill next round matches with winners
            for i, next_match in enumerate(next_round_matches):
                match_update = {}
                
                if i * 2 < len(winners):
                    match_update["team1_id"] = winners[i * 2]
                    match_update["team1_name"] = "Winner"
                
                if i * 2 + 1 < len(winners):
                    match_update["team2_id"] = winners[i * 2 + 1]
                    match_update["team2_name"] = "Winner"
                
                if match_update:
                    match_update["status"] = MatchStatus.SCHEDULED
                    match_update["updated_at"] = datetime.utcnow().isoformat()
                    
                    # Schedule the match
                    if not next_match.get('scheduled_time'):
                        match_update["scheduled_time"] = (datetime.utcnow() + timedelta(minutes=15 * (i + 1))).isoformat()
                    
                    DatabaseService.update("matches", match_update, "id", next_match['id'])
            
            # Update tournament current round
            DatabaseService.update(
                "tournaments",
                {"current_round": next_round, "updated_at": datetime.utcnow().isoformat()},
                "id",
                tournament_id
            )
            
            logger.info(f"✅ Progressed tournament {tournament_id} to round {next_round}")
            return True
            
        except Exception as e:
            logger.error(f"Error progressing winners: {e}")
            return False
    
    @staticmethod
    def check_and_progress_round(tournament_id: str, round_number: int) -> bool:
        """Check if round is complete and progress to next round"""
        try:
            # Get all matches for this round
            round_matches = DatabaseService.select(
                "matches",
                f"tournament_id=eq.'{tournament_id}'&round_number=eq.{round_number}"
            )
            
            if not round_matches:
                return False
            
            # Check if all matches are completed
            all_completed = all(m.get('status') == MatchStatus.COMPLETED for m in round_matches)
            
            if all_completed:
                # Progress to next round
                return TournamentService.progress_winners_to_next_round(tournament_id, round_number)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking round progression: {e}")
            return False
    
    @staticmethod
    def get_tournament_bracket(tournament_id: str) -> Dict[str, Any]:
        """Get complete tournament bracket structure"""
        try:
            # Get tournament
            tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
            if not tournaments:
                return None
            
            tournament = tournaments[0]
            
            # Get teams
            teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament_id}'")
            
            # Get matches
            matches = DatabaseService.select(
                "matches",
                f"tournament_id=eq.'{tournament_id}'&order=round_number.asc,match_number.asc"
            )
            
            # Group matches by round
            rounds = {}
            for match in matches:
                round_num = match.get('round_number')
                if round_num not in rounds:
                    rounds[round_num] = []
                rounds[round_num].append(match)
            
            # Build bracket structure
            bracket_rounds = []
            total_rounds = tournament.get('total_rounds', 1)
            
            for round_num in sorted(rounds.keys()):
                round_matches = rounds[round_num]
                round_data = {
                    "round_number": round_num,
                    "name": TournamentService.get_round_name(round_num, total_rounds),
                    "matches": []
                }
                
                for match in round_matches:
                    # Find team details
                    team1 = next((t for t in teams if t.get('id') == match.get('team1_id')), {})
                    team2 = next((t for t in teams if t.get('id') == match.get('team2_id')), {})
                    
                    match_data = {
                        "id": match.get('id'),
                        "match_number": match.get('match_number'),
                        "team1": {
                            "id": team1.get('id'),
                            "name": match.get('team1_name') or team1.get('name', 'TBD'),
                            "captain": team1.get('captain_name'),
                            "score": match.get('team1_score', 0)
                        },
                        "team2": {
                            "id": team2.get('id'),
                            "name": match.get('team2_name') or team2.get('name', 'TBD'),
                            "captain": team2.get('captain_name'),
                            "score": match.get('team2_score', 0)
                        },
                        "winner_id": match.get('winner_id'),
                        "status": match.get('status'),
                        "is_live": match.get('is_live', False),
                        "scheduled_time": match.get('scheduled_time'),
                        "region": match.get('region', 'GLOBAL')
                    }
                    
                    round_data["matches"].append(match_data)
                
                bracket_rounds.append(round_data)
            
            # Fill empty rounds if needed
            for round_num in range(1, total_rounds + 1):
                if round_num not in rounds:
                    matches_in_round = max(1, tournament.get('max_teams', 16) // (2 ** (round_num - 1)))
                    round_matches = []
                    
                    for match_num in range(1, matches_in_round + 1):
                        round_matches.append({
                            "id": f"empty_{round_num}_{match_num}",
                            "match_number": match_num,
                            "team1": {"name": "TBD", "score": 0},
                            "team2": {"name": "TBD", "score": 0},
                            "winner_id": None,
                            "status": MatchStatus.PENDING,
                            "is_live": False,
                            "scheduled_time": None,
                            "region": 'GLOBAL'
                        })
                    
                    bracket_rounds.append({
                        "round_number": round_num,
                        "name": TournamentService.get_round_name(round_num, total_rounds),
                        "matches": round_matches
                    })
            
            # Sort rounds by round number
            bracket_rounds.sort(key=lambda x: x['round_number'])
            
            return {
                "tournament": {
                    "id": tournament.get('id'),
                    "name": tournament.get('name'),
                    "game": tournament.get('game'),
                    "status": tournament.get('status'),
                    "current_round": tournament.get('current_round', 1),
                    "total_rounds": total_rounds,
                    "region_lock": tournament.get('region_lock', False),
                    "max_teams": tournament.get('max_teams'),
                    "team_count": len(teams),
                    "start_date": tournament.get('start_date'),
                    "prize_pool": tournament.get('prize_pool')
                },
                "teams": teams,
                "rounds": bracket_rounds,
                "has_region_lock": tournament.get('region_lock', False)
            }
            
        except Exception as e:
            logger.error(f"Error getting tournament bracket: {e}")
            return None

# ========== PROOF VERIFICATION SERVICE ==========
class ProofService:
    """Service for proof verification and auto-completion"""
    
    @staticmethod
    def extract_score_from_description(description: str) -> Optional[Tuple[int, int]]:
        """Extract score from proof description"""
        try:
            # Look for patterns like "13-7", "13:7", "won 13-7", "score 13-7"
            import re
            pattern = r'(\d+)\s*[-:]\s*(\d+)'
            match = re.search(pattern, description)
            if match:
                return int(match.group(1)), int(match.group(2))
        except:
            pass
        return None
    
    @staticmethod
    def check_auto_completion(match_id: str) -> bool:
        """Check if match can be auto-completed based on proofs"""
        try:
            # Get all proofs for this match
            proofs = DatabaseService.select("proofs", f"match_id=eq.'{match_id}'")
            
            if not proofs or len(proofs) < 2:
                return False
            
            # Group proofs by team
            team_proofs = {}
            for proof in proofs:
                team_name = proof.get('team_name')
                if team_name:
                    if team_name not in team_proofs:
                        team_proofs[team_name] = []
                    team_proofs[team_name].append(proof)
            
            # Need proofs from at least 2 different teams
            if len(team_proofs) < 2:
                return False
            
            # Check if all verified proofs agree on score
            verified_proofs = [p for p in proofs if p.get('status') == ProofStatus.VERIFIED]
            
            if len(verified_proofs) >= 2:
                scores = []
                for proof in verified_proofs:
                    score = ProofService.extract_score_from_description(proof.get('description', ''))
                    if score:
                        scores.append(score)
                
                # Check if all scores match
                if len(scores) >= 2 and all(s == scores[0] for s in scores):
                    # Auto-complete match
                    return ProofService.auto_complete_match(match_id, scores[0])
            
            # Check pending proofs for matching scores
            pending_proofs = [p for p in proofs if p.get('status') == ProofStatus.PENDING]
            if len(pending_proofs) >= 2:
                scores = []
                for proof in pending_proofs:
                    score = ProofService.extract_score_from_description(proof.get('description', ''))
                    if score:
                        scores.append(score)
                
                # If we have at least 2 matching scores from different teams
                if len(scores) >= 2:
                    # Check if we have consistent scores from different teams
                    team_scores = {}
                    for proof in pending_proofs:
                        team = proof.get('team_name')
                        score = ProofService.extract_score_from_description(proof.get('description', ''))
                        if team and score:
                            if team not in team_scores:
                                team_scores[team] = []
                            team_scores[team].append(score)
                    
                    # Check if we have consistent scores across teams
                    consistent_scores = set()
                    for team, score_list in team_scores.items():
                        if score_list:
                            consistent_scores.add(tuple(score_list[0]))
                    
                    if len(consistent_scores) == 1:
                        # All teams agree on the score
                        winning_score = list(consistent_scores)[0]
                        # Auto-verify these proofs
                        for proof in pending_proofs:
                            DatabaseService.update(
                                "proofs",
                                {"status": ProofStatus.VERIFIED, "reviewed_at": datetime.utcnow().isoformat()},
                                "id",
                                proof['id']
                            )
                        
                        return ProofService.auto_complete_match(match_id, winning_score)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking auto-completion: {e}")
            return False
    
    @staticmethod
    def auto_complete_match(match_id: str, score: Tuple[int, int]) -> bool:
        """Auto-complete match with given score"""
        try:
            # Get match
            matches = DatabaseService.select("matches", f"id=eq.'{match_id}'")
            if not matches:
                return False
            
            match = matches[0]
            team1_score, team2_score = score
            
            # Determine winner
            winner_id = None
            if team1_score > team2_score:
                winner_id = match.get('team1_id')
            elif team2_score > team1_score:
                winner_id = match.get('team2_id')
            else:
                # Tie - cannot auto-complete
                return False
            
            # Update match
            update_data = {
                "team1_score": team1_score,
                "team2_score": team2_score,
                "winner_id": winner_id,
                "status": MatchStatus.COMPLETED,
                "is_live": False,
                "completed_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            DatabaseService.update("matches", update_data, "id", match_id)
            
            # Check round progression
            tournament_id = match.get('tournament_id')
            round_number = match.get('round_number')
            
            # Update tournament stats
            TournamentService.check_and_progress_round(tournament_id, round_number)
            
            logger.info(f"✅ Auto-completed match {match_id} with score {team1_score}-{team2_score}")
            return True
            
        except Exception as e:
            logger.error(f"Error auto-completing match: {e}")
            return False

# ========== MIDDLEWARE ==========
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = datetime.utcnow()
    
    try:
        response = await call_next(request)
        process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(
            f"{request.method} {request.url.path} "
            f"{response.status_code} {process_time:.2f}ms"
        )
        
        return response
    except Exception as e:
        logger.error(f"Request error: {str(e)}")
        raise

# ========== HEALTH & STATUS ==========
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "XTourney API v2.0",
        "version": Config.API_VERSION,
        "status": "running",
        "environment": Config.ENVIRONMENT,
        "docs": "/docs",
        "health": "/api/health",
        "features": ["auto-brackets", "region-lock", "proof-verification", "auto-progression"]
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db_check = DatabaseService.select("users", "limit=1")
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected" if db_check is not None else "disconnected",
            "version": Config.API_VERSION,
            "features": {
                "auto_brackets": True,
                "region_lock": True,
                "proof_verification": True,
                "auto_progression": True
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )

# ========== TOURNAMENT ENDPOINTS ==========
@app.post("/api/tournaments")
async def create_tournament(
    request: TournamentCreate,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Create a new tournament with region lock support"""
    try:
        # Validate server exists if specified
        if request.discord_server_id:
            bot_servers = DatabaseService.select("bot_servers", f"server_id=eq.'{request.discord_server_id}'")
            if not bot_servers:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Discord server not found"
                )
        
        # Create tournament ID
        tournament_id = str(uuid4())
        
        # Calculate total rounds
        total_rounds = TournamentService.calculate_total_rounds(request.max_teams)
        
        # Create tournament
        tournament_data = {
            "id": tournament_id,
            "name": request.name,
            "game": request.game,
            "description": request.description,
            "max_teams": request.max_teams,
            "start_date": request.start_date,
            "discord_server_id": request.discord_server_id,
            "bracket_type": request.bracket_type,
            "max_players_per_team": request.max_players_per_team,
            "region": request.region,
            "region_lock": request.region_lock,
            "auto_matchmaking": request.auto_matchmaking,
            "prize_pool": request.prize_pool,
            "status": TournamentStatus.REGISTRATION,
            "current_round": 1,
            "total_rounds": total_rounds,
            "created_by": current_user['id'],
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = DatabaseService.insert("tournaments", tournament_data, admin=True)
        
        if result:
            # Update server tournament count
            if request.discord_server_id:
                server_tournaments = DatabaseService.select("tournaments", f"discord_server_id=eq.'{request.discord_server_id}'")
                
                server_update = {
                    "tournament_count": len(server_tournaments) if server_tournaments else 1,
                    "last_updated": datetime.utcnow().isoformat()
                }
                DatabaseService.update("bot_servers", server_update, "server_id", request.discord_server_id)
            
            return {
                "success": True,
                "tournament_id": tournament_id,
                "message": "Tournament created successfully",
                "region_lock": request.region_lock,
                "total_rounds": total_rounds
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create tournament"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create tournament error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating tournament"
        )

@app.post("/api/tournaments/{tournament_id}/start")
async def start_tournament(
    tournament_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Start tournament and generate bracket"""
    try:
        # Get tournament
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if tournament can be started
        if tournament.get('status') != TournamentStatus.REGISTRATION:
            raise HTTPException(
                status_code=400,
                detail=f"Tournament is already {tournament.get('status')}"
            )
        
        # Get registered teams
        teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament_id}'")
        
        if len(teams) < 2:
            raise HTTPException(
                status_code=400,
                detail="Need at least 2 teams to start tournament"
            )
        
        # Generate bracket based on tournament settings
        max_teams = tournament.get('max_teams', 16)
        region_lock = tournament.get('region_lock', False)
        auto_matchmaking = tournament.get('auto_matchmaking', True)
        
        matches = []
        
        if region_lock:
            # Generate region-locked bracket
            bracket_structure = TournamentService.generate_region_locked_bracket(teams, tournament_id, max_teams)
            
            # Save region bracket matches
            for region, region_data in bracket_structure.get('region_brackets', {}).items():
                for match in region_data.get('matches', []):
                    DatabaseService.insert("matches", match, admin=True)
                    matches.append(match)
            
            # Generate empty rounds for each region
            for region, region_data in bracket_structure.get('region_brackets', {}).items():
                region_rounds = region_data.get('total_rounds', 1)
                empty_matches = TournamentService.generate_empty_rounds(
                    tournament_id, 1, region_rounds, len(region_data.get('teams', [])), region
                )
                for match in empty_matches:
                    DatabaseService.insert("matches", match, admin=True)
                    matches.append(match)
            
        else:
            # Generate global bracket
            first_round_matches = TournamentService.generate_global_bracket(
                teams, tournament_id, max_teams, auto_matchmaking
            )
            
            # Save first round matches
            for match in first_round_matches:
                DatabaseService.insert("matches", match, admin=True)
                matches.append(match)
            
            # Generate empty future rounds
            total_rounds = tournament.get('total_rounds', 1)
            empty_matches = TournamentService.generate_empty_rounds(
                tournament_id, 1, total_rounds, max_teams
            )
            
            for match in empty_matches:
                DatabaseService.insert("matches", match, admin=True)
                matches.append(match)
        
        # Update tournament status
        update_data = {
            "status": TournamentStatus.ONGOING,
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "team_count": len(teams)
        }
        
        DatabaseService.update("tournaments", update_data, "id", tournament_id)
        
        return {
            "success": True,
            "message": "Tournament started successfully",
            "matches_generated": len(matches),
            "region_lock": region_lock,
            "first_round_matches": len([m for m in matches if m.get('round_number') == 1])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting tournament: {e}")
        raise HTTPException(status_code=500, detail="Error starting tournament")

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str):
    """Get tournament bracket with all rounds"""
    try:
        bracket = TournamentService.get_tournament_bracket(tournament_id)
        
        if not bracket:
            raise HTTPException(status_code=404, detail="Tournament bracket not found")
        
        return {
            "success": True,
            "bracket": bracket
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting bracket: {e}")
        raise HTTPException(status_code=500, detail="Error getting bracket")

@app.post("/api/tournaments/{tournament_id}/progress-round")
async def progress_tournament_round(
    tournament_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Manually progress tournament to next round"""
    try:
        # Get tournament
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        current_round = tournament.get('current_round', 1)
        
        # Check if round can be progressed
        success = TournamentService.check_and_progress_round(tournament_id, current_round)
        
        if success:
            return {
                "success": True,
                "message": f"Tournament progressed to round {current_round + 1}"
            }
        else:
            raise HTTPException(
                status_code=400,
                detail="Cannot progress round. Not all matches are completed."
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error progressing round: {e}")
        raise HTTPException(status_code=500, detail="Error progressing round")

# ========== MATCH ENDPOINTS ==========
@app.post("/api/matches/{match_id}/update")
async def update_match_result(
    match_id: str,
    request: MatchUpdate,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Update match result and auto-progress if needed"""
    try:
        # Get match
        matches = DatabaseService.select("matches", f"id=eq.'{match_id}'")
        if not matches:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match = matches[0]
        
        # Determine winner
        winner_id = None
        if request.team1_score > request.team2_score:
            winner_id = match.get('team1_id')
        elif request.team2_score > request.team1_score:
            winner_id = match.get('team2_id')
        else:
            raise HTTPException(status_code=400, detail="Tie scores not allowed in tournaments")
        
        # Update match
        update_data = {
            "team1_score": request.team1_score,
            "team2_score": request.team2_score,
            "winner_id": winner_id,
            "status": MatchStatus.COMPLETED,
            "is_live": False,
            "completed_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.update("matches", update_data, "id", match_id)
        
        # Check round progression
        tournament_id = match.get('tournament_id')
        round_number = match.get('round_number')
        
        TournamentService.check_and_progress_round(tournament_id, round_number)
        
        return {
            "success": True,
            "message": "Match result updated",
            "winner_id": winner_id,
            "score": f"{request.team1_score}-{request.team2_score}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating match: {e}")
        raise HTTPException(status_code=500, detail="Error updating match")

@app.post("/api/matches/{match_id}/start")
async def start_match(
    match_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Start a match"""
    try:
        # Get match
        matches = DatabaseService.select("matches", f"id=eq.'{match_id}'")
        if not matches:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match = matches[0]
        
        if match.get('status') != MatchStatus.SCHEDULED:
            raise HTTPException(
                status_code=400,
                detail=f"Match is already {match.get('status')}"
            )
        
        # Update match
        update_data = {
            "status": MatchStatus.ONGOING,
            "is_live": True,
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.update("matches", update_data, "id", match_id)
        
        return {
            "success": True,
            "message": "Match started",
            "match_id": match_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting match: {e}")
        raise HTTPException(status_code=500, detail="Error starting match")

# ========== PROOF ENDPOINTS ==========
@app.post("/api/proofs/submit")
async def submit_proof(
    request: ProofSubmission,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Submit proof for a match"""
    try:
        # Check if match exists
        matches = DatabaseService.select("matches", f"id=eq.'{request.match_id}'")
        if not matches:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match = matches[0]
        
        # Check if user is part of the match
        # This would need additional logic to verify team membership
        
        # Create proof
        proof_id = str(uuid4())
        proof_data = {
            "id": proof_id,
            "match_id": request.match_id,
            "tournament_id": request.tournament_id,
            "user_id": current_user.get('id'),
            "user_name": current_user.get('username'),
            "team_name": request.team_name,
            "image_url": request.image_url,
            "description": request.description,
            "status": ProofStatus.PENDING,
            "created_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.insert("proofs", proof_data, admin=True)
        
        # Check for auto-completion
        ProofService.check_auto_completion(request.match_id)
        
        return {
            "success": True,
            "proof_id": proof_id,
            "message": "Proof submitted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting proof: {e}")
        raise HTTPException(status_code=500, detail="Error submitting proof")

@app.post("/api/proofs/{proof_id}/verify")
async def verify_proof(
    proof_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Verify a proof"""
    try:
        # Get proof
        proofs = DatabaseService.select("proofs", f"id=eq.'{proof_id}'")
        if not proofs:
            raise HTTPException(status_code=404, detail="Proof not found")
        
        proof = proofs[0]
        
        # Update proof
        update_data = {
            "status": ProofStatus.VERIFIED,
            "reviewed_by": current_user.get('username'),
            "reviewed_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.update("proofs", update_data, "id", proof_id)
        
        # Check for auto-completion
        match_id = proof.get('match_id')
        if match_id:
            ProofService.check_auto_completion(match_id)
        
        return {
            "success": True,
            "message": "Proof verified"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying proof: {e}")
        raise HTTPException(status_code=500, detail="Error verifying proof")

@app.post("/api/proofs/{proof_id}/reject")
async def reject_proof(
    proof_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Reject a proof"""
    try:
        # Get proof
        proofs = DatabaseService.select("proofs", f"id=eq.'{proof_id}'")
        if not proofs:
            raise HTTPException(status_code=404, detail="Proof not found")
        
        # Update proof
        update_data = {
            "status": ProofStatus.REJECTED,
            "reviewed_by": current_user.get('username'),
            "reviewed_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.update("proofs", update_data, "id", proof_id)
        
        return {
            "success": True,
            "message": "Proof rejected"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting proof: {e}")
        raise HTTPException(status_code=500, detail="Error rejecting proof")

# ========== TEAM ENDPOINTS ==========
@app.post("/api/teams/register")
async def register_team(
    request: TeamRegister,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Register a team for tournament"""
    try:
        # Check if tournament exists
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{request.tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if tournament is accepting registrations
        if tournament.get('status') != TournamentStatus.REGISTRATION:
            raise HTTPException(
                status_code=400,
                detail="Tournament is not accepting registrations"
            )
        
        # Check team limit
        teams = DatabaseService.select("teams", f"tournament_id=eq.'{request.tournament_id}'")
        if len(teams) >= tournament.get('max_teams', 16):
            raise HTTPException(
                status_code=400,
                detail="Tournament is full"
            )
        
        # Check if team name is unique in tournament
        existing_teams = DatabaseService.select(
            "teams", 
            f"tournament_id=eq.'{request.tournament_id}'&name=eq.{request.name}"
        )
        if existing_teams:
            raise HTTPException(
                status_code=400,
                detail="Team name already taken in this tournament"
            )
        
        # Create team
        team_id = str(uuid4())
        team_data = {
            "id": team_id,
            "tournament_id": request.tournament_id,
            "name": request.name,
            "captain_discord_id": request.captain_discord_id,
            "captain_name": current_user.get('username'),
            "region": request.region,
            "members": json.dumps(request.members),
            "status": "registered",
            "created_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.insert("teams", team_data, admin=True)
        
        # Update tournament team count
        update_data = {
            "team_count": len(teams) + 1,
            "updated_at": datetime.utcnow().isoformat()
        }
        DatabaseService.update("tournaments", update_data, "id", request.tournament_id)
        
        return {
            "success": True,
            "team_id": team_id,
            "message": "Team registered successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering team: {e}")
        raise HTTPException(status_code=500, detail="Error registering team")

# ========== STATS ENDPOINTS ==========
@app.get("/api/stats/real")
async def get_real_stats():
    """Get real platform statistics"""
    try:
        # Get active servers
        active_servers = DatabaseService.select("bot_servers", "is_active=eq.true")
        
        # Get active tournaments
        active_tournaments = DatabaseService.select(
            "tournaments", 
            f"status=in.({TournamentStatus.REGISTRATION},{TournamentStatus.ONGOING})"
        )
        
        # Get live matches
        live_matches = DatabaseService.select("matches", "is_live=eq.true")
        
        # Calculate total players (estimate)
        total_players = 0
        for server in active_servers:
            total_players += server.get('member_count', 0)
        
        return {
            "success": True,
            "stats": {
                "connected_servers": len(active_servers),
                "active_tournaments": len(active_tournaments),
                "live_matches": len(live_matches),
                "total_players": total_players
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {
            "success": True,
            "stats": {
                "connected_servers": 0,
                "active_tournaments": 0,
                "live_matches": 0,
                "total_players": 0
            }
        }

@app.get("/api/tournaments/public")
async def get_public_tournaments():
    """Get public tournaments for display"""
    try:
        # Get active tournaments
        tournaments = DatabaseService.select(
            "tournaments", 
            f"status=in.({TournamentStatus.REGISTRATION},{TournamentStatus.ONGOING})&order=created_at.desc&limit=20"
        )
        
        # Get team counts for each tournament
        for tournament in tournaments:
            teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament['id']}'")
            tournament['team_count'] = len(teams)
        
        return {
            "success": True,
            "tournaments": tournaments,
            "count": len(tournaments)
        }
        
    except Exception as e:
        logger.error(f"Error getting public tournaments: {e}")
        return {
            "success": True,
            "tournaments": [],
            "count": 0
        }

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/server-stats")
async def update_server_stats(request: Request):
    """Update server statistics from bot"""
    try:
        data = await request.json()
        
        server_id = data.get('server_id')
        server_name = data.get('server_name')
        member_count = data.get('member_count', 0)
        is_active = data.get('is_active', True)
        
        if not server_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Server ID required"
            )
        
        # Clean server name
        if server_name:
            server_name = server_name[:100]
        else:
            server_name = "Unknown Server"
        
        # Check if server exists
        existing_servers = DatabaseService.select("bot_servers", f"server_id=eq.'{server_id}'")
        
        current_time = datetime.utcnow().isoformat()
        
        if existing_servers:
            # Update existing server
            update_data = {
                "server_name": server_name,
                "member_count": member_count,
                "is_active": is_active,
                "last_updated": current_time
            }
            
            icon_url = data.get('icon_url')
            if icon_url:
                update_data["icon_url"] = icon_url
            
            DatabaseService.update("bot_servers", update_data, "server_id", server_id)
            logger.info(f"✅ Updated server {server_name} ({server_id})")
        else:
            # Create new server entry
            server_data = {
                "server_id": server_id,
                "server_name": server_name,
                "member_count": member_count,
                "is_active": is_active,
                "created_at": current_time,
                "last_updated": current_time
            }
            
            icon_url = data.get('icon_url')
            if icon_url:
                server_data["icon_url"] = icon_url
            
            DatabaseService.insert("bot_servers", server_data, admin=True)
            logger.info(f"✅ Created new server {server_name} ({server_id})")
        
        return {
            "success": True, 
            "message": "Server stats updated",
            "server_id": server_id,
            "server_name": server_name
        }
        
    except Exception as e:
        logger.error(f"Server stats error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating server statistics"
        )

# ========== AUTO-COMPLETION ENDPOINTS ==========
@app.post("/api/tournaments/{tournament_id}/auto-complete-config")
async def update_auto_complete_config(
    tournament_id: str,
    request: TournamentAutoCompleteConfig,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Update auto-completion configuration for tournament"""
    try:
        # Get tournament
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        # Store configuration (could be in a separate table)
        # For now, we'll just log it
        logger.info(f"Auto-complete config updated for tournament {tournament_id}: {request.dict()}")
        
        return {
            "success": True,
            "message": "Auto-complete configuration updated"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating auto-complete config: {e}")
        raise HTTPException(status_code=500, detail="Error updating configuration")

# ========== ERROR HANDLERS ==========
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "detail": exc.detail,
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "detail": "Internal server error",
            "path": request.url.path
        }
    )

# ========== BACKGROUND TASKS ==========
async def auto_check_round_progression():
    """Background task to auto-check and progress rounds"""
    while True:
        try:
            # Get ongoing tournaments
            ongoing_tournaments = DatabaseService.select(
                "tournaments", 
                f"status=eq.{TournamentStatus.ONGOING}"
            )
            
            for tournament in ongoing_tournaments:
                tournament_id = tournament.get('id')
                current_round = tournament.get('current_round', 1)
                
                # Check and progress round
                TournamentService.check_and_progress_round(tournament_id, current_round)
            
            # Wait 1 minute before next check
            await asyncio.sleep(60)
            
        except Exception as e:
            logger.error(f"Error in auto round progression: {e}")
            await asyncio.sleep(60)

async def auto_check_proof_completion():
    """Background task to auto-check proof completion"""
    while True:
        try:
            # Get ongoing matches
            ongoing_matches = DatabaseService.select(
                "matches",
                "status=eq.ongoing&is_live=eq.true"
            )
            
            for match in ongoing_matches:
                match_id = match.get('id')
                
                # Check for auto-completion
                ProofService.check_auto_completion(match_id)
            
            # Wait 30 seconds before next check
            await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in auto proof completion: {e}")
            await asyncio.sleep(30)

# ========== START BACKGROUND TASKS ==========
@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup"""
    import asyncio
    
    # Start background tasks
    asyncio.create_task(auto_check_round_progression())
    asyncio.create_task(auto_check_proof_completion())
    
    logger.info("✅ Background tasks started")

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    
    # Development server
    if Config.ENVIRONMENT == "development":
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=int(os.getenv("PORT", 8000)),
            reload=True,
            log_level="info"
        )
    else:
        # Production server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=int(os.getenv("PORT", 8000)),
            workers=int(os.getenv("WORKERS", 4)),
            log_level="warning"
        )
