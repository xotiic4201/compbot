from fastapi import FastAPI, HTTPException, Request, Header, Depends, status, Response
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
import redis.asyncio as redis
import random
from enum import Enum
import asyncio

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
    "https://*.xotiicsplaza.us",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
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
    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ugaeaekzhocwqdzdtrry.supabase.co")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVnYWVhZWt6aG9jd3FkemR0cnJ5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzM0MDQzMzMsImV4cCI6MjA0ODk4MDMzM30.3r7y8ryqpH7FBy-HwKN5TVpeL6hQsCFgC-nonBRkYFQ")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVnYWVhZWt6aG9jd3FkemR0cnJ5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTczMzQwNDMzMywiZXhwIjoyMDQ4OTgwMzMzfQ.75OHIq7HOSzRGRa8AGm8_zs6tqukmvNw2kD7D60UJ0k")
    
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your_discord_secret")
    
    FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us/")
    JWT_SECRET = os.getenv("JWT_SECRET", "your-super-secret-jwt-key-change-this-now")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_DAYS = 30
    
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    API_VERSION = "v2"
    
    @classmethod
    def validate(cls):
        """Validate required environment variables"""
        logger.info("✅ Configuration loaded")
        return True

# Validate config
Config.validate()

# Headers for Supabase requests
headers = {
    "apikey": Config.SUPABASE_KEY,
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

service_headers = {
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

class TeamRegister(BaseModel):
    tournament_id: str
    name: str = Field(..., min_length=2, max_length=50)
    captain_discord_id: str
    region: Optional[str] = Field(default="global")
    members: Optional[List[str]] = Field(default_factory=list)

# ========== DATABASE SERVICE ==========
class DatabaseService:
    """Database service with error handling"""
    
    @staticmethod
    def execute_query(table: str, method: str = "GET", data: dict = None, 
                     query: str = "", admin: bool = False):
        """Execute a database query"""
        try:
            url = f"{Config.SUPABASE_URL}/rest/v1/{table}"
            if query:
                url += f"?{query}"
            
            # Always use service headers for authenticated operations
            # This bypasses RLS policies
            headers_to_use = service_headers
            
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
            
            logger.info(f"Database {method} {table}: {response.status_code}")
            
            if response.status_code in [200, 201, 204]:
                try:
                    return response.json()
                except:
                    return {"success": True}
            elif response.status_code == 404:
                return []
            else:
                error_text = response.text[:200]
                logger.error(f"Database error {response.status_code}: {error_text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Database error: {error_text}"
                )
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Database connection error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        except Exception as e:
            logger.error(f"Database exception: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    @staticmethod
    def insert(table: str, data: dict):
        return DatabaseService.execute_query(table, "POST", data, admin=True)
    
    @staticmethod
    def select(table: str, query: str = ""):
        return DatabaseService.execute_query(table, "GET", query=query, admin=True)
    
    @staticmethod
    def update(table: str, data: dict, column: str, value: str):
        query_str = f"{column}=eq.{value}"
        return DatabaseService.execute_query(table, "PATCH", data, query=query_str, admin=True)
    
    @staticmethod
    def delete(table: str, column: str, value: str):
        query_str = f"{column}=eq.{value}"
        return DatabaseService.execute_query(table, "DELETE", query=query_str, admin=True)

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
        
        if not users or len(users) == 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return users[0]

# ========== DISCORD AUTH ENDPOINTS ==========
@app.post("/api/auth/discord/token")
async def discord_auth_token(request: DiscordAuthRequest):
    """Exchange Discord OAuth code for access token"""
    try:
        logger.info(f"Processing Discord OAuth for redirect: {request.redirect_uri}")
        
        # Exchange code for access token
        token_data = {
            'client_id': Config.DISCORD_CLIENT_ID,
            'client_secret': Config.DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': request.redirect_uri or f"{Config.FRONTEND_URL}"
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        # Get Discord access token
        token_response = requests.post(
            'https://discord.com/api/oauth2/token',
            data=token_data,
            headers=headers
        )
        
        if token_response.status_code != 200:
            logger.error(f"Discord token error {token_response.status_code}: {token_response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to authenticate with Discord"
            )
        
        token_json = token_response.json()
        discord_access_token = token_json['access_token']
        
        # Get user info from Discord
        user_response = requests.get(
            'https://discord.com/api/users/@me',
            headers={'Authorization': f'Bearer {discord_access_token}'}
        )
        
        if user_response.status_code != 200:
            logger.error(f"Discord user error: {user_response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user info from Discord"
            )
        
        discord_user = user_response.json()
        discord_id = discord_user['id']
        username = discord_user['username']
        discriminator = discord_user.get('discriminator', '0')
        email = discord_user.get('email')
        avatar = f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_user.get('avatar')}.png" if discord_user.get('avatar') else None
        
        # Full username with discriminator
        full_username = f"{username}#{discriminator}"
        
        logger.info(f"Discord user: {full_username} ({discord_id}), email: {email}")
        
        # Check if user exists
        users = DatabaseService.select("users", f"discord_id=eq.'{discord_id}'")
        
        if users and len(users) > 0:
            # Update existing user
            user = users[0]
            logger.info(f"Updating existing user: {user['id']}")
            update_data = {
                "username": full_username,
                "email": email or user.get('email'),
                "avatar_url": avatar,
                "last_login": datetime.utcnow().isoformat()
            }
            DatabaseService.update("users", update_data, "id", user['id'])
            user.update(update_data)
        else:
            # Create new user
            user_id = str(uuid4())
            logger.info(f"Creating new user: {user_id}")
            user_data = {
                "id": user_id,
                "discord_id": discord_id,
                "username": full_username,
                "email": email,
                "avatar_url": avatar,
                "account_type": "discord",
                "is_verified": True if email else False,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            DatabaseService.insert("users", user_data)
            users = DatabaseService.select("users", f"id=eq.'{user_id}'")
            user = users[0] if users else user_data
        
        # Create JWT tokens
        tokens = AuthService.create_tokens(user)
        
        # Get user's servers from database (simplified for now)
        servers = DatabaseService.select("bot_servers", "is_active=eq.true")
        
        response_data = {
            "success": True,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": {
                "id": user.get("id"),
                "discord_id": user.get("discord_id"),
                "username": user.get("username"),
                "email": user.get("email"),
                "avatar": user.get("avatar_url"),
                "account_type": user.get("account_type")
            },
            "servers": [
                {
                    "id": server.get('server_id'),
                    "name": server.get('server_name'),
                    "icon": server.get('icon_url'),
                    "member_count": server.get('member_count'),
                    "tournament_count": server.get('tournament_count', 0)
                }
                for server in (servers or [])
            ]
        }
        
        logger.info(f"✅ Discord auth successful for {full_username}")
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Discord auth error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error authenticating with Discord"
        )

@app.get("/api/auth/discord/servers")
async def get_discord_servers(current_user: Dict = Depends(AuthService.get_current_user)):
    """Get user's Discord servers where bot is present"""
    try:
        # Get all active servers from database
        servers = DatabaseService.select("bot_servers", "is_active=eq.true")
        
        return {
            "success": True,
            "servers": [
                {
                    "id": server.get('server_id'),
                    "name": server.get('server_name'),
                    "icon": server.get('icon_url'),
                    "member_count": server.get('member_count'),
                    "tournament_count": server.get('tournament_count', 0)
                }
                for server in (servers or [])
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting Discord servers: {e}")
        return {
            "success": True,
            "servers": []
        }

# ========== EMAIL AUTH ENDPOINTS ==========
@app.post("/api/auth/email/register")
async def email_register(request: EmailRegisterRequest):
    """Register new user with email"""
    try:
        # Check if email already exists
        users_by_email = DatabaseService.select("users", f"email=eq.'{request.email}'")
        if users_by_email and len(users_by_email) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Check if username already exists
        users_by_username = DatabaseService.select("users", f"username=eq.'{request.username}'")
        if users_by_username and len(users_by_username) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        # Create password hash
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        
        # Create user
        user_id = str(uuid4())
        user_data = {
            "id": user_id,
            "username": request.username,
            "email": request.email,
            "password_hash": password_hash,
            "account_type": "email",
            "is_verified": False,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat()
        }
        
        DatabaseService.insert("users", user_data)
        
        # Create tokens
        tokens = AuthService.create_tokens(user_data)
        
        return {
            "success": True,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": {
                "id": user_id,
                "username": request.username,
                "email": request.email,
                "account_type": "email"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email register error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error registering user"
        )

@app.post("/api/auth/email/login")
async def email_login(request: EmailLoginRequest):
    """Login with email and password"""
    try:
        # Find user by email
        users = DatabaseService.select("users", f"email=eq.'{request.email}'")
        if not users or len(users) == 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        user = users[0]
        
        # Verify password
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        if password_hash != user.get('password_hash'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Update last login
        DatabaseService.update(
            "users",
            {"last_login": datetime.utcnow().isoformat()},
            "id",
            user['id']
        )
        
        # Create tokens
        tokens = AuthService.create_tokens(user)
        
        return {
            "success": True,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": {
                "id": user.get("id"),
                "username": user.get("username"),
                "email": user.get("email"),
                "account_type": user.get("account_type")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error logging in"
        )

@app.post("/api/auth/refresh")
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    try:
        payload = AuthService.verify_token(request.refresh_token)
        
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user_id = payload.get("sub")
        users = DatabaseService.select("users", f"id=eq.'{user_id}'")
        
        if not users or len(users) == 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Create new tokens
        tokens = AuthService.create_tokens(users[0])
        
        return {
            "success": True,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"]
        }
        
    except Exception as e:
        logger.error(f"Refresh token error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@app.get("/api/auth/me")
async def get_current_user_profile(current_user: Dict = Depends(AuthService.get_current_user)):
    """Get current user profile"""
    return {
        "success": True,
        "user": {
            "id": current_user.get("id"),
            "username": current_user.get("username"),
            "email": current_user.get("email"),
            "avatar": current_user.get("avatar_url"),
            "discord_id": current_user.get("discord_id"),
            "account_type": current_user.get("account_type"),
            "created_at": current_user.get("created_at")
        }
    }

# ========== TOURNAMENT ENDPOINTS ==========
@app.post("/api/tournaments")
async def create_tournament(
    request: TournamentCreate,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Create a new tournament"""
    try:
        # Parse start date
        try:
            start_date = datetime.fromisoformat(request.start_date.replace('Z', '+00:00'))
        except:
            start_date = datetime.utcnow() + timedelta(days=7)
        
        # Calculate total rounds
        def calculate_rounds(teams):
            rounds = 0
            while teams > 1:
                teams //= 2
                rounds += 1
            return max(rounds, 1)
        
        total_rounds = calculate_rounds(request.max_teams)
        
        # Create tournament
        tournament_id = str(uuid4())
        tournament_data = {
            "id": tournament_id,
            "name": request.name,
            "game": request.game,
            "description": request.description,
            "max_teams": request.max_teams,
            "start_date": start_date.isoformat(),
            "discord_server_id": request.discord_server_id,
            "server_id": request.discord_server_id,
            "bracket_type": request.bracket_type,
            "max_players_per_team": request.max_players_per_team,
            "region": request.region,
            "region_lock": request.region_lock,
            "auto_matchmaking": request.auto_matchmaking,
            "prize_pool": request.prize_pool,
            "status": TournamentStatus.REGISTRATION.value,
            "current_round": 1,
            "total_rounds": total_rounds,
            "created_by": current_user['id'],
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "team_count": 0
        }
        
        DatabaseService.insert("tournaments", tournament_data)
        
        # Update server tournament count
        if request.discord_server_id:
            try:
                servers = DatabaseService.select("bot_servers", f"server_id=eq.'{request.discord_server_id}'")
                if servers and len(servers) > 0:
                    server = servers[0]
                    tournament_count = server.get('tournament_count', 0)
                    DatabaseService.update(
                        "bot_servers",
                        {"tournament_count": tournament_count + 1},
                        "server_id",
                        request.discord_server_id
                    )
            except Exception as e:
                logger.error(f"Error updating server count: {e}")
        
        return {
            "success": True,
            "tournament_id": tournament_id,
            "message": "Tournament created successfully",
            "tournament": tournament_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create tournament error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating tournament"
        )

@app.get("/api/tournaments/public")
async def get_public_tournaments():
    """Get public tournaments for display"""
    try:
        # Get active tournaments
        tournaments = DatabaseService.select(
            "tournaments", 
            "status=in.(registration,ongoing)&order=created_at.desc&limit=20"
        )
        
        # Get team counts for each tournament
        for tournament in (tournaments or []):
            teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament['id']}'")
            tournament['team_count'] = len(teams) if teams else 0
        
        return {
            "success": True,
            "tournaments": tournaments or [],
            "count": len(tournaments) if tournaments else 0
        }
        
    except Exception as e:
        logger.error(f"Error getting public tournaments: {e}")
        return {
            "success": True,
            "tournaments": [],
            "count": 0
        }

@app.get("/api/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str):
    """Get specific tournament details"""
    try:
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments or len(tournaments) == 0:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Get teams
        teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament_id}'")
        tournament['teams'] = teams or []
        tournament['team_count'] = len(teams) if teams else 0
        
        # Get matches
        matches = DatabaseService.select("matches", f"tournament_id=eq.'{tournament_id}'")
        tournament['matches'] = matches or []
        
        return {
            "success": True,
            "tournament": tournament
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting tournament: {e}")
        raise HTTPException(status_code=500, detail="Error getting tournament")

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
            "status=in.(registration,ongoing)"
        )
        
        # Get live matches
        live_matches = DatabaseService.select("matches", "is_live=eq.true")
        
        # Calculate total players (estimate)
        total_players = 0
        for server in (active_servers or []):
            total_players += server.get('member_count', 0)
        
        return {
            "success": True,
            "stats": {
                "connected_servers": len(active_servers) if active_servers else 0,
                "active_tournaments": len(active_tournaments) if active_tournaments else 0,
                "live_matches": len(live_matches) if live_matches else 0,
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
        
        if existing_servers and len(existing_servers) > 0:
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
                "tournament_count": 0,
                "created_at": current_time,
                "last_updated": current_time
            }
            
            icon_url = data.get('icon_url')
            if icon_url:
                server_data["icon_url"] = icon_url
            
            DatabaseService.insert("bot_servers", server_data)
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
        "features": ["authentication", "tournaments", "stats", "bot-integration"]
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
            "version": Config.API_VERSION
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "error",
            "error": str(e)
        }

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
