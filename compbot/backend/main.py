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
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, validator
import jwt
from uuid import uuid4
import re
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
import redis.asyncio as redis
# ========== SETUP LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== LIFECYCLE MANAGEMENT ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    logger.info("🚀 Starting XTourney API")
    logger.info(f"📊 Environment: {os.getenv('ENVIRONMENT', 'development')}")
    yield
    # Shutdown
    logger.info("🛑 Shutting down XTourney API")

# ========== APP INITIALIZATION ==========
app = FastAPI(
    title="XTourney API", 
    version="10.0.0",
    description="Professional Esports Tournament Platform",
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
    API_VERSION = "v1"
    
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
    bracket_type: str = Field(default="single_elimination")
    max_players_per_team: int = Field(default=5, ge=1, le=10)
    region: str = Field(default="global")
    prize_pool: Optional[str] = Field(default="", max_length=200)
    
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
                else:
                    raise ValueError(f"Invalid method: {method}")
                
                if response.status_code in [200, 201]:
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
            "exp": datetime.utcnow() + timedelta(days=7)  # Short-lived access token
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
            "expires_in": 7 * 24 * 60 * 60  # 7 days in seconds
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

# ========== DISCORD API SERVICE ==========
class DiscordAPIService:
    """Discord API integration service"""
    
    @staticmethod
    def exchange_code(code: str, redirect_uri: str) -> Dict:
        """Exchange Discord authorization code for tokens"""
        try:
            token_data = {
                'client_id': Config.DISCORD_CLIENT_ID,
                'client_secret': Config.DISCORD_CLIENT_SECRET,
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri
            }
            
            response = requests.post(
                'https://discord.com/api/oauth2/token',
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Discord token exchange failed: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Discord authentication failed"
                )
            
            return response.json()
        except requests.exceptions.Timeout:
            logger.error("Discord API timeout")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Discord API timeout"
            )
        except Exception as e:
            logger.error(f"Discord API error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Discord API error"
            )
    
    @staticmethod
    def get_user_info(access_token: str) -> Dict:
        """Get Discord user information"""
        try:
            response = requests.get(
                'https://discord.com/api/users/@me',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get Discord user info: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get Discord user information"
                )
            
            return response.json()
        except Exception as e:
            logger.error(f"Error getting Discord user info: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error getting Discord user information"
            )
    
    @staticmethod
    def get_user_guilds(access_token: str) -> List[Dict]:
        """Get user's Discord guilds"""
        try:
            response = requests.get(
                'https://discord.com/api/users/@me/guilds',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to get Discord guilds: {response.text}")
                return []
            
            return response.json()
        except Exception as e:
            logger.warning(f"Error getting Discord guilds: {str(e)}")
            return []
    
    @staticmethod
    def get_guild_member(guild_id: str, user_id: str, access_token: str) -> Optional[Dict]:
        """Get guild member information"""
        try:
            response = requests.get(
                f'https://discord.com/api/guilds/{guild_id}/members/{user_id}',
                headers={'Authorization': f'Bot {Config.DISCORD_CLIENT_SECRET}'},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.warning(f"Error getting guild member: {str(e)}")
            return None

# ========== RATE LIMITING ==========
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis

async def init_redis():
    """Initialize Redis for rate limiting"""
    redis_client = redis.from_url(
        "redis://localhost:6379",
        encoding="utf-8",
        decode_responses=True
    )
    await FastAPILimiter.init(redis_client)

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
        "message": "XTourney API",
        "version": Config.API_VERSION,
        "status": "running",
        "environment": Config.ENVIRONMENT,
        "docs": "/docs",
        "health": "/api/health"
    }

@app.get("/api/health", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db_check = DatabaseService.select("users", "limit=1")
        
        # Check Discord API (lightweight endpoint)
        discord_check = requests.get(
            "https://discord.com/api/v10/users/@me",
            headers={"Authorization": f"Bot {Config.DISCORD_CLIENT_SECRET}"},
            timeout=5
        )
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected" if db_check is not None else "disconnected",
            "discord_api": "connected" if discord_check.status_code in [200, 401] else "disconnected",
            "version": Config.API_VERSION
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )

# ========== AUTH ENDPOINTS ==========
@app.post("/api/auth/discord/token", response_model=Dict, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def discord_auth_token(request: DiscordAuthRequest):
    """Exchange Discord OAuth2 code for JWT tokens"""
    try:
        # Exchange code for Discord tokens
        discord_tokens = DiscordAPIService.exchange_code(
            request.code, 
            request.redirect_uri or Config.FRONTEND_URL
        )
        
        access_token = discord_tokens.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No access token received from Discord"
            )
        
        # Get user info from Discord
        user_data = DiscordAPIService.get_user_info(access_token)
        
        if 'id' not in user_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user data from Discord"
            )
        
        discord_id = user_data['id']
        discord_username = user_data.get('global_name') or user_data['username']
        
        # Check if user exists in our database
        existing_users = DatabaseService.select("users", f"discord_id=eq.'{discord_id}'")
        
        if existing_users:
            # Update existing user
            user = existing_users[0]
            user_id = user['id']
            
            update_data = {
                "username": discord_username,
                "last_login": datetime.utcnow().isoformat()
            }
            
            if user_data.get('avatar'):
                update_data["avatar_url"] = f"https://cdn.discordapp.com/avatars/{discord_id}/{user_data['avatar']}.png"
            
            if user_data.get('email'):
                update_data["email"] = user_data.get('email')
            
            DatabaseService.update("users", update_data, "id", user_id)
            
        else:
            # Create new user
            user_id = str(uuid4())
            user_db = {
                "id": user_id,
                "discord_id": discord_id,
                "username": discord_username,
                "email": user_data.get("email", ""),
                "avatar_url": f"https://cdn.discordapp.com/avatars/{discord_id}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat(),
                "is_verified": True
            }
            
            DatabaseService.insert("users", user_db, admin=True)
        
        # Get user's guilds where bot is present
        user_guilds = DiscordAPIService.get_user_guilds(access_token)
        
        # Get bot servers from database
        bot_servers = DatabaseService.select("bot_servers", "is_active=eq.true")
        bot_server_ids = [s['server_id'] for s in bot_servers] if bot_servers else []
        
        # Filter and format servers
        servers = []
        for guild in user_guilds[:50]:  # Limit to 50 guilds
            if guild['id'] in bot_server_ids:
                permissions = int(guild.get('permissions', 0))
                if permissions & 0x8 or permissions & 0x20:  # Admin or Manage Server
                    server_info = next((s for s in bot_servers if s['server_id'] == guild['id']), None)
                    
                    servers.append({
                        "id": guild['id'],
                        "name": server_info['server_name'] if server_info else guild['name'],
                        "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon')}.png" if guild.get('icon') else None,
                        "permissions": permissions,
                        "member_count": server_info.get('member_count', 0) if server_info else 0,
                        "tournament_count": server_info.get('tournament_count', 0) if server_info else 0
                    })
        
        # Create JWT tokens
        tokens = AuthService.create_tokens({
            "id": user_id,
            "username": discord_username,
            "discord_id": discord_id,
            "email": user_data.get("email"),
            "account_type": "discord"
        })
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": discord_username,
                "avatar": f"https://cdn.discordapp.com/avatars/{discord_id}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
                "discord_id": discord_id,
                "email": user_data.get("email"),
                "account_type": "discord"
            },
            **tokens,
            "servers": servers
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Discord auth error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )

@app.get("/api/auth/discord/servers", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def get_discord_servers(current_user: Dict = Depends(AuthService.get_current_user)):
    """Get user's Discord servers where bot is present"""
    try:
        discord_id = current_user.get('discord_id')
        
        if not discord_id:
            return {"success": True, "servers": []}
        
        # Get Discord access token from user session (in production, store this securely)
        # For now, we'll return servers from our database
        
        bot_servers = DatabaseService.select("bot_servers", "is_active=eq.true")
        
        if not bot_servers:
            return {"success": True, "servers": []}
        
        servers = []
        for server in bot_servers:
            servers.append({
                "id": server.get('server_id'),
                "name": server.get('server_name', 'Unknown Server'),
                "icon": server.get('icon_url'),
                "permissions": 8,  # Assume admin for now (in production, check Discord API)
                "member_count": server.get('member_count', 0),
                "tournament_count": server.get('tournament_count', 0)
            })
        
        return {
            "success": True,
            "servers": servers
        }
        
    except Exception as e:
        logger.error(f"Error getting Discord servers: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting Discord servers"
        )

# ========== TOURNAMENT ENDPOINTS ==========
@app.post("/api/tournaments", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def create_tournament(
    request: TournamentCreate,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Create a new tournament"""
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
            "prize_pool": request.prize_pool,
            "status": "registration",
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
                "message": "Tournament created successfully"
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

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/server-stats", dependencies=[Depends(RateLimiter(times=60, seconds=60))])
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

@app.get("/api/bot/servers", dependencies=[Depends(RateLimiter(times=30, seconds=60))])
async def get_bot_servers():
    """Get all servers where bot is active"""
    try:
        active_servers = DatabaseService.select("bot_servers", "is_active=eq.true&order=last_updated.desc")
        
        servers = []
        for server in active_servers:
            tournaments = DatabaseService.select("tournaments", f"discord_server_id=eq.'{server.get('server_id')}'")
            
            servers.append({
                "server_id": server.get('server_id'),
                "server_name": server.get('server_name', 'Unknown Server'),
                "member_count": server.get('member_count', 0),
                "tournament_count": len(tournaments) if tournaments else 0,
                "last_updated": server.get('last_updated'),
                "is_active": server.get('is_active', True)
            })
        
        return {
            "success": True,
            "servers": servers,
            "count": len(servers),
            "total_members": sum(s.get('member_count', 0) for s in servers)
        }
    except Exception as e:
        logger.error(f"Error getting bot servers: {str(e)}")
        return {"success": False, "servers": [], "count": 0}

# Add to your backend after the existing code

# ========== BRACKET GENERATION SERVICE ==========
class BracketService:
    """Service for generating and managing tournament brackets"""
    
    @staticmethod
    def generate_single_elimination_bracket(teams: List[Dict], tournament_id: str) -> List[Dict]:
        """Generate single elimination bracket matches"""
        matches = []
        
        # Seed teams (simple random seeding for now)
        import random
        random.shuffle(teams)
        
        # Calculate number of rounds
        team_count = len(teams)
        max_teams = 16  # Default, should come from tournament
        total_rounds = 1
        while (2 ** total_rounds) < max_teams:
            total_rounds += 1
        
        # First round matches
        round_num = 1
        matches_in_round = max_teams // 2
        
        for i in range(matches_in_round):
            team1 = teams[i * 2] if i * 2 < len(teams) else None
            team2 = teams[i * 2 + 1] if i * 2 + 1 < len(teams) else None
            
            # Create bye if odd number of teams
            if team1 and not team2:
                match_data = {
                    "id": str(uuid4()),
                    "tournament_id": tournament_id,
                    "round_number": round_num,
                    "match_number": i + 1,
                    "team1_id": team1['id'],
                    "team2_id": None,
                    "team1_score": 1,  # Auto-win for bye
                    "team2_score": 0,
                    "winner_id": team1['id'],
                    "status": "completed",
                    "is_live": False,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
            elif team1 and team2:
                match_data = {
                    "id": str(uuid4()),
                    "tournament_id": tournament_id,
                    "round_number": round_num,
                    "match_number": i + 1,
                    "team1_id": team1['id'],
                    "team2_id": team2['id'],
                    "team1_score": 0,
                    "team2_score": 0,
                    "winner_id": None,
                    "status": "scheduled",
                    "is_live": False,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
            else:
                # Empty match slot
                match_data = {
                    "id": str(uuid4()),
                    "tournament_id": tournament_id,
                    "round_number": round_num,
                    "match_number": i + 1,
                    "team1_id": None,
                    "team2_id": None,
                    "team1_score": 0,
                    "team2_score": 0,
                    "winner_id": None,
                    "status": "empty",
                    "is_live": False,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
            
            matches.append(match_data)
        
        # Generate subsequent rounds (empty for now, will be filled as winners progress)
        current_matches = matches_in_round
        for round_num in range(2, total_rounds + 1):
            matches_in_round = current_matches // 2
            for i in range(matches_in_round):
                match_data = {
                    "id": str(uuid4()),
                    "tournament_id": tournament_id,
                    "round_number": round_num,
                    "match_number": i + 1,
                    "team1_id": None,  # Will be filled by winner of previous round
                    "team2_id": None,  # Will be filled by winner of previous round
                    "team1_score": 0,
                    "team2_score": 0,
                    "winner_id": None,
                    "status": "pending",
                    "is_live": False,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                matches.append(match_data)
            current_matches = matches_in_round
        
        return matches
    
    @staticmethod
    def get_bracket_structure(tournament: Dict, teams: List[Dict], matches: List[Dict]) -> Dict:
        """Generate bracket structure for frontend display"""
        bracket_type = tournament.get('bracket_type', 'single_elimination')
        max_teams = tournament.get('max_teams', 16)
        
        # Calculate rounds
        total_rounds = 1
        while (2 ** total_rounds) < max_teams:
            total_rounds += 1
        
        rounds = []
        
        for round_num in range(1, total_rounds + 1):
            round_matches = [m for m in matches if m.get('round_number') == round_num]
            round_data = {
                "round_number": round_num,
                "name": BracketService.get_round_name(round_num, total_rounds),
                "matches": []
            }
            
            for match in round_matches:
                # Get team details
                team1 = next((t for t in teams if t.get('id') == match.get('team1_id')), None)
                team2 = next((t for t in teams if t.get('id') == match.get('team2_id')), None)
                
                match_data = {
                    "id": match.get('id'),
                    "match_number": match.get('match_number'),
                    "team1": {
                        "id": team1.get('id') if team1 else None,
                        "name": team1.get('name') if team1 else "TBD",
                        "captain": team1.get('captain_name') if team1 else None,
                        "score": match.get('team1_score', 0)
                    } if team1 else {"name": "TBD", "score": 0},
                    "team2": {
                        "id": team2.get('id') if team2 else None,
                        "name": team2.get('name') if team2 else "TBD",
                        "captain": team2.get('captain_name') if team2 else None,
                        "score": match.get('team2_score', 0)
                    } if team2 else {"name": "TBD", "score": 0},
                    "winner_id": match.get('winner_id'),
                    "status": match.get('status'),
                    "is_live": match.get('is_live', False),
                    "round": round_num
                }
                
                round_data["matches"].append(match_data)
            
            rounds.append(round_data)
        
        return {
            "type": bracket_type,
            "total_rounds": total_rounds,
            "current_round": BracketService.get_current_round(matches),
            "rounds": rounds,
            "teams": teams,
            "tournament_id": tournament.get('id'),
            "tournament_name": tournament.get('name')
        }
    
    @staticmethod
    def get_round_name(round_num: int, total_rounds: int) -> str:
        """Get human-readable round name"""
        if total_rounds == 1:
            return "Finals"
        elif total_rounds == 2:
            return "Semifinals" if round_num == 1 else "Finals"
        elif total_rounds == 3:
            if round_num == 1:
                return "Quarterfinals"
            elif round_num == 2:
                return "Semifinals"
            else:
                return "Finals"
        elif total_rounds >= 4:
            if round_num == 1:
                return "Round of 16"
            elif round_num == 2:
                return "Quarterfinals"
            elif round_num == 3:
                return "Semifinals"
            elif round_num == total_rounds:
                return "Finals"
            else:
                return f"Round {round_num}"
        return f"Round {round_num}"
    
    @staticmethod
    def get_current_round(matches: List[Dict]) -> int:
        """Get current round number"""
        if not matches:
            return 1
        
        completed_matches = [m for m in matches if m.get('status') == 'completed']
        if not completed_matches:
            return 1
        
        max_round = max([m.get('round_number', 1) for m in completed_matches])
        ongoing_matches = [m for m in matches if m.get('status') in ['scheduled', 'ongoing'] and m.get('round_number') == max_round]
        
        if ongoing_matches:
            return max_round
        return max_round + 1

# ========== BRACKET ENDPOINTS ==========
@app.post("/api/tournaments/{tournament_id}/generate-bracket")
async def generate_tournament_bracket(
    tournament_id: str,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Generate bracket for a tournament"""
    try:
        # Get tournament
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Get teams
        teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament_id}'")
        
        if len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams to generate bracket")
        
        # Check if bracket already exists
        existing_matches = DatabaseService.select("matches", f"tournament_id=eq.'{tournament_id}'")
        if existing_matches:
            raise HTTPException(status_code=400, detail="Bracket already generated")
        
        # Generate matches
        bracket_type = tournament.get('bracket_type', 'single_elimination')
        
        if bracket_type == 'single_elimination':
            matches = BracketService.generate_single_elimination_bracket(teams, tournament_id)
        
        # Save matches to database
        for match in matches:
            DatabaseService.insert("matches", match, admin=True)
        
        # Update tournament status
        DatabaseService.update("tournaments", {"status": "ongoing"}, "id", tournament_id)
        
        # Get updated bracket
        updated_matches = DatabaseService.select("matches", f"tournament_id=eq.'{tournament_id}'")
        bracket = BracketService.get_bracket_structure(tournament, teams, updated_matches)
        
        return {
            "success": True,
            "message": "Bracket generated successfully",
            "bracket": bracket,
            "match_count": len(matches)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating bracket: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating bracket")

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str):
    """Get tournament bracket"""
    try:
        # Get tournament
        tournaments = DatabaseService.select("tournaments", f"id=eq.'{tournament_id}'")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Get teams
        teams = DatabaseService.select("teams", f"tournament_id=eq.'{tournament_id}'")
        
        # Get matches
        matches = DatabaseService.select("matches", f"tournament_id=eq.'{tournament_id}'&order=round_number.asc,match_number.asc")
        
        # Generate bracket structure
        bracket = BracketService.get_bracket_structure(tournament, teams, matches)
        
        return {
            "success": True,
            "bracket": bracket,
            "tournament": {
                "id": tournament.get('id'),
                "name": tournament.get('name'),
                "game": tournament.get('game'),
                "status": tournament.get('status'),
                "start_date": tournament.get('start_date')
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting bracket: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting bracket")

@app.post("/api/matches/{match_id}/update-score")
async def update_match_score(
    match_id: str,
    request: Dict,
    current_user: Dict = Depends(AuthService.get_current_user)
):
    """Update match score and progress bracket"""
    try:
        team1_score = request.get('team1_score')
        team2_score = request.get('team2_score')
        
        if team1_score is None or team2_score is None:
            raise HTTPException(status_code=400, detail="Both scores required")
        
        # Get match
        matches = DatabaseService.select("matches", f"id=eq.'{match_id}'")
        if not matches:
            raise HTTPException(status_code=404, detail="Match not found")
        
        match = matches[0]
        tournament_id = match.get('tournament_id')
        
        # Determine winner
        winner_id = None
        if team1_score > team2_score:
            winner_id = match.get('team1_id')
        elif team2_score > team1_score:
            winner_id = match.get('team2_id')
        else:
            raise HTTPException(status_code=400, detail="Ties not allowed in tournament play")
        
        # Update match
        update_data = {
            "team1_score": team1_score,
            "team2_score": team2_score,
            "winner_id": winner_id,
            "status": "completed",
            "is_live": False,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        DatabaseService.update("matches", update_data, "id", match_id)
        
        # Progress winner to next round if applicable
        await progress_winner_to_next_round(match, winner_id)
        
        return {
            "success": True,
            "message": "Match score updated",
            "winner_id": winner_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating match score: {str(e)}")
        raise HTTPException(status_code=500, detail="Error updating match score")

async def progress_winner_to_next_round(match: Dict, winner_id: str):
    """Progress winner to next round in bracket"""
    try:
        tournament_id = match.get('tournament_id')
        round_number = match.get('round_number')
        match_number = match.get('match_number')
        
        # Determine next round match
        next_round = round_number + 1
        next_match_number = (match_number + 1) // 2  # Math for bracket progression
        
        # Find next match
        next_matches = DatabaseService.select(
            "matches", 
            f"tournament_id=eq.'{tournament_id}'&round_number=eq.{next_round}&match_number=eq.{next_match_number}"
        )
        
        if next_matches:
            next_match = next_matches[0]
            
            # Determine which team slot to fill (odd match numbers go to team1, even to team2)
            slot = "team1_id" if match_number % 2 == 1 else "team2_id"
            
            update_data = {slot: winner_id}
            if next_match.get('team1_id') and next_match.get('team2_id'):
                # Both teams filled, match can start
                update_data["status"] = "scheduled"
            
            DatabaseService.update("matches", update_data, "id", next_match['id'])
            
    except Exception as e:
        logger.error(f"Error progressing winner: {str(e)}")

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



