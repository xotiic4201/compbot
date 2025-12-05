from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
import os
import requests
import secrets
import hashlib
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from pydantic import BaseModel, EmailStr, Field
import jwt
from uuid import uuid4
import re

app = FastAPI(title="XTourney API", version="10.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "your-service-key")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-client-secret")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us/")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

# Headers for Supabase requests
headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

admin_headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json"
}

# ========== PYDANTIC MODELS ==========
class DiscordAuthRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    token: str

class EmailRegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=8)

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
    region_filter: bool = Field(default=False)
    prize_pool: Optional[str] = Field(default="", max_length=200)

class TeamRegister(BaseModel):
    tournament_id: str
    name: str = Field(..., min_length=2, max_length=50)
    captain_discord_id: str

class ProofSubmission(BaseModel):
    tournament_id: str
    match_id: str
    description: Optional[str] = ""
    image_url: Optional[str] = None

# ========== DATABASE FUNCTIONS ==========
def supabase_insert(table: str, data: dict, admin=False):
    """Insert data into Supabase"""
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers=admin_headers if admin else headers,
            params={"select": "*"}
        )
        if response.status_code in [200, 201, 409]:
            try:
                return response.json()
            except:
                return {"success": True}
        print(f"Insert error {response.status_code}: {response.text[:200]}")
        return None
    except Exception as e:
        print(f"Insert exception: {str(e)}")
        return None

def supabase_select(table: str, query: str = "", admin=False):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        response = requests.get(url, headers=admin_headers if admin else headers)
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return []
        return []
    except Exception as e:
        print(f"Select exception: {str(e)}")
        return []

def supabase_update(table: str, data: dict, column: str, value: str, admin=False):
    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers=admin_headers if admin else headers,
            params={"select": "*"}
        )
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        print(f"Update exception: {str(e)}")
        return []

def supabase_delete(table: str, column: str, value: str, admin=False):
    try:
        response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            headers=admin_headers if admin else headers
        )
        return response.status_code == 204
    except Exception as e:
        print(f"Delete exception: {str(e)}")
        return False

# ========== JWT FUNCTIONS ==========
def create_jwt_token(data: dict):
    """Create JWT token"""
    payload = data.copy()
    payload['exp'] = datetime.utcnow() + timedelta(days=30)
    payload['iat'] = datetime.utcnow()
    
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user(authorization: str):
    """Get current user from authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        return None
    
    user_id = payload.get("sub")
    users = supabase_select("users", f"id=eq.'{user_id}'")
    
    if not users:
        return None
    
    return users[0]

# ========== PUBLIC ENDPOINTS ==========
@app.get("/")
async def root():
    return {"message": "XTourney API", "status": "running", "version": "10.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/stats/summary")
async def get_stats_summary():
    """Get overall platform statistics"""
    try:
        # Get tournaments count
        tournaments = supabase_select("tournaments", "status=in.(registration,ongoing)")
        active_tournaments = len(tournaments)
        
        # Get total teams
        total_teams = 0
        total_players = 0
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament.get('id')}")
            total_teams += len(teams)
            total_players += len(teams) * tournament.get('max_players_per_team', 5)
        
        # Get server count
        servers = supabase_select("bot_servers", "is_active=eq.true")
        connected_servers = len(servers)
        
        # Estimate live matches
        live_matches = min(total_teams // 2, 10)
        
        return {
            "success": True,
            "stats": {
                "live_matches": live_matches,
                "active_tournaments": active_tournaments,
                "connected_servers": connected_servers,
                "total_players": total_players,
                "total_teams": total_teams
            }
        }
    except Exception as e:
        print(f"Stats error: {str(e)}")
        return {
            "success": True,
            "stats": {
                "live_matches": 0,
                "active_tournaments": 0,
                "connected_servers": 0,
                "total_players": 0,
                "total_teams": 0
            }
        }

@app.get("/api/matches/live")
async def get_live_matches():
    """Get live matches"""
    try:
        tournaments = supabase_select("tournaments", "status=eq.ongoing&limit=5")
        
        matches = []
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament.get('id')}&limit=8")
            
            if len(teams) >= 2:
                for i in range(0, len(teams), 2):
                    if i + 1 < len(teams):
                        matches.append({
                            "id": f"{tournament['id']}_{i//2}",
                            "tournament_id": tournament['id'],
                            "tournament_name": tournament['name'],
                            "game": tournament['game'],
                            "status": "live",
                            "team1": {
                                "id": teams[i]['id'],
                                "name": teams[i]['name'],
                                "score": teams[i].get('score', 0)
                            },
                            "team2": {
                                "id": teams[i+1]['id'],
                                "name": teams[i+1]['name'],
                                "score": teams[i+1].get('score', 0)
                            },
                            "start_time": tournament.get('start_date'),
                            "viewers": 0,
                            "round": "Round 1"
                        })
        
        if not matches:
            # Sample data for demo
            matches = [
                {
                    "id": "demo_1",
                    "tournament_id": "demo",
                    "tournament_name": "Valorant Championship",
                    "game": "Valorant",
                    "status": "live",
                    "team1": {
                        "id": "team1",
                        "name": "Team Phoenix",
                        "score": 8
                    },
                    "team2": {
                        "id": "team2",
                        "name": "Team Dragon",
                        "score": 5
                    },
                    "start_time": datetime.utcnow().isoformat(),
                    "viewers": 1245,
                    "round": "Semi-Finals"
                }
            ]
        
        return {
            "success": True,
            "matches": matches[:10],
            "count": len(matches)
        }
    except Exception as e:
        print(f"Live matches error: {str(e)}")
        return {"success": False, "matches": [], "count": 0}

@app.get("/api/tournaments/public")
async def get_public_tournaments():
    """Get public tournaments"""
    try:
        tournaments = supabase_select("tournaments", "status=in.(registration,ongoing)&order=start_date.asc&limit=20")
        
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament.get('id')}")
            tournament['team_count'] = len(teams)
            tournament['current_teams'] = len(teams)
            tournament['progress_percent'] = int((len(teams) / tournament.get('max_teams', 16)) * 100) if tournament.get('max_teams', 16) > 0 else 0
        
        return {
            "success": True,
            "tournaments": tournaments,
            "count": len(tournaments)
        }
    except Exception as e:
        print(f"Public tournaments error: {str(e)}")
        return {"success": False, "tournaments": [], "count": 0}

# ========== AUTH ENDPOINTS ==========
@app.post("/api/auth/discord/token")
async def discord_auth_token(request: DiscordAuthRequest):
    """Exchange Discord code for token"""
    try:
        redirect_uri = request.redirect_uri or f"{FRONTEND_URL}"
        
        # Get Discord access token
        token_data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': redirect_uri
        }
        
        token_response = requests.post('https://discord.com/api/oauth2/token', data=token_data)
        
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Discord auth failed")
        
        discord_token = token_response.json()
        access_token = discord_token.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        # Get Discord user info
        user_response = requests.get('https://discord.com/api/users/@me', 
                                   headers={'Authorization': f'Bearer {access_token}'})
        user_data = user_response.json()
        
        if 'id' not in user_data:
            raise HTTPException(status_code=400, detail="Invalid user data from Discord")
        
        discord_username = user_data.get('global_name') or user_data['username']
        discord_id = user_data['id']
        
        # Check if user exists
        existing_users = supabase_select("users", f"discord_id=eq.{discord_id}")
        
        if existing_users and len(existing_users) > 0:
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
            
            supabase_update("users", update_data, "id", user_id)
            
        else:
            # Create new user
            user_uuid = str(uuid4())
            user_db = {
                "id": user_uuid,
                "discord_id": discord_id,
                "username": discord_username,
                "email": user_data.get("email", ""),
                "avatar_url": f"https://cdn.discordapp.com/avatars/{discord_id}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat(),
                "is_verified": True
            }
            
            supabase_insert("users", user_db, admin=True)
            user_id = user_uuid
        
        # Get Discord servers
        servers = []
        try:
            guilds_response = requests.get('https://discord.com/api/users/@me/guilds', 
                                         headers={'Authorization': f'Bearer {access_token}'})
            if guilds_response.status_code == 200:
                user_guilds = guilds_response.json()
                for guild in user_guilds[:20]:
                    permissions = int(guild.get('permissions', 0))
                    if permissions & 0x8 or permissions & 0x20:  # Admin or Manage Server
                        servers.append({
                            "id": guild['id'],
                            "name": guild['name'],
                            "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon')}.png" if guild.get('icon') else None,
                            "permissions": permissions
                        })
        except:
            pass
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
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
            "access_token": jwt_token,
            "servers": servers
        }
        
    except Exception as e:
        print(f"Discord auth error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/email/register")
async def email_register(request: EmailRegisterRequest):
    """Register with email"""
    try:
        # Validate username
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', request.username):
            raise HTTPException(status_code=400, detail="Invalid username format")
        
        # Check if email exists
        existing_email = supabase_select("users", f"email=ilike.'{request.email}'")
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username exists
        existing_username = supabase_select("users", f"username=ilike.'{request.username}'")
        if existing_username:
            raise HTTPException(status_code=400, detail="Username already taken")
        
        # Hash password
        hashed_password = hashlib.sha256(request.password.encode()).hexdigest()
        
        # Create user
        user_uuid = str(uuid4())
        user_db = {
            "id": user_uuid,
            "username": request.username,
            "email": request.email.lower(),
            "password_hash": hashed_password,
            "account_type": "email",
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            "is_verified": False,
            "avatar_url": f"https://ui-avatars.com/api/?name={request.username.replace(' ', '+')}&background=DC2626&color=fff"
        }
        
        result = supabase_insert("users", user_db, admin=True)
        
        if result:
            jwt_token = create_jwt_token({
                "sub": user_uuid,
                "username": request.username,
                "email": request.email,
                "account_type": "email"
            })
            
            return {
                "success": True,
                "user": {
                    "id": user_uuid,
                    "username": request.username,
                    "email": request.email,
                    "account_type": "email",
                    "avatar": f"https://ui-avatars.com/api/?name={request.username.replace(' ', '+')}&background=DC2626&color=fff"
                },
                "access_token": jwt_token
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create user")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Email register error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/email/login")
async def email_login(request: EmailLoginRequest):
    """Login with email"""
    try:
        # Find user
        users = supabase_select("users", f"email=ilike.'{request.email}'")
        
        if not users:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = users[0]
        
        # Verify password
        hashed_input = hashlib.sha256(request.password.encode()).hexdigest()
        stored_hash = user.get('password_hash')
        
        if not stored_hash or hashed_input != stored_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        supabase_update("users", {
            "last_login": datetime.utcnow().isoformat()
        }, "id", user['id'])
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user['id'],
            "username": user['username'],
            "email": user['email'],
            "account_type": user.get('account_type', 'email')
        })
        
        return {
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "account_type": user.get('account_type', 'email'),
                "avatar": user.get('avatar_url')
            },
            "access_token": jwt_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Email login error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/link-email")
async def link_email(request: LinkEmailRequest, authorization: Optional[str] = Header(None)):
    """Link email to Discord account"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    
    # Check if email already exists
    existing_email = supabase_select("users", f"email=ilike.'{request.email}'")
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Update user
    update_data = {
        "email": request.email.lower(),
        "account_type": "both"
    }
    
    result = supabase_update("users", update_data, "id", user_id)
    
    if result:
        return {"success": True, "message": "Email linked successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to link email")

@app.post("/api/auth/refresh")
async def refresh_login(request: RefreshTokenRequest):
    """Refresh token"""
    try:
        payload = verify_jwt_token(request.token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        users = supabase_select("users", f"id=eq.'{user_id}'")
        
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        
        # Create new token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": user.get('username'),
            "email": user.get('email'),
            "account_type": user.get('account_type', 'email')
        })
        
        return {
            "success": True,
            "access_token": jwt_token,
            "user": {
                "id": user_id,
                "username": user.get('username'),
                "email": user.get('email'),
                "account_type": user.get('account_type', 'email'),
                "avatar": user.get('avatar_url')
            }
        }
        
    except Exception as e:
        print(f"Refresh error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== TOURNAMENT ENDPOINTS ==========
@app.post("/api/tournaments")
async def create_tournament(request: TournamentCreate, authorization: Optional[str] = Header(None)):
    """Create a tournament"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    
    try:
        # Create tournament ID
        tournament_id = str(uuid4())
        
        # Validate start date
        try:
            start_date = datetime.fromisoformat(request.start_date.replace('Z', '+00:00'))
            if start_date < datetime.utcnow():
                raise HTTPException(status_code=400, detail="Start date must be in the future")
        except:
            raise HTTPException(status_code=400, detail="Invalid start date format")
        
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
            "region_filter": request.region_filter,
            "prize_pool": request.prize_pool,
            "status": "registration",
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament_data, admin=True)
        
        if result:
            # Update server stats
            if request.discord_server_id:
                server_stats = {
                    "server_id": request.discord_server_id,
                    "server_name": f"Tournament: {request.name}",
                    "last_updated": datetime.utcnow().isoformat(),
                    "is_active": True
                }
                
                # Check if server exists
                existing_servers = supabase_select("bot_servers", f"server_id=eq.{request.discord_server_id}")
                if not existing_servers:
                    supabase_insert("bot_servers", server_stats, admin=True)
            
            return {
                "success": True,
                "tournament_id": tournament_id,
                "message": "Tournament created successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str, authorization: Optional[str] = Header(None)):
    """Get tournament details"""
    tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
    
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    
    tournament = tournaments[0]
    
    # Get teams
    teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
    
    # Add team count
    tournament['team_count'] = len(teams)
    tournament['current_teams'] = len(teams)
    tournament['progress_percent'] = int((len(teams) / tournament.get('max_teams', 16)) * 100) if tournament.get('max_teams', 16) > 0 else 0
    
    return {
        "success": True,
        "tournament": tournament,
        "teams": teams
    }

@app.get("/api/tournaments/{tournament_id}/public")
async def get_tournament_public(tournament_id: str):
    """Get tournament details (public)"""
    tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
    
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    
    tournament = tournaments[0]
    teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
    
    tournament['team_count'] = len(teams)
    tournament['current_teams'] = len(teams)
    tournament['progress_percent'] = int((len(teams) / tournament.get('max_teams', 16)) * 100) if tournament.get('max_teams', 16) > 0 else 0
    
    return {
        "success": True,
        "tournament": tournament,
        "teams": teams
    }

# ========== TEAM ENDPOINTS ==========
@app.post("/api/teams")
async def register_team(request: TeamRegister, authorization: Optional[str] = Header(None)):
    """Register a team"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Check if tournament exists
    tournaments = supabase_select("tournaments", f"id=eq.{request.tournament_id}")
    
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    
    tournament = tournaments[0]
    
    # Check if tournament is accepting registrations
    if tournament.get('status') != 'registration':
        raise HTTPException(status_code=400, detail="Tournament is not accepting registrations")
    
    # Check if team name is taken
    existing_teams = supabase_select("teams", f"tournament_id=eq.{request.tournament_id}&name=ilike.'{request.name}'")
    if existing_teams:
        raise HTTPException(status_code=400, detail="Team name already taken in this tournament")
    
    # Check if captain already has a team
    captain_teams = supabase_select("teams", f"captain_discord_id=eq.{request.captain_discord_id}&tournament_id=eq.{request.tournament_id}")
    if captain_teams:
        raise HTTPException(status_code=400, detail="Captain already has a team in this tournament")
    
    # Check team limit
    current_teams = supabase_select("teams", f"tournament_id=eq.{request.tournament_id}")
    if len(current_teams) >= tournament.get('max_teams', 16):
        raise HTTPException(status_code=400, detail="Tournament is full")
    
    # Create team
    team_id = str(uuid4())
    team_data = {
        "id": team_id,
        "tournament_id": request.tournament_id,
        "name": request.name,
        "captain_discord_id": request.captain_discord_id,
        "created_at": datetime.utcnow().isoformat(),
        "status": "registered"
    }
    
    result = supabase_insert("teams", team_data, admin=True)
    
    if result:
        return {
            "success": True,
            "team_id": team_id,
            "message": "Team registered successfully"
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to register team")

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/server-stats")
async def update_server_stats(request: Request):
    """Update server stats from bot"""
    try:
        data = await request.json()
        
        server_id = data.get('server_id')
        server_name = data.get('server_name')
        member_count = data.get('member_count', 0)
        is_active = data.get('is_active', True)
        
        if not server_id:
            raise HTTPException(status_code=400, detail="Server ID required")
        
        # Check if server exists
        existing_servers = supabase_select("bot_servers", f"server_id=eq.{server_id}")
        
        if existing_servers:
            # Update
            update_data = {
                "server_name": server_name[:100] if server_name else "Unknown Server",
                "member_count": member_count,
                "is_active": is_active,
                "last_updated": datetime.utcnow().isoformat()
            }
            
            supabase_update("bot_servers", update_data, "server_id", server_id)
        else:
            # Create
            server_data = {
                "server_id": server_id,
                "server_name": server_name[:100] if server_name else "Unknown Server",
                "member_count": member_count,
                "is_active": is_active,
                "created_at": datetime.utcnow().isoformat(),
                "last_updated": datetime.utcnow().isoformat()
            }
            
            supabase_insert("bot_servers", server_data, admin=True)
        
        return {"success": True, "message": "Server stats updated"}
        
    except Exception as e:
        print(f"Server stats error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
