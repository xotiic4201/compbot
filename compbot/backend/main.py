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
from typing import Optional
from pydantic import BaseModel, EmailStr
import jwt
from uuid import uuid4
import re

app = FastAPI(title="XTourney API", version="8.0.0")

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

# Two sets of headers - one for regular access, one for admin operations
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
    username: str
    password: str

class EmailLoginRequest(BaseModel):
    email: EmailStr
    password: str

class DiscordConnectRequest(BaseModel):
    discord_code: str

class TournamentCreate(BaseModel):
    name: str
    game: str
    description: Optional[str] = ""
    max_teams: int = 16
    start_date: str
    discord_server_id: Optional[str] = None
    bracket_type: str = "single_elimination"
    max_players_per_team: int = 5
    region_filter: bool = False
    prize_pool: Optional[str] = ""

class TeamRegister(BaseModel):
    tournament_id: str
    name: str
    captain_discord_id: str

class ServerStats(BaseModel):
    server_id: str
    server_name: str
    member_count: int

# ========== DATABASE FUNCTIONS ==========
def supabase_insert(table: str, data: dict, admin=False):
    """Insert data into Supabase with better error handling"""
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers=admin_headers if admin else headers,
            params={"select": "*"}  # Return inserted data
        )
        print(f"Insert response: {response.status_code} - {response.text[:200]}")
        
        if response.status_code in [200, 201, 409]:
            try:
                return response.json()
            except:
                return {"id": "unknown"}
        
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
        print(f"Select URL: {url}")
        response = requests.get(url, headers=admin_headers if admin else headers)
        print(f"Select response: {response.status_code} - {response.text[:200]}")
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return []
        print(f"Select error {response.status_code}: {response.text[:200]}")
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
        print(f"Update response: {response.status_code} - {response.text[:200]}")
        if response.status_code == 200:
            return response.json()
        print(f"Update error {response.status_code}: {response.text[:200]}")
        return []
    except Exception as e:
        print(f"Update exception: {str(e)}")
        return []

def supabase_upsert(table: str, data: dict, on_conflict: str = "discord_id", admin=False):
    """Upsert data - insert or update on conflict"""
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers=admin_headers if admin else headers,
            params={
                "on_conflict": on_conflict,
                "select": "*"
            }
        )
        print(f"Upsert response: {response.status_code} - {response.text[:200]}")
        if response.status_code in [200, 201]:
            try:
                return response.json()
            except:
                return data
        print(f"Upsert error {response.status_code}: {response.text[:200]}")
        return None
    except Exception as e:
        print(f"Upsert exception: {str(e)}")
        return None

def supabase_rpc(function_name: str, params: dict):
    """Call a PostgreSQL function in Supabase"""
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/rpc/{function_name}",
            json=params,
            headers=headers
        )
        print(f"RPC {function_name} response: {response.status_code} - {response.text[:200]}")
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return True
        return False
    except Exception as e:
        print(f"RPC exception: {str(e)}")
        return False

# ========== JWT FUNCTIONS ==========
def create_jwt_token(data: dict):
    """Create JWT token using pyjwt"""
    payload = data.copy()
    payload['exp'] = datetime.utcnow() + timedelta(days=30)  # 30 day expiry
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

# ========== PUBLIC ENDPOINTS ==========
@app.get("/")
async def root():
    return {"message": "XTourney API", "status": "running", "version": "8.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ========== STATS ENDPOINTS ==========
@app.get("/api/stats/summary")
async def get_stats_summary():
    """Get overall platform statistics"""
    try:
        # Get tournaments count
        tournaments = supabase_select("tournaments", "status=in.(registration,ongoing)")
        active_tournaments = len(tournaments)
        
        # Get total teams across all tournaments
        total_teams = 0
        total_players = 0
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament.get('id')}")
            tournament_teams = len(teams)
            total_teams += tournament_teams
            total_players += tournament_teams * tournament.get('max_players_per_team', 5)
        
        # Get unique users who created tournaments
        tournament_creators = set(t.get('created_by') for t in tournaments if t.get('created_by'))
        unique_organizers = len(tournament_creators)
        
        # Get live matches (estimate)
        live_matches = min(total_teams // 2, 10)  # Estimate based on teams
        
        # Get server count from bot_servers table
        server_stats = supabase_select("bot_servers", "is_active=eq.true")
        connected_servers = len(server_stats)
        
        return {
            "success": True,
            "stats": {
                "live_matches": live_matches,
                "active_tournaments": active_tournaments,
                "connected_servers": connected_servers,
                "total_players": total_players,
                "total_teams": total_teams,
                "unique_organizers": unique_organizers
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
                "total_teams": 0,
                "unique_organizers": 0
            }
        }

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
            raise HTTPException(status_code=400, detail="Server ID required")
        
        # Upsert server stats
        server_data = {
            "server_id": server_id,
            "server_name": server_name[:100] if server_name else "Unknown Server",
            "member_count": member_count,
            "is_active": is_active,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        result = supabase_upsert("bot_servers", server_data, on_conflict="server_id", admin=True)
        
        if result:
            return {"success": True, "message": "Server stats updated"}
        else:
            return {"success": False, "message": "Failed to update stats"}
            
    except Exception as e:
        print(f"Server stats error: {str(e)}")
        return {"success": False, "message": str(e)}

# ========== PUBLIC MATCHES (NO LOGIN REQUIRED) ==========
@app.get("/api/matches/live")
async def get_live_matches():
    """Get live matches - Public endpoint"""
    try:
        tournaments = supabase_select("tournaments", "status=eq.ongoing&limit=10")
        
        matches = []
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament['id']}&limit=8")
            
            if len(teams) >= 2:
                # Create matches for tournament
                for i in range(0, len(teams), 2):
                    if i + 1 < len(teams):
                        match = {
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
                        }
                        matches.append(match)
        
        # If no real matches, create some sample data
        if not matches:
            matches = [
                {
                    "id": "sample_1",
                    "tournament_id": "sample",
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
                },
                {
                    "id": "sample_2",
                    "tournament_id": "sample",
                    "tournament_name": "CS2 Showdown",
                    "game": "Counter-Strike 2",
                    "status": "live",
                    "team1": {
                        "id": "team3",
                        "name": "Eagle Squad",
                        "score": 12
                    },
                    "team2": {
                        "id": "team4",
                        "name": "Wolf Pack",
                        "score": 10
                    },
                    "start_time": datetime.utcnow().isoformat(),
                    "viewers": 856,
                    "round": "Quarter-Finals"
                }
            ]
        
        return {
            "success": True,
            "matches": matches[:10],  # Limit to 10 matches
            "count": len(matches)
        }
    except Exception as e:
        print(f"Get live matches error: {str(e)}")
        return {"success": False, "matches": [], "count": 0}

@app.get("/api/tournaments/public")
async def get_public_tournaments():
    """Get public tournaments - No login required"""
    try:
        tournaments = supabase_select("tournaments", "status=in.(registration,ongoing)&order=start_date.asc&limit=20")
        
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament['id']}")
            tournament['team_count'] = len(teams)
            tournament['registered_teams'] = len(teams)
            tournament['progress_percent'] = int((len(teams) / tournament.get('max_teams', 16)) * 100) if tournament.get('max_teams', 16) > 0 else 0
            
        return {
            "success": True,
            "tournaments": tournaments,
            "count": len(tournaments)
        }
    except Exception as e:
        print(f"Get tournaments error: {str(e)}")
        return {"success": False, "tournaments": [], "count": 0}

# ========== DISCORD AUTH - FIXED ==========
@app.post("/api/auth/discord/token")
async def discord_auth_token(request: DiscordAuthRequest):
    """Exchange Discord code for token - FIXED DUPLICATE USER ISSUE"""
    try:
        print(f"Discord auth with code: {request.code[:20]}...")
        
        redirect_uri = request.redirect_uri or f"{FRONTEND_URL}/auth/callback"
        
        # Get Discord access token
        token_data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': redirect_uri
        }
        
        print("Getting Discord token...")
        token_response = requests.post('https://discord.com/api/oauth2/token', data=token_data)
        
        if token_response.status_code != 200:
            error_text = token_response.text[:200]
            print(f"Discord token error: {error_text}")
            raise HTTPException(status_code=400, detail=f"Discord auth failed: {error_text}")
        
        discord_token = token_response.json()
        access_token = discord_token.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        # Get Discord user info
        user_response = requests.get('https://discord.com/api/users/@me', 
                                   headers={'Authorization': f'Bearer {access_token}'})
        user_data = user_response.json()
        
        print(f"Got Discord user: {user_data.get('id')} - {user_data.get('username')}")
        
        if 'id' not in user_data:
            raise HTTPException(status_code=400, detail="Invalid user data from Discord")
        
        discord_username = user_data['username']
        if user_data.get('global_name'):
            discord_username = user_data['global_name']
        
        # Check if user exists by discord_id
        print(f"Checking for existing user with discord_id: {user_data['id']}")
        existing_users = supabase_select("users", f"discord_id=eq.{user_data['id']}")
        
        user_id = None
        user_record = None
        
        if existing_users and len(existing_users) > 0:
            # User exists - UPDATE
            user_record = existing_users[0]
            user_id = user_record.get('id')
            print(f"Found existing user: {user_id}")
            
            # Update user info
            update_data = {
                "username": discord_username,
                "last_login": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            if user_data.get('avatar'):
                update_data["avatar_url"] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
            
            if user_data.get('email'):
                update_data["email"] = user_data.get('email')
            
            # Update the user
            update_result = supabase_update("users", update_data, "id", user_id)
            print(f"Updated user: {update_result}")
            
        else:
            # Create new user
            print("Creating new user...")
            user_db = {
                "discord_id": user_data["id"],
                "username": discord_username,
                "email": user_data.get("email", ""),
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat(),
                "is_verified": True
            }
            
            # Use upsert to handle any race conditions
            insert_result = supabase_upsert("users", user_db, on_conflict="discord_id", admin=True)
            
            if insert_result:
                if isinstance(insert_result, list) and len(insert_result) > 0:
                    user_record = insert_result[0]
                    user_id = user_record.get('id')
                elif isinstance(insert_result, dict):
                    user_record = insert_result
                    user_id = insert_result.get('id')
                else:
                    # Try to fetch the user we just created
                    existing_users = supabase_select("users", f"discord_id=eq.{user_data['id']}")
                    if existing_users and len(existing_users) > 0:
                        user_record = existing_users[0]
                        user_id = user_record.get('id')
                    else:
                        raise HTTPException(status_code=500, detail="User creation failed")
            
            print(f"Created new user with ID: {user_id}")
        
        if not user_id:
            raise HTTPException(status_code=500, detail="User ID not found")
        
        # Get user's Discord servers (guilds)
        servers = []
        try:
            guilds_response = requests.get('https://discord.com/api/users/@me/guilds', 
                                         headers={'Authorization': f'Bearer {access_token}'})
            if guilds_response.status_code == 200:
                user_guilds = guilds_response.json()
                for guild in user_guilds[:20]:  # Limit to 20 guilds
                    permissions = int(guild.get('permissions', 0))
                    # Check if user has admin or manage server permissions
                    if permissions & 0x8 or permissions & 0x20:  # Admin or Manage Server
                        servers.append({
                            "id": guild['id'],
                            "name": guild['name'],
                            "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon')}.png" if guild.get('icon') else None,
                            "permissions": permissions
                        })
                print(f"Found {len(servers)} servers with admin permissions")
        except Exception as e:
            print(f"Error fetching guilds: {str(e)}")
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": str(user_id),
            "username": discord_username,
            "discord_id": user_data["id"],
            "email": user_data.get("email"),
            "avatar": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
            "account_type": "discord",
            "exp": (datetime.utcnow() + timedelta(days=30)).timestamp()
        })
        
        print(f"Auth successful for user: {user_id}")
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": discord_username,
                "avatar": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar')}.png" if user_data.get('avatar') else None,
                "discord_id": user_data["id"],
                "email": user_data.get("email"),
                "account_type": "discord"
            },
            "access_token": jwt_token,
            "servers": servers,
            "message": "Login successful"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Discord auth error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

# ========== EMAIL AUTH - FIXED ==========
@app.post("/api/auth/email/register")
async def email_register(request: EmailRegisterRequest):
    """Register with email and password - FIXED"""
    try:
        # Validate username
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', request.username):
            raise HTTPException(status_code=400, detail="Username must be 3-20 characters, letters, numbers, and underscores only")
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, request.email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        
        # Check if email already exists
        existing_email = supabase_select("users", f"email=ilike.'{request.email}'")
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username already exists
        existing_username = supabase_select("users", f"username=ilike.'{request.username}'")
        if existing_username:
            raise HTTPException(status_code=400, detail="Username already taken")
        
        # Hash password
        hashed_password = hashlib.sha256(request.password.encode()).hexdigest()
        
        # Generate a UUID for the user
        user_uuid = str(uuid4())
        
        user_db = {
            "id": user_uuid,
            "username": request.username,
            "email": request.email.lower(),  # Store email in lowercase
            "password_hash": hashed_password,
            "account_type": "email",
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            "is_verified": False,
            "avatar_url": f"https://ui-avatars.com/api/?name={request.username.replace(' ', '+')}&background=DC2626&color=fff"
        }
        
        print(f"Attempting to create user: {user_db['email']}")
        
        result = supabase_insert("users", user_db, admin=True)
        
        if result:
            print(f"User created successfully: {user_uuid}")
            
            # Create JWT token
            jwt_token = create_jwt_token({
                "sub": user_uuid,
                "username": request.username,
                "email": request.email,
                "account_type": "email",
                "exp": (datetime.utcnow() + timedelta(days=30)).timestamp()
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
                "access_token": jwt_token,
                "message": "Account created successfully"
            }
        else:
            print(f"Failed to create user in database")
            raise HTTPException(status_code=500, detail="Failed to create user in database")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Email registration error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

@app.post("/api/auth/email/login")
async def email_login(request: EmailLoginRequest):
    """Login with email and password"""
    try:
        # Find user by email (case-insensitive)
        users = supabase_select("users", f"email=ilike.'{request.email}'")
        
        if not users:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        user = users[0]
        
        # Verify password
        hashed_input = hashlib.sha256(request.password.encode()).hexdigest()
        stored_hash = user.get('password_hash')
        
        if not stored_hash or hashed_input != stored_hash:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Update last login
        supabase_update("users", {
            "last_login": datetime.utcnow().isoformat()
        }, "id", user['id'])
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user['id'],
            "username": user['username'],
            "email": user['email'],
            "account_type": user.get('account_type', 'email'),
            "discord_id": user.get('discord_id'),
            "avatar": user.get('avatar_url'),
            "exp": (datetime.utcnow() + timedelta(days=30)).timestamp()
        })
        
        return {
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "account_type": user.get('account_type', 'email'),
                "discord_id": user.get('discord_id'),
                "avatar": user.get('avatar_url')
            },
            "access_token": jwt_token,
            "message": "Login successful"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Email login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

# ========== REFRESH TOKEN ==========
@app.post("/api/auth/refresh")
async def refresh_login(request: RefreshTokenRequest):
    """Refresh user session"""
    try:
        user_token = request.token
        
        if not user_token:
            raise HTTPException(status_code=400, detail="No token provided")
        
        payload = verify_jwt_token(user_token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        user_id = payload.get("sub")
        
        users = supabase_select("users", f"id=eq.'{user_id}'")
        
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        
        # Update last login
        supabase_update("users", {
            "last_login": datetime.utcnow().isoformat()
        }, "id", user_id)
        
        # Create new JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": user.get('username'),
            "email": user.get('email'),
            "discord_id": user.get('discord_id'),
            "account_type": user.get('account_type', 'email'),
            "avatar": user.get('avatar_url'),
            "exp": (datetime.utcnow() + timedelta(days=30)).timestamp()
        })
        
        # Get Discord servers if user has Discord connected
        servers = []
        if user.get('discord_id') and user.get('account_type') in ['discord', 'both']:
            # Note: Can't get servers without Discord token
            pass
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": user.get('username'),
                "email": user.get('email'),
                "account_type": user.get('account_type', 'email'),
                "discord_id": user.get('discord_id'),
                "avatar": user.get('avatar_url')
            },
            "access_token": jwt_token,
            "servers": servers,
            "message": "Session refreshed"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Refresh error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Refresh error: {str(e)}")

# ========== PROTECTED ENDPOINTS ==========
@app.get("/api/auth/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Get current user info"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    users = supabase_select("users", f"id=eq.'{user_id}'")
    
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users[0]
    return {"success": True, "user": user}

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

