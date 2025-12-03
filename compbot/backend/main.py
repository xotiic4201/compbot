from fastapi import FastAPI, HTTPException, Request
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

app = FastAPI(title="XTourney API", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-client-secret")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://compbot-lhuy.onrender.com/api/auth/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://compbot-ik5bayp8r-xotiics-projects.vercel.app")

headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

# ========== PYDANTIC MODELS ==========
class DiscordAuthRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None

class EmailRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class EmailLoginRequest(BaseModel):
    email: EmailStr
    password: str

class TournamentCreateRequest(BaseModel):
    name: str
    game: str
    description: Optional[str] = ""
    max_teams: int = 16
    start_date: str
    discord_server_id: Optional[str] = None
    bracket_type: Optional[str] = "single_elimination"
    max_players_per_team: Optional[int] = 5
    region_filter: Optional[bool] = False

# ========== SIMPLE JWT FUNCTIONS ==========
def create_jwt_token(data: dict):
    """Simple token creation"""
    # Add expiry (7 days from now)
    data['exp'] = (datetime.utcnow() + timedelta(days=7)).timestamp()
    data['iat'] = datetime.utcnow().timestamp()
    
    # Create token parts
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    
    # Create signature
    signature = hashlib.sha256(f"{header_b64}.{payload_b64}.{SECRET_KEY}".encode()).hexdigest()
    
    return f"{header_b64}.{payload_b64}.{signature}"

def verify_jwt_token(token: str):
    """Simple token verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        # Decode payload
        payload_json = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))
        payload = json.loads(payload_json)
        
        # Check expiry
        if 'exp' in payload and datetime.utcnow().timestamp() > payload['exp']:
            return None
            
        return payload
    except:
        return None

# ========== DATABASE FUNCTIONS ==========
def supabase_insert(table: str, data: dict):
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        if response.status_code in [200, 201]:
            return response.json()[0] if response.json() else None
        print(f"Insert error {response.status_code}: {response.text}")
        return None
    except Exception as e:
        print(f"Insert exception: {e}")
        return None

def supabase_select(table: str, query: str = ""):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        print(f"Select error {response.status_code}: {response.text}")
        return []
    except Exception as e:
        print(f"Select exception: {e}")
        return []

def supabase_update(table: str, data: dict, column: str, value: str):
    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        if response.status_code == 200:
            return response.json()
        print(f"Update error {response.status_code}: {response.text}")
        return []
    except Exception as e:
        print(f"Update exception: {e}")
        return []

# ========== PASSWORD HASHING ==========
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{hash_obj.hexdigest()}:{salt}"

def verify_password(password: str, hashed_password: str) -> bool:
    if not hashed_password or ":" not in hashed_password:
        return False
    hash_value, salt = hashed_password.split(":")
    test_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return test_hash == hash_value

# ========== HEALTH CHECK ==========
@app.get("/")
async def root():
    return {"message": "XTourney API", "status": "running", "version": "6.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ========== DISCORD AUTH ==========
@app.get("/api/auth/discord")
async def discord_auth_redirect():
    """FIXED: Redirect to Discord OAuth2 - Use proper frontend redirect URI"""
    # Use frontend URL for redirect
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={FRONTEND_URL}&"
        f"response_type=code&"
        f"scope=identify%20email%20guilds&"
        f"prompt=consent"
    )
    return RedirectResponse(url=discord_auth_url)

@app.get("/api/auth/discord/callback")
async def discord_auth_callback(code: str, state: str = None):
    """Handle Discord OAuth2 callback - THIS IS FOR FRONTEND"""
    try:
        print(f"Discord callback received with code: {code[:20]}...")
        
        # Exchange code for token using FRONTEND_URL as redirect_uri
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': FRONTEND_URL
        }
        
        headers_auth = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers_auth)
        
        print(f"Discord token response: {response.status_code}")
        
        if response.status_code != 200:
            error_text = response.text[:200]
            print(f"Discord token error: {error_text}")
            # Redirect to frontend with error
            return RedirectResponse(f"{FRONTEND_URL}?error=auth_failed&message={error_text}")
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            return RedirectResponse(f"{FRONTEND_URL}?error=no_token")
        
        # Get user info
        user_headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=user_headers)
        user_data = user_response.json()
        
        print(f"Discord user data received for: {user_data.get('username')}")
        
        if 'id' not in user_data:
            return RedirectResponse(f"{FRONTEND_URL}?error=invalid_user_data")
        
        # Create username
        discord_username = user_data['username']
        if user_data.get('global_name'):
            discord_username = user_data['global_name']
        
        # Check if user exists
        existing = supabase_select("users", f"discord_id=eq.'{user_data['id']}'")
        
        if existing:
            user = existing[0]
            user_id = user['id']
            # Update user
            supabase_update("users", {
                "last_login": datetime.utcnow().isoformat(),
                "username": discord_username,
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None
            }, "id", user_id)
        else:
            # Create new user
            user_db = {
                "discord_id": user_data["id"],
                "username": discord_username,
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None,
                "email": user_data.get("email"),
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            
            result = supabase_insert("users", user_db)
            if not result:
                return RedirectResponse(f"{FRONTEND_URL}?error=user_creation_failed")
            user_id = result['id']
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": discord_username,
            "discord_id": user_data["id"],
            "account_type": "discord",
            "avatar": user_db.get("avatar_url")
        })
        
        # Get user's Discord guilds (servers)
        guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=user_headers)
        servers = []
        if guilds_response.status_code == 200:
            user_guilds = guilds_response.json()
            # Filter guilds where user has admin permissions
            for guild in user_guilds:
                permissions = int(guild.get('permissions', 0))
                # Check for admin permissions (0x8) or manage server (0x20)
                if permissions & 0x8 or permissions & 0x20:
                    servers.append({
                        "id": guild['id'],
                        "name": guild['name'],
                        "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None,
                        "permissions": guild.get('permissions')
                    })
        
        # Store servers in localStorage (via URL params)
        servers_json = json.dumps(servers)
        servers_encoded = base64.urlsafe_b64encode(servers_json.encode()).decode().rstrip('=')
        
        # Redirect to frontend with token and servers
        return RedirectResponse(
            f"{FRONTEND_URL}/auth/callback?token={jwt_token}&user_id={user_id}&username={discord_username}&servers={servers_encoded}&success=true"
        )
        
    except Exception as e:
        print(f"Discord auth error: {str(e)}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(f"{FRONTEND_URL}?error=server_error&message={str(e)}")

@app.post("/api/auth/discord/token")
async def discord_auth_token(request: DiscordAuthRequest):
    """Direct token exchange (for frontend POST)"""
    try:
        print(f"Direct Discord auth with code: {request.code[:20]}...")
        
        # Use provided redirect_uri or default to frontend URL
        redirect_uri = request.redirect_uri or FRONTEND_URL
        
        # Exchange code for token
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': redirect_uri
        }
        
        headers_auth = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers_auth)
        
        print(f"Direct Discord token response: {response.status_code}")
        
        if response.status_code != 200:
            error_text = response.text[:200]
            print(f"Direct Discord token error: {error_text}")
            raise HTTPException(status_code=400, detail=f"Discord auth failed: {error_text}")
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        # Get user info
        user_headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=user_headers)
        user_data = user_response.json()
        
        if 'id' not in user_data:
            raise HTTPException(status_code=400, detail="Invalid user data from Discord")
        
        # Create username
        discord_username = user_data['username']
        if user_data.get('global_name'):
            discord_username = user_data['global_name']
        
        # Check if user exists
        existing = supabase_select("users", f"discord_id=eq.'{user_data['id']}'")
        
        if existing:
            user_id = existing[0]['id']
            # Update user
            supabase_update("users", {
                "last_login": datetime.utcnow().isoformat(),
                "username": discord_username,
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None
            }, "id", user_id)
        else:
            # Create new user
            user_db = {
                "discord_id": user_data["id"],
                "username": discord_username,
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None,
                "email": user_data.get("email"),
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            
            result = supabase_insert("users", user_db)
            if not result:
                raise HTTPException(status_code=500, detail="Failed to create user")
            user_id = result['id']
        
        # Get user's Discord servers
        servers = []
        try:
            guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=user_headers)
            if guilds_response.status_code == 200:
                user_guilds = guilds_response.json()
                for guild in user_guilds:
                    permissions = int(guild.get('permissions', 0))
                    if permissions & 0x8 or permissions & 0x20:  # Admin or Manage Server
                        servers.append({
                            "id": guild['id'],
                            "name": guild['name'],
                            "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None
                        })
        except Exception as e:
            print(f"Error fetching guilds: {e}")
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": discord_username,
            "discord_id": user_data["id"],
            "account_type": "discord",
            "avatar": user_db.get("avatar_url")
        })
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": discord_username,
                "avatar": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None,
                "discord_id": user_data["id"],
                "email": user_data.get("email")
            },
            "access_token": jwt_token,
            "servers": servers
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Direct Discord auth error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ========== EMAIL AUTH ==========
@app.post("/api/auth/register")
async def register_email(request: EmailRegisterRequest):
    """Register with email and password"""
    try:
        print(f"Registration attempt for: {request.email}")
        
        # Validate input
        if len(request.username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
        
        if len(request.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        
        # Check if email exists
        existing = supabase_select("users", f"email=eq.'{request.email}'")
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username exists
        existing_user = supabase_select("users", f"username=eq.'{request.username}'")
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already taken")
        
        # Create user
        user_db = {
            "username": request.username,
            "email": request.email,
            "password_hash": hash_password(request.password),
            "account_type": "email",
            "avatar_url": f"https://ui-avatars.com/api/?name={request.username}&background=5865F2&color=fff",
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("users", user_db)
        if not result:
            raise HTTPException(status_code=500, detail="Failed to create user")
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": result["id"],
            "username": request.username,
            "email": request.email,
            "account_type": "email"
        })
        
        return {
            "success": True,
            "user": {
                "id": result["id"],
                "username": request.username,
                "email": request.email,
                "avatar": user_db["avatar_url"]
            },
            "access_token": jwt_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/auth/login")
async def login_email(request: EmailLoginRequest):
    """Login with email and password"""
    try:
        print(f"Login attempt for: {request.email}")
        
        # Find user
        users = supabase_select("users", f"email=eq.'{request.email}'")
        if not users:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        user = users[0]
        
        # Verify password
        if not verify_password(request.password, user.get("password_hash", "")):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Update last login
        supabase_update("users", {
            "last_login": datetime.utcnow().isoformat()
        }, "id", user["id"])
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user["id"],
            "username": user["username"],
            "email": user["email"],
            "account_type": user.get("account_type", "email")
        })
        
        return {
            "success": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "avatar": user.get("avatar_url") or f"https://ui-avatars.com/api/?name={user['username']}&background=5865F2&color=fff"
            },
            "access_token": jwt_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/auth/me")
async def get_current_user(authorization: str = None):
    """Get current user"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
        
        token = authorization.split(" ")[1]
        payload = verify_jwt_token(token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        if "password_hash" in user:
            del user["password_hash"]
        
        return {"user": user}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Get me error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== TOURNAMENT MANAGEMENT ==========
@app.post("/api/tournaments")
async def create_tournament(request: Request):
    """Create tournament"""
    try:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authorization")
        
        token = authorization.split(" ")[1]
        payload = verify_jwt_token(token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        data = await request.json()
        
        print(f"Creating tournament for user {user_id}: {data.get('name')}")
        
        # Validate required fields
        required_fields = ['name', 'game', 'max_teams', 'start_date']
        for field in required_fields:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Get user
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Create tournament
        tournament = {
            "name": data.get("name"),
            "game": data.get("game"),
            "description": data.get("description", ""),
            "max_teams": data.get("max_teams", 16),
            "current_teams": 0,
            "bracket_type": data.get("bracket_type", "single_elimination"),
            "start_date": data.get("start_date"),
            "status": "registration",
            "discord_server_id": data.get("discord_server_id"),
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "settings": {
                "queue_time_minutes": 10,
                "match_duration_minutes": 30,
                "max_players_per_team": data.get("max_players_per_team", 5),
                "region_filter": data.get("region_filter", False),
                "auto_start": True,
                "server_filter": True
            }
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            return {
                "success": True, 
                "tournament": result,
                "message": "Tournament created successfully!"
            }
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments")
async def get_tournaments(authorization: str = None):
    """Get user's tournaments"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authorization")
        
        token = authorization.split(" ")[1]
        payload = verify_jwt_token(token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        tournaments = supabase_select("tournaments", f"created_by=eq.{user_id}")
        
        # Add team counts
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament['id']}")
            tournament['current_teams'] = len(teams)
        
        return {"tournaments": tournaments}
    except Exception as e:
        print(f"Get tournaments error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str):
    """Get specific tournament"""
    try:
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        return {
            "tournament": tournament,
            "teams": teams
        }
        
    except Exception as e:
        print(f"Get tournament error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str):
    """Get tournament bracket"""
    try:
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Generate simple bracket structure
        rounds = {}
        if teams:
            # Create first round
            team_pairs = []
            for i in range(0, len(teams), 2):
                if i + 1 < len(teams):
                    team_pairs.append({
                        "team1_id": teams[i]['id'],
                        "team2_id": teams[i + 1]['id'],
                        "team1_name": teams[i]['name'],
                        "team2_name": teams[i + 1]['name']
                    })
            
            if team_pairs:
                rounds["1"] = team_pairs
        
        return {
            "tournament": tournament,
            "teams": teams,
            "rounds": rounds
        }
        
    except Exception as e:
        print(f"Get bracket error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/tournaments")
async def create_tournament_bot(request: Request):
    """Create tournament via Discord bot"""
    try:
        data = await request.json()
        user_id = data.get("created_by")
        server_id = data.get("discord_server_id")
        
        print(f"Bot creating tournament: {data.get('name')} by user {user_id}")
        
        # Check if user exists in database
        users = supabase_select("users", f"discord_id=eq.'{user_id}'")
        if not users:
            # Create user if doesn't exist
            user_db = {
                "discord_id": user_id,
                "username": f"Discord User {user_id[:8]}",
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            result = supabase_insert("users", user_db)
            if not result:
                raise HTTPException(status_code=500, detail="Failed to create user")
            db_user_id = result['id']
        else:
            db_user_id = users[0]['id']
        
        # Create tournament
        tournament = {
            "name": data.get("name"),
            "game": data.get("game"),
            "description": data.get("description", ""),
            "max_teams": data.get("max_teams", 16),
            "current_teams": 0,
            "bracket_type": data.get("bracket_type", "single_elimination"),
            "start_date": data.get("start_date"),
            "status": "registration",
            "discord_server_id": server_id,
            "created_by": db_user_id,
            "created_at": datetime.utcnow().isoformat(),
            "settings": {
                "queue_time_minutes": 10,
                "match_duration_minutes": 30,
                "max_players_per_team": data.get("max_players_per_team", 5),
                "region_filter": data.get("region_filter", False),
                "auto_start": True,
                "server_filter": True
            }
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            return {
                "success": True, 
                "tournament": result,
                "message": "Tournament created via bot!"
            }
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except Exception as e:
        print(f"Bot tournament creation error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bot/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket_bot(tournament_id: str):
    """Get tournament bracket for bot"""
    try:
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        return {
            "tournament": tournament,
            "teams": teams
        }
        
    except Exception as e:
        print(f"Bot bracket error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bot/tournaments/server/{server_id}")
async def get_server_tournaments(server_id: str):
    """Get all tournaments for a server"""
    try:
        tournaments = supabase_select("tournaments", f"discord_server_id=eq.'{server_id}'")
        return {"tournaments": tournaments}
    except Exception as e:
        print(f"Server tournaments error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/bot/teams")
async def register_team_bot(request: Request):
    """Register team via bot"""
    try:
        data = await request.json()
        tournament_id = data.get("tournament_id")
        team_name = data.get("name")
        captain_id = data.get("captain_discord_id")
        
        print(f"Bot registering team: {team_name} for tournament {tournament_id}")
        
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        
        # Check if registration is open
        if tournament["status"] != "registration":
            raise HTTPException(status_code=400, detail="Tournament registration is closed")
        
        # Check if already at max teams
        current_teams = len(supabase_select("teams", f"tournament_id=eq.{tournament_id}"))
        if current_teams >= tournament["max_teams"]:
            raise HTTPException(status_code=400, detail="Tournament is full")
        
        # Check if captain already registered
        existing_teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        for team in existing_teams:
            if captain_id == team.get('captain_discord_id'):
                raise HTTPException(status_code=400, detail="Already registered as captain")
        
        # Check team name uniqueness
        for team in existing_teams:
            if team['name'].lower() == team_name.lower():
                raise HTTPException(status_code=400, detail="Team name already taken")
        
        # Create team
        team = {
            "tournament_id": tournament_id,
            "name": team_name,
            "captain_discord_id": captain_id,
            "players": [captain_id],
            "checked_in": False,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("teams", team)
        
        if result:
            return {
                "success": True, 
                "team": result,
                "message": "Team registered successfully!"
            }
        raise HTTPException(status_code=500, detail="Failed to register team")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Bot team registration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== CHANNEL MANAGEMENT ==========
@app.post("/api/bot/channels/set")
async def bot_set_channel(request: Request):
    """Set channel via Discord bot"""
    try:
        data = await request.json()
        channel_data = {
            "discord_server_id": data.get("discord_server_id"),
            "channel_type": data.get("channel_type"),
            "discord_channel_id": data.get("discord_channel_id"),
            "channel_name": data.get("channel_name"),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Check if exists
        existing = supabase_select("server_channels", 
                                 f"discord_server_id=eq.'{channel_data['discord_server_id']}' AND channel_type=eq.'{channel_data['channel_type']}'")
        
        if existing:
            result = supabase_update("server_channels", channel_data, 
                                   "discord_server_id", channel_data['discord_server_id'])
        else:
            channel_data["created_at"] = datetime.utcnow().isoformat()
            result = supabase_insert("server_channels", channel_data)
        
        if result:
            return {"success": True}
        raise HTTPException(status_code=500, detail="Failed to save channel")
            
    except Exception as e:
        print(f"Bot set channel error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bot/channels/{server_id}")
async def bot_get_channels(server_id: str):
    """Get all channels for a server - bot version"""
    try:
        channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
        return channels
    except Exception as e:
        print(f"Bot get channels error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== UTILITY ENDPOINTS ==========
@app.get("/api/auth/discord/redirect")
async def discord_redirect_manual():
    """Manual Discord redirect for testing"""
    discord_url = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={FRONTEND_URL}&response_type=code&scope=identify%20email%20guilds"
    return {"redirect_url": discord_url}

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
