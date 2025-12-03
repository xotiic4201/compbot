from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import os
import requests
import jwt
import secrets
import hashlib
from typing import Optional
from pydantic import BaseModel, EmailStr

app = FastAPI(title="XTourney API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://xtourney.vercel.app", "http://localhost:3000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
ALGORITHM = "HS256"

# ========== PYDANTIC MODELS ==========
class DiscordAuthRequest(BaseModel):
    code: str
    redirect_uri: str

class EmailRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class EmailLoginRequest(BaseModel):
    email: EmailStr
    password: str

# ========== SUPABASE SETUP ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "your-supabase-url")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-supabase-key")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-discord-secret")

headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

def supabase_insert(table, data):
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        if response.status_code in [200, 201]:
            return response.json()[0]
        return None
    except Exception as e:
        print(f"Supabase insert error: {e}")
        return None

def supabase_select(table, query=""):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        print(f"Supabase select error: {e}")
        return []

def supabase_update(table, data, column, value):
    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        print(f"Supabase update error: {e}")
        return []

# ========== PASSWORD HASHING ==========
def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{hash_obj.hexdigest()}:{salt}"

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    if not hashed_password or ":" not in hashed_password:
        return False
    hash_value, salt = hashed_password.split(":")
    test_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return test_hash == hash_value

# ========== DISCORD TOKEN ENCRYPTION ==========
def encrypt_token(token: str) -> str:
    """Simple encryption for storing Discord tokens"""
    # In production, use a proper encryption library like cryptography
    import base64
    encoded = base64.b64encode(token.encode()).decode()
    return f"enc:{encoded}"

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt Discord token"""
    if not encrypted_token or not encrypted_token.startswith("enc:"):
        return encrypted_token
    import base64
    try:
        encoded = encrypted_token[4:]  # Remove 'enc:' prefix
        decoded = base64.b64decode(encoded).decode()
        return decoded
    except:
        return ""

# ========== JWT AUTH ==========
def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ========== DISCORD AUTH ==========
@app.post("/api/auth/discord")
async def discord_auth(request: DiscordAuthRequest):
    """Production Discord OAuth2"""
    try:
        print(f"Discord auth request received: {request.redirect_uri}")
        
        # Exchange code for token
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': request.redirect_uri
        }
        
        response = requests.post('https://discord.com/api/oauth2/token', data=data, 
                               headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        if response.status_code != 200:
            print(f"Discord token error: {response.text}")
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        token_data = response.json()
        
        # Store Discord tokens
        discord_access_token = token_data.get("access_token")
        discord_refresh_token = token_data.get("refresh_token")
        discord_expires_in = token_data.get("expires_in")
        
        # Calculate expiry time
        discord_expires_at = (datetime.utcnow() + timedelta(seconds=discord_expires_in)).isoformat() if discord_expires_in else None
        
        # Get user info
        user_headers = {'Authorization': f'Bearer {discord_access_token}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=user_headers)
        user_data = user_response.json()
        
        if 'id' not in user_data:
            raise HTTPException(status_code=400, detail="Invalid user data from Discord")
        
        # Get user's guilds (servers)
        guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=user_headers)
        guilds_data = guilds_response.json()
        
        # Filter to guilds where user has admin permissions
        bot_guilds = []
        for guild in guilds_data:
            permissions = int(guild.get('permissions', 0))
            # Check if user has ADMINISTRATOR permission (0x8)
            if permissions & 0x8:
                bot_guilds.append({
                    'id': guild['id'],
                    'name': guild['name'],
                    'icon': f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None,
                    'permissions': guild['permissions']
                })
        
        # Generate unique username
        discord_username = f"{user_data['username']}"
        if user_data.get('discriminator') and user_data['discriminator'] != '0':
            discord_username = f"{user_data['username']}#{user_data['discriminator']}"
        
        # Save/update user with Discord tokens
        user_db = {
            "discord_id": user_data["id"],
            "username": discord_username,
            "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else f"https://cdn.discordapp.com/embed/avatars/{int(user_data.get('discriminator', '0')) % 5}.png",
            "email": user_data.get("email"),
            "last_login": datetime.utcnow().isoformat(),
            "account_type": "discord",
            "discord_access_token": encrypt_token(discord_access_token) if discord_access_token else None,
            "discord_refresh_token": encrypt_token(discord_refresh_token) if discord_refresh_token else None,
            "discord_token_expires": discord_expires_at
        }
        
        # Check if user exists by discord_id
        existing = supabase_select("users", f"discord_id=eq.{user_db['discord_id']}")
        if existing:
            supabase_update("users", user_db, "discord_id", user_db['discord_id'])
            user_id = existing[0]['id']
        else:
            # Also check if email exists (in case they registered with email first)
            if user_db['email']:
                existing_email = supabase_select("users", f"email=eq.{user_db['email']}")
                if existing_email:
                    # Link Discord to existing email account
                    supabase_update("users", {
                        "discord_id": user_db['discord_id'],
                        "avatar_url": user_db['avatar_url'],
                        "last_login": user_db['last_login'],
                        "account_type": "both",  # User has both email and Discord
                        "discord_access_token": user_db['discord_access_token'],
                        "discord_refresh_token": user_db['discord_refresh_token'],
                        "discord_token_expires": user_db['discord_token_expires']
                    }, "email", user_db['email'])
                    user_id = existing_email[0]['id']
                else:
                    # Create new user
                    result = supabase_insert("users", user_db)
                    user_id = result['id'] if result else None
            else:
                result = supabase_insert("users", user_db)
                user_id = result['id'] if result else None
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id if user_id else user_data["id"],
            "username": discord_username,
            "avatar": user_data.get("avatar"),
            "email": user_data.get("email"),
            "discord_id": user_data["id"],
            "account_type": "discord"
        })
        
        return {
            "success": True,
            "user": {
                "id": user_id if user_id else user_data["id"],
                "username": discord_username,
                "avatar": user_db["avatar_url"],
                "email": user_data.get("email"),
                "discord_id": user_data["id"]
            },
            "servers": bot_guilds,
            "access_token": jwt_token,
            "token_type": "Bearer"
        }
        
    except Exception as e:
        print(f"Auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

# ========== EMAIL AUTH ==========
@app.post("/api/auth/register")
async def register_email(request: EmailRegisterRequest):
    """Register with email and password"""
    try:
        # Check if email already exists
        existing = supabase_select("users", f"email=eq.{request.email}")
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username already exists
        existing_user = supabase_select("users", f"username=eq.{request.username}")
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already taken")
        
        # Create user
        user_db = {
            "username": request.username,
            "email": request.email,
            "password_hash": hash_password(request.password),
            "account_type": "email",
            "avatar_url": f"https://ui-avatars.com/api/?name={request.username.replace(' ', '+')}&background=5865F2&color=fff",
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
            "access_token": jwt_token,
            "token_type": "Bearer"
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
        # Find user by email
        users = supabase_select("users", f"email=eq.{request.email}")
        if not users:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        user = users[0]
        
        # Verify password
        if not verify_password(request.password, user.get("password_hash")):
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
        
        avatar = user.get("avatar_url") or f"https://ui-avatars.com/api/?name={user['username'].replace(' ', '+')}&background=5865F2&color=fff"
        
        return {
            "success": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "avatar": avatar
            },
            "access_token": jwt_token,
            "token_type": "Bearer"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

# ========== GET USER PROFILE ==========
@app.get("/api/auth/me")
async def get_current_user(token: dict = Depends(verify_token)):
    """Get current user from JWT"""
    try:
        user_id = token.get("sub")
        
        # Get user from database
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=401, detail="User not found")
        
        user = users[0]
        
        # Don't return sensitive data
        user.pop("password_hash", None)
        user.pop("discord_access_token", None)
        user.pop("discord_refresh_token", None)
        
        # Get Discord servers if user has Discord tokens
        servers = []
        if user.get("discord_access_token") and user.get("discord_id"):
            try:
                # Decrypt and use Discord token
                access_token = decrypt_token(user.get("discord_access_token", ""))
                if access_token:
                    headers = {'Authorization': f'Bearer {access_token}'}
                    response = requests.get('https://discord.com/api/users/@me/guilds', headers=headers)
                    
                    if response.status_code == 200:
                        guilds_data = response.json()
                        for guild in guilds_data:
                            permissions = int(guild.get('permissions', 0))
                            if permissions & 0x8:  # ADMINISTRATOR permission
                                servers.append({
                                    'id': guild['id'],
                                    'name': guild['name'],
                                    'icon': f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None,
                                    'permissions': guild['permissions']
                                })
            except Exception as e:
                print(f"Error fetching Discord servers: {e}")
                # Token might be expired, could implement refresh here
        
        return {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user.get("email"),
                "avatar": user.get("avatar_url") or f"https://ui-avatars.com/api/?name={user['username'].replace(' ', '+')}&background=5865F2&color=fff",
                "discord_id": user.get("discord_id"),
                "account_type": user.get("account_type", "email")
            },
            "servers": servers
        }
        
    except Exception as e:
        print(f"Get me error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user data")

# ========== DISCORD TOKEN REFRESH ==========
@app.post("/api/auth/discord/refresh")
async def refresh_discord_token(token: dict = Depends(verify_token)):
    """Refresh Discord access token"""
    try:
        user_id = token.get("sub")
        
        # Get user from database
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        refresh_token = decrypt_token(user.get("discord_refresh_token", ""))
        
        if not refresh_token:
            raise HTTPException(status_code=400, detail="No refresh token available")
        
        # Request new tokens from Discord
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        
        response = requests.post('https://discord.com/api/oauth2/token', data=data,
                               headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to refresh token")
        
        token_data = response.json()
        
        # Update stored tokens
        discord_expires_at = (datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 604800))).isoformat()
        
        supabase_update("users", {
            "discord_access_token": encrypt_token(token_data.get("access_token")),
            "discord_refresh_token": encrypt_token(token_data.get("refresh_token")),
            "discord_token_expires": discord_expires_at
        }, "id", user_id)
        
        return {"success": True, "message": "Token refreshed"}
        
    except Exception as e:
        print(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh token")

# ========== LOGOUT ==========
@app.post("/api/auth/logout")
async def logout_user(token: dict = Depends(verify_token)):
    """Logout user (clear Discord tokens)"""
    try:
        user_id = token.get("sub")
        
        # Clear Discord tokens but keep user account
        supabase_update("users", {
            "discord_access_token": None,
            "discord_refresh_token": None,
            "discord_token_expires": None
        }, "id", user_id)
        
        return {"success": True, "message": "Logged out successfully"}
        
    except Exception as e:
        print(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

# ========== SERVER MANAGEMENT ==========
@app.get("/api/servers")
async def get_user_servers(token: dict = Depends(verify_token)):
    """Get user's Discord servers"""
    try:
        user_id = token.get("sub")
        users = supabase_select("users", f"id=eq.{user_id}")
        
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        access_token = decrypt_token(user.get("discord_access_token", ""))
        
        if not access_token:
            return {"servers": []}
        
        # Get fresh data from Discord
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get('https://discord.com/api/users/@me/guilds', headers=headers)
        
        if response.status_code != 200:
            # Token might be expired
            return {"servers": []}
        
        guilds_data = response.json()
        bot_guilds = []
        
        for guild in guilds_data:
            permissions = int(guild.get('permissions', 0))
            if permissions & 0x8:  # ADMINISTRATOR permission
                bot_guilds.append({
                    'id': guild['id'],
                    'name': guild['name'],
                    'icon': f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None,
                    'permissions': guild['permissions']
                })
        
        return {"servers": bot_guilds}
        
    except Exception as e:
        print(f"Get servers error: {e}")
        return {"servers": []}

# ========== TOURNAMENT API ==========
@app.post("/api/tournaments")
async def create_tournament(data: dict, token: dict = Depends(verify_token)):
    """Create tournament"""
    try:
        tournament = {
            "name": data["name"],
            "game": data["game"],
            "description": data.get("description", ""),
            "max_teams": data.get("max_teams", 16),
            "current_teams": 0,
            "bracket_type": data.get("bracket_type", "single_elimination"),
            "start_date": data["start_date"],
            "status": "registration",
            "discord_server_id": data["discord_server_id"],
            "created_by": token["sub"],
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            # Create initial bracket
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            return {"success": True, "tournament": result}
        else:
            raise HTTPException(status_code=500, detail="Failed to create tournament")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def create_initial_bracket(tournament_id: str, max_teams: int):
    """Create initial bracket structure"""
    rounds = []
    matches_per_round = max_teams // 2
    
    for round_num in range(1, 4):  # Create 3 rounds initially
        for match_num in range(1, matches_per_round + 1):
            match_data = {
                "tournament_id": tournament_id,
                "round": round_num,
                "match_number": match_num,
                "status": "pending",
                "created_at": datetime.utcnow().isoformat()
            }
            supabase_insert("brackets", match_data)
        
        matches_per_round = matches_per_round // 2

@app.get("/api/tournaments")
async def get_tournaments(server_id: Optional[str] = None, token: dict = Depends(verify_token)):
    """Get tournaments"""
    try:
        query = f"created_by=eq.{token['sub']}"
        if server_id:
            query += f"&discord_server_id=eq.{server_id}"
        
        tournaments = supabase_select("tournaments", query)
        return {"tournaments": tournaments}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_bracket(tournament_id: str, token: dict = Depends(verify_token)):
    """Get tournament bracket"""
    try:
        # Verify tournament belongs to user
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}&created_by=eq.{token['sub']}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        # Get bracket matches
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        
        # Get teams
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Organize by round
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        return {
            "tournament": tournaments[0],
            "teams": teams,
            "rounds": rounds
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== TEAM REGISTRATION ==========
@app.post("/api/teams")
async def register_team(data: dict, token: dict = Depends(verify_token)):
    """Register team for tournament"""
    try:
        # Check tournament
        tournaments = supabase_select("tournaments", f"id=eq.{data['tournament_id']}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if user is already in a team
        existing_teams = supabase_select("teams", f"tournament_id=eq.{data['tournament_id']}")
        for team in existing_teams:
            if token['sub'] in team.get('players', []):
                raise HTTPException(status_code=400, detail="Already registered in this tournament")
        
        # Create team
        team = {
            "tournament_id": data["tournament_id"],
            "name": data["name"],
            "captain_discord_id": token['sub'],
            "players": [token['sub']],
            "checked_in": False,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("teams", team)
        
        if result:
            # Update tournament team count
            supabase_update("tournaments", 
                          {"current_teams": tournament["current_teams"] + 1}, 
                          "id", tournament["id"])
            
            return {"success": True, "team": result}
        else:
            raise HTTPException(status_code=500, detail="Failed to register team")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== HEALTH CHECK ==========
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "XTourney API",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    return {
        "service": "XTourney API",
        "docs": "/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True)
