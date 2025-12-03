from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import os
import requests
import secrets
import hashlib
from typing import Optional
from pydantic import BaseModel, EmailStr

app = FastAPI(title="XTourney API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

class ChannelConfig(BaseModel):
    discord_server_id: str
    channel_type: str
    discord_channel_id: str
    channel_name: str

# ========== SUPABASE SETUP ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "your-supabase-url")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-supabase-key")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-discord-secret")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "your-bot-token")

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
        print(f"Supabase insert error {response.status_code}: {response.text}")
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
        if response.status_code == 200:
            return response.json()
        print(f"Supabase select error {response.status_code}: {response.text}")
        return []
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
        if response.status_code == 200:
            return response.json()
        print(f"Supabase update error {response.status_code}: {response.text}")
        return []
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

# ========== DISCORD BOT FUNCTIONS ==========
def get_discord_user_roles(guild_id: str, user_id: str):
    """Get user's roles in a Discord server"""
    try:
        if not DISCORD_BOT_TOKEN:
            return []
            
        headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{guild_id}/members/{user_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('roles', [])
        return []
    except Exception as e:
        print(f"Error getting Discord roles: {e}")
        return []

def check_host_permission(guild_id: str, user_id: str):
    """Check if user has HOST role"""
    try:
        user_roles = get_discord_user_roles(guild_id, user_id)
        
        # Get server roles to check names
        headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{guild_id}/roles',
            headers=headers
        )
        
        if response.status_code == 200:
            guild_roles = response.json()
            
            # Look for HOST role
            for role in guild_roles:
                if role['name'].lower() in ['host', 'tournament host', 'tournament organizer']:
                    if role['id'] in user_roles:
                        return True
        return False
    except Exception as e:
        print(f"Permission check error: {e}")
        return False

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

# ========== HEALTH CHECK ==========
@app.get("/")
async def root():
    return {"message": "XTourney API", "status": "running"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ========== DISCORD AUTH ==========
@app.post("/api/auth/discord")
async def discord_auth(request: DiscordAuthRequest):
    """Discord OAuth2 authentication"""
    try:
        print(f"Discord auth request for redirect: {request.redirect_uri}")
        
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
        access_token = token_data.get("access_token")
        
        # Get user info
        user_headers = {'Authorization': f'Bearer {access_token}'}
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
            if permissions & 0x8:  # ADMINISTRATOR permission
                bot_guilds.append({
                    'id': guild['id'],
                    'name': guild['name'],
                    'icon': f"https://cdn.discordapp.com/icons/{guild['id']}/{guild.get('icon', '')}.png" if guild.get('icon') else None,
                    'permissions': guild['permissions']
                })
        
        # Create username
        discord_username = f"{user_data['username']}"
        if user_data.get('discriminator') and user_data['discriminator'] != '0':
            discord_username = f"{user_data['username']}#{user_data['discriminator']}"
        
        # Check if user exists
        existing = supabase_select("users", f"discord_id=eq.'{user_data['id']}'")
        
        if existing:
            user_id = existing[0]['id']
            # Update user
            supabase_update("users", {
                "last_login": datetime.utcnow().isoformat()
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
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": discord_username,
            "discord_id": user_data["id"],
            "account_type": "discord"
        })
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": discord_username,
                "avatar": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else None,
                "discord_id": user_data["id"]
            },
            "servers": bot_guilds,
            "access_token": jwt_token
        }
        
    except Exception as e:
        print(f"Discord auth error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== EMAIL AUTH ==========
@app.post("/api/auth/register")
async def register_email(request: EmailRegisterRequest):
    """Register with email and password"""
    try:
        print(f"Registration attempt for: {request.email}")
        
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
async def get_current_user(token: dict = Depends(verify_token)):
    """Get current user"""
    try:
        user_id = token.get("sub")
        
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        user.pop("password_hash", None)
        
        return {"user": user}
        
    except Exception as e:
        print(f"Get me error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== CHANNEL MANAGEMENT ==========
@app.post("/channels/set")
async def set_channel(channel: ChannelConfig):
    """Set channel for tournament purposes"""
    try:
        channel_data = {
            "discord_server_id": channel.discord_server_id,
            "channel_type": channel.channel_type,
            "discord_channel_id": channel.discord_channel_id,
            "channel_name": channel.channel_name,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Check if exists
        existing = supabase_select("server_channels", 
                                 f"discord_server_id=eq.'{channel.discord_server_id}' AND channel_type=eq.'{channel.channel_type}'")
        
        if existing:
            result = supabase_update("server_channels", channel_data, 
                                   "discord_server_id", channel.discord_server_id)
        else:
            channel_data["created_at"] = datetime.utcnow().isoformat()
            result = supabase_insert("server_channels", channel_data)
        
        if result:
            return {"success": True}
        raise HTTPException(status_code=500, detail="Failed to save channel")
            
    except Exception as e:
        print(f"Set channel error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/channels/{server_id}")
async def get_channels(server_id: str):
    """Get all channels for a server"""
    try:
        channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
        return channels
    except Exception as e:
        print(f"Get channels error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== TOURNAMENT MANAGEMENT ==========
@app.post("/api/tournaments")
async def create_tournament(data: dict, token: dict = Depends(verify_token)):
    """Create tournament - requires HOST role"""
    try:
        user_id = token.get("sub")
        
        # Get user
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        discord_id = user.get("discord_id")
        server_id = data.get("discord_server_id")
        
        # Check Discord connection and HOST role
        if not discord_id:
            raise HTTPException(status_code=403, detail="Connect Discord account to create tournaments")
        
        if not server_id:
            raise HTTPException(status_code=400, detail="Server ID is required")
        
        # Check HOST permission
        has_permission = check_host_permission(server_id, discord_id)
        if not has_permission:
            raise HTTPException(status_code=403, detail="You need HOST role to create tournaments")
        
        # Create tournament
        tournament = {
            "name": data["name"],
            "game": data["game"],
            "description": data.get("description", ""),
            "max_teams": data.get("max_teams", 16),
            "current_teams": 0,
            "bracket_type": data.get("bracket_type", "single_elimination"),
            "start_date": data["start_date"],
            "status": "registration",
            "discord_server_id": server_id,
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            # Create initial bracket
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            # Send to Discord if brackets channel is set
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
                brackets_channel = next((c for c in channels if c['channel_type'] == 'brackets'), None)
                
                if brackets_channel and DISCORD_BOT_TOKEN:
                    # Format bracket for Discord
                    bracket_text = format_bracket_for_discord(result["id"])
                    
                    headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
                    requests.post(
                        f'https://discord.com/api/channels/{brackets_channel["discord_channel_id"]}/messages',
                        headers=headers,
                        json={
                            "content": f"🎮 **New Tournament Created: {data['name']}**\n\n{bracket_text}"
                        }
                    )
            except Exception as e:
                print(f"Failed to send to Discord: {e}")
            
            return {"success": True, "tournament": result}
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def create_initial_bracket(tournament_id: str, max_teams: int):
    """Create initial bracket matches"""
    matches_per_round = max_teams // 2
    
    for round_num in range(1, 4):
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

def format_bracket_for_discord(tournament_id: str):
    """Format bracket for Discord message"""
    try:
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            return "Bracket not available"
        
        tournament = tournament[0]
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        
        text = f"**{tournament['name']}** - {tournament['game']}\n"
        text += f"Teams: {tournament['current_teams']}/{tournament['max_teams']}\n"
        text += f"Type: {tournament['bracket_type'].replace('_', ' ').title()}\n\n"
        
        # Group by round
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        for round_num in sorted(rounds.keys()):
            text += f"**Round {round_num}:**\n"
            for match in rounds[round_num]:
                text += f"Match {match['match_number']}: TBD vs TBD\n"
            text += "\n"
        
        return text
    except Exception as e:
        print(f"Format bracket error: {e}")
        return "Error loading bracket"

@app.get("/api/tournaments")
async def get_tournaments(token: dict = Depends(verify_token)):
    """Get user's tournaments"""
    try:
        user_id = token.get("sub")
        tournaments = supabase_select("tournaments", f"created_by=eq.{user_id}")
        return {"tournaments": tournaments}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_bracket(tournament_id: str, token: dict = Depends(verify_token)):
    """Get tournament bracket"""
    try:
        user_id = token.get("sub")
        
        # Verify ownership
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}&created_by=eq.{user_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Organize by round
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        return {
            "tournament": tournament,
            "teams": teams,
            "rounds": rounds
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/tournaments")
async def create_tournament_bot(data: dict):
    """Create tournament via Discord bot"""
    try:
        user_id = data.get("created_by")
        server_id = data.get("discord_server_id")
        
        # Check HOST permission
        if not check_host_permission(server_id, user_id):
            raise HTTPException(status_code=403, detail="Need HOST role")
        
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
            "name": data["name"],
            "game": data["game"],
            "description": data.get("description", ""),
            "max_teams": data.get("max_teams", 16),
            "current_teams": 0,
            "bracket_type": data.get("bracket_type", "single_elimination"),
            "start_date": data["start_date"],
            "status": "registration",
            "discord_server_id": server_id,
            "created_by": db_user_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            # Send bracket to Discord
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
                brackets_channel = next((c for c in channels if c['channel_type'] == 'brackets'), None)
                
                if brackets_channel and DISCORD_BOT_TOKEN:
                    bracket_text = format_bracket_for_discord(result["id"])
                    
                    headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
                    requests.post(
                        f'https://discord.com/api/channels/{brackets_channel["discord_channel_id"]}/messages',
                        headers=headers,
                        json={
                            "content": f"🎮 **Tournament Created via Bot: {data['name']}**\n\n{bracket_text}"
                        }
                    )
            except Exception as e:
                print(f"Failed to send bracket to Discord: {e}")
            
            return {"success": True, "tournament": result}
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Bot tournament creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bot/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket_bot(tournament_id: str):
    """Get tournament bracket for bot"""
    try:
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        return {
            "tournament": tournament,
            "teams": teams,
            "rounds": rounds
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/bot/teams")
async def register_team_bot(data: dict):
    """Register team via bot"""
    try:
        tournament_id = data.get("tournament_id")
        team_name = data.get("name")
        captain_id = data.get("captain_discord_id")
        
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        
        # Check if already registered
        existing = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        for team in existing:
            if captain_id in team.get('players', []):
                raise HTTPException(status_code=400, detail="Already registered")
        
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
            # Update team count
            supabase_update("tournaments", 
                          {"current_teams": tournament["current_teams"] + 1}, 
                          "id", tournament["id"])
            
            return {"success": True, "team": result}
        raise HTTPException(status_code=500, detail="Failed to register team")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

