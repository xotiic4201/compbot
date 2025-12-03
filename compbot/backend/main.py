from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import os
import requests
import secrets
import hashlib
import jwt
from typing import Optional
from pydantic import BaseModel, EmailStr
import asyncio
from enum import Enum

app = FastAPI(title="XTourney API", version="2.0.0")

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

class TournamentSettings(BaseModel):
    queue_time_minutes: int = 10
    match_duration_minutes: int = 30
    max_players_per_team: int = 5
    region_filter: bool = False

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
def get_discord_user_info(user_id: str):
    """Get Discord user info"""
    try:
        headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/users/{user_id}',
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting Discord user: {e}")
        return None

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

def send_discord_message(channel_id: str, content: str, embed: dict = None, components: list = None):
    """Send message to Discord channel"""
    try:
        if not DISCORD_BOT_TOKEN:
            return False
            
        headers = {
            'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {"content": content}
        if embed:
            payload["embeds"] = [embed]
        if components:
            payload["components"] = components
            
        response = requests.post(
            f'https://discord.com/api/channels/{channel_id}/messages',
            headers=headers,
            json=payload
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Send Discord message error: {e}")
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
    return {"message": "XTourney API", "status": "running", "version": "2.0.0"}

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

# ========== BOT CHANNEL MANAGEMENT ==========
@app.post("/api/bot/channels/set")
async def bot_set_channel(data: dict):
    """Set channel via Discord bot"""
    try:
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
            "created_at": datetime.utcnow().isoformat(),
            "settings": {
                "queue_time_minutes": data.get("queue_time_minutes", 10),
                "match_duration_minutes": data.get("match_duration_minutes", 30),
                "max_players_per_team": data.get("max_players_per_team", 5),
                "region_filter": data.get("region_filter", False),
                "auto_start": data.get("auto_start", True)
            }
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            # Create initial bracket
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            # Create registration message in Discord
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
                registration_channel = next((c for c in channels if c['channel_type'] == 'registrations'), None)
                
                if registration_channel and DISCORD_BOT_TOKEN:
                    # Discord embed for registration
                    embed = {
                        "title": f"🎮 {data['name']} Registration Open!",
                        "description": f"A new {data['game']} tournament has been created!\n\n**Click the button below to register your team!**",
                        "color": 5814783,
                        "fields": [
                            {"name": "Host", "value": f"<@{discord_id}>", "inline": True},
                            {"name": "Max Teams", "value": str(data.get("max_teams", 16)), "inline": True},
                            {"name": "Start Time", "value": datetime.fromisoformat(data["start_date"].replace('Z', '+00:00')).strftime("%b %d, %Y %I:%M %p"), "inline": True},
                            {"name": "Tournament ID", "value": f"`{result['id']}`", "inline": False},
                            {"name": "Queue Time", "value": f"{data.get('queue_time_minutes', 10)} minutes", "inline": True},
                            {"name": "Region Filter", "value": "✅ Enabled" if data.get("region_filter", False) else "❌ Disabled", "inline": True}
                        ],
                        "footer": {"text": "Registration will close 10 minutes before start time"}
                    }
                    
                    # Discord components (buttons)
                    components = [
                        {
                            "type": 1,
                            "components": [
                                {
                                    "type": 2,
                                    "label": "🏆 Register Team",
                                    "style": 3,
                                    "custom_id": f"register_tournament_{result['id']}"
                                },
                                {
                                    "type": 2,
                                    "label": "📋 View Bracket",
                                    "style": 2,
                                    "custom_id": f"view_bracket_{result['id']}"
                                },
                                {
                                    "type": 2,
                                    "label": "❓ Info",
                                    "style": 2,
                                    "custom_id": f"tournament_info_{result['id']}"
                                }
                            ]
                        }
                    ]
                    
                    send_discord_message(registration_channel["discord_channel_id"], "", embed, components)
                    
            except Exception as e:
                print(f"Failed to send Discord registration: {e}")
            
            return {"success": True, "tournament": result}
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def create_initial_bracket(tournament_id: str, max_teams: int):
    """Create initial bracket matches"""
    import math
    
    # Calculate number of rounds
    num_rounds = int(math.log2(max_teams))
    
    matches_per_round = max_teams // 2
    
    for round_num in range(1, num_rounds + 1):
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
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
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
                # Get team names if assigned
                team1_name = get_team_name_by_match(match, teams, 1)
                team2_name = get_team_name_by_match(match, teams, 2)
                text += f"Match {match['match_number']}: {team1_name or 'TBD'} vs {team2_name or 'TBD'}\n"
            text += "\n"
        
        return text
    except Exception as e:
        print(f"Format bracket error: {e}")
        return "Error loading bracket"

def get_team_name_by_match(match, teams, team_position):
    """Get team name from match data"""
    try:
        if team_position == 1 and match.get('team1_id'):
            team = next((t for t in teams if t['id'] == match['team1_id']), None)
            return team['name'] if team else None
        elif team_position == 2 and match.get('team2_id'):
            team = next((t for t in teams if t['id'] == match['team2_id']), None)
            return team['name'] if team else None
    except:
        pass
    return None

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
        
        # Get player info for each team
        team_details = []
        for team in teams:
            players = []
            for player_id in team.get('players', []):
                player_info = get_discord_user_info(player_id)
                if player_info:
                    players.append({
                        'discord_id': player_id,
                        'username': player_info.get('username'),
                        'avatar': player_info.get('avatar')
                    })
            
            team_details.append({
                'id': team['id'],
                'name': team['name'],
                'players': players,
                'captain': team.get('captain_discord_id')
            })
        
        # Organize by round
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        return {
            "tournament": tournament,
            "teams": team_details,
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
            "created_at": datetime.utcnow().isoformat(),
            "settings": {
                "queue_time_minutes": data.get("queue_time_minutes", 10),
                "match_duration_minutes": data.get("match_duration_minutes", 30),
                "max_players_per_team": data.get("max_players_per_team", 5),
                "region_filter": data.get("region_filter", False),
                "auto_start": data.get("auto_start", True)
            }
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            # Send registration message to Discord
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
                registration_channel = next((c for c in channels if c['channel_type'] == 'registrations'), None)
                
                if registration_channel and DISCORD_BOT_TOKEN:
                    embed = {
                        "title": f"🎮 {data['name']} Registration Open!",
                        "description": f"A new {data['game']} tournament has been created via Discord!\n\n**Click the button below to register your team!**",
                        "color": 5814783,
                        "fields": [
                            {"name": "Host", "value": f"<@{user_id}>", "inline": True},
                            {"name": "Max Teams", "value": str(data.get("max_teams", 16)), "inline": True},
                            {"name": "Tournament ID", "value": f"`{result['id']}`", "inline": False}
                        ]
                    }
                    
                    components = [
                        {
                            "type": 1,
                            "components": [
                                {
                                    "type": 2,
                                    "label": "🏆 Register Team",
                                    "style": 3,
                                    "custom_id": f"register_tournament_{result['id']}"
                                }
                            ]
                        }
                    ]
                    
                    send_discord_message(registration_channel["discord_channel_id"], "", embed, components)
                    
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
        
        # Get player info
        team_details = []
        for team in teams:
            players = []
            for player_id in team.get('players', []):
                player_info = get_discord_user_info(player_id)
                if player_info:
                    players.append({
                        'discord_id': player_id,
                        'username': f"{player_info.get('username')}#{player_info.get('discriminator', '0')}",
                        'avatar': f"https://cdn.discordapp.com/avatars/{player_id}/{player_info.get('avatar')}.png" if player_info.get('avatar') else None
                    })
            
            team_details.append({
                'id': team['id'],
                'name': team['name'],
                'players': players,
                'captain': team.get('captain_discord_id')
            })
        
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        return {
            "tournament": tournament,
            "teams": team_details,
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
        
        # Check if registration is open
        if tournament["status"] != "registration":
            raise HTTPException(status_code=400, detail="Tournament registration is closed")
        
        # Check if already at max teams
        if tournament["current_teams"] >= tournament["max_teams"]:
            raise HTTPException(status_code=400, detail="Tournament is full")
        
        # Check if captain already registered
        existing = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        for team in existing:
            if captain_id in team.get('players', []):
                raise HTTPException(status_code=400, detail="Already registered in this tournament")
        
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
            
            # Assign team to bracket if bracket exists
            brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
            if brackets:
                # Find first available match in first round
                first_round_matches = [m for m in brackets if m["round"] == 1]
                for match in first_round_matches:
                    if not match.get("team1_id"):
                        supabase_update("brackets", {"team1_id": result["id"]}, "id", match["id"])
                        break
                    elif not match.get("team2_id"):
                        supabase_update("brackets", {"team2_id": result["id"]}, "id", match["id"])
                        break
            
            # Send notification to host
            try:
                users = supabase_select("users", f"id=eq.{tournament['created_by']}")
                if users and users[0].get('discord_id'):
                    host_id = users[0]['discord_id']
                    
                    player_info = get_discord_user_info(captain_id)
                    player_name = f"<@{captain_id}>"
                    if player_info:
                        player_name = f"{player_info.get('username')}#{player_info.get('discriminator', '0')}"
                    
                    # Get brackets channel
                    channels = supabase_select("server_channels", f"discord_server_id=eq.'{tournament['discord_server_id']}'")
                    brackets_channel = next((c for c in channels if c['channel_type'] == 'brackets'), None)
                    
                    if brackets_channel:
                        embed = {
                            "title": "✅ New Team Registered",
                            "description": f"**{team_name}** has registered for **{tournament['name']}**",
                            "color": 5763719,
                            "fields": [
                                {"name": "Captain", "value": player_name, "inline": True},
                                {"name": "Team Count", "value": f"{tournament['current_teams'] + 1}/{tournament['max_teams']}", "inline": True}
                            ],
                            "footer": {"text": f"Tournament ID: {tournament_id}"}
                        }
                        
                        send_discord_message(brackets_channel["discord_channel_id"], "", embed)
                    
            except Exception as e:
                print(f"Failed to send notification: {e}")
            
            return {"success": True, "team": result}
        raise HTTPException(status_code=500, detail="Failed to register team")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== TEAM MANAGEMENT ==========
@app.post("/api/bot/teams/add_player")
async def add_player_to_team(data: dict):
    """Add player to existing team"""
    try:
        tournament_id = data.get("tournament_id")
        team_id = data.get("team_id")
        player_id = data.get("player_discord_id")
        
        # Get tournament
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        
        # Get team
        team = supabase_select("teams", f"id=eq.{team_id}")
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        
        team = team[0]
        
        # Check max players per team
        max_players = tournament.get('settings', {}).get('max_players_per_team', 5)
        current_players = len(team.get('players', []))
        
        if current_players >= max_players:
            raise HTTPException(status_code=400, detail=f"Team already has {max_players} players")
        
        # Check if player already in tournament
        all_teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        for t in all_teams:
            if player_id in t.get('players', []):
                raise HTTPException(status_code=400, detail="Player already registered in this tournament")
        
        # Add player to team
        updated_players = team.get('players', [])
        if player_id not in updated_players:
            updated_players.append(player_id)
            
            supabase_update("teams", {"players": updated_players}, "id", team_id)
            
            # Get player info
            player_info = get_discord_user_info(player_id)
            player_name = f"<@{player_id}>"
            if player_info:
                player_name = f"{player_info.get('username')}#{player_info.get('discriminator', '0')}"
            
            return {
                "success": True,
                "message": f"{player_name} added to {team['name']}",
                "team_size": len(updated_players)
            }
        else:
            raise HTTPException(status_code=400, detail="Player already in team")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== REGION FILTERING ==========
def get_user_server_region(user_id: str, server_id: str):
    """Get user's server region (approximated by server creation location)"""
    try:
        headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{server_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            guild = response.json()
            # Discord doesn't expose region directly, but we can use features
            features = guild.get('features', [])
            
            # Check for regional features
            if 'VANITY_URL' in features:
                return "na"  # North America
            elif 'INVITE_SPLASH' in features:
                return "eu"  # Europe
            else:
                return "global"
        
        return "global"
    except Exception as e:
        print(f"Get region error: {e}")
        return "global"

# ========== TOURNAMENT AUTO-START ==========
async def auto_start_tournament(tournament_id: str):
    """Automatically start tournament when conditions are met"""
    try:
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            return
        
        tournament = tournament[0]
        
        # Check if tournament should auto-start
        settings = tournament.get('settings', {})
        if not settings.get('auto_start', True):
            return
        
        # Check if registration is open
        if tournament['status'] != 'registration':
            return
        
        # Check if max teams reached or time reached
        current_time = datetime.utcnow()
        start_time = datetime.fromisoformat(tournament['start_date'].replace('Z', '+00:00'))
        
        # Check if we should start now
        if tournament['current_teams'] >= tournament['max_teams'] or current_time >= start_time:
            # Update tournament status
            supabase_update("tournaments", {"status": "ongoing"}, "id", tournament_id)
            
            # Generate bracket
            generate_final_bracket(tournament_id)
            
            # Send notification
            channels = supabase_select("server_channels", f"discord_server_id=eq.'{tournament['discord_server_id']}'")
            announcements_channel = next((c for c in channels if c['channel_type'] == 'announcements'), None)
            
            if announcements_channel:
                embed = {
                    "title": "🏁 Tournament Starting!",
                    "description": f"**{tournament['name']}** has started!\n\nCheck the brackets channel for matchups.",
                    "color": 16776960,
                    "fields": [
                        {"name": "Teams", "value": str(tournament['current_teams']), "inline": True},
                        {"name": "Status", "value": "LIVE", "inline": True}
                    ]
                }
                
                send_discord_message(announcements_channel["discord_channel_id"], "", embed)
    
    except Exception as e:
        print(f"Auto-start error: {e}")

def generate_final_bracket(tournament_id: str):
    """Generate final bracket with all teams"""
    try:
        # Get all teams
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Get tournament
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            return
        
        tournament = tournament[0]
        
        # Clear existing bracket assignments
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        
        # Shuffle teams for random seeding
        import random
        random.shuffle(teams)
        
        # Assign teams to first round matches
        first_round_matches = [m for m in brackets if m["round"] == 1]
        
        for i, team in enumerate(teams):
            if i < len(first_round_matches) * 2:  # 2 teams per match
                match_index = i // 2
                team_position = i % 2 + 1  # 1 or 2
                
                match = first_round_matches[match_index]
                if team_position == 1:
                    supabase_update("brackets", {"team1_id": team["id"]}, "id", match["id"])
                else:
                    supabase_update("brackets", {"team2_id": team["id"]}, "id", match["id"])
    
    except Exception as e:
        print(f"Generate bracket error: {e}")

# ========== BOT INTERACTION ENDPOINTS ==========
@app.post("/api/bot/interactions/register")
async def handle_registration_interaction(data: dict):
    """Handle Discord button click for registration"""
    try:
        interaction_type = data.get("type")
        
        if interaction_type == 1:  # PING
            return {"type": 1}
        
        elif interaction_type == 2:  # APPLICATION_COMMAND
            # Handle slash commands
            pass
        
        elif interaction_type == 3:  # MESSAGE_COMPONENT
            custom_id = data.get("data", {}).get("custom_id", "")
            user_id = data.get("member", {}).get("user", {}).get("id", "")
            
            if custom_id.startswith("register_tournament_"):
                tournament_id = custom_id.split("_")[-1]
                
                # Open modal for team registration
                return {
                    "type": 9,  # MODAL
                    "data": {
                        "custom_id": f"team_registration_{tournament_id}",
                        "title": "Register Team",
                        "components": [
                            {
                                "type": 1,
                                "components": [
                                    {
                                        "type": 4,
                                        "custom_id": "team_name",
                                        "label": "Team Name",
                                        "style": 1,
                                        "min_length": 3,
                                        "max_length": 32,
                                        "placeholder": "Enter your team name",
                                        "required": True
                                    }
                                ]
                            },
                            {
                                "type": 1,
                                "components": [
                                    {
                                        "type": 4,
                                        "custom_id": "player_tags",
                                        "label": "Player Discord Tags (comma separated)",
                                        "style": 2,
                                        "min_length": 1,
                                        "placeholder": "@player1, @player2, @player3",
                                        "required": False
                                    }
                                ]
                            }
                        ]
                    }
                }
        
        return {"type": 4, "data": {"content": "Interaction handled", "flags": 64}}
        
    except Exception as e:
        print(f"Interaction error: {e}")
        return {"type": 4, "data": {"content": f"Error: {str(e)}", "flags": 64}}

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
