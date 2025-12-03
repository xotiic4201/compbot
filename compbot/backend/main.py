from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import os
import requests
import secrets
import hashlib
import jwt
import asyncio
import random
from typing import Optional, List, Dict
from pydantic import BaseModel, EmailStr
import math

app = FastAPI(title="XTourney API", version="3.0.0")

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

class TeamRegistration(BaseModel):
    tournament_id: str
    team_name: str
    captain_discord_id: str
    players: List[str] = []

# ========== SUPABASE SETUP ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-client-secret")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "your-bot-token")

headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

# Database helper functions
def supabase_insert(table: str, data: dict):
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        if response.status_code in [200, 201]:
            return response.json()[0] if response.json() else None
        print(f"Supabase insert error {response.status_code}: {response.text}")
        return None
    except Exception as e:
        print(f"Supabase insert error: {e}")
        return None

def supabase_select(table: str, query: str = ""):
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

def supabase_update(table: str, data: dict, column: str, value: str):
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

def supabase_delete(table: str, column: str, value: str):
    try:
        response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            headers=headers
        )
        return response.status_code == 204
    except Exception as e:
        print(f"Supabase delete error: {e}")
        return False

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

# ========== DISCORD FUNCTIONS ==========
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

def get_discord_guild_info(guild_id: str):
    """Get Discord server info"""
    try:
        headers = {'Authorization': f'Bot {DISCORD_BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{guild_id}',
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting Discord guild: {e}")
        return None

def get_discord_user_roles(guild_id: str, user_id: str):
    """Get user's roles in a Discord server"""
    try:
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
                role_name_lower = role['name'].lower()
                if any(keyword in role_name_lower for keyword in ['host', 'tournament', 'organizer', 'admin']):
                    if role['id'] in user_roles:
                        return True
        
        # Check if user is server owner
        guild_info = get_discord_guild_info(guild_id)
        if guild_info and guild_info.get('owner_id') == user_id:
            return True
            
        return False
    except Exception as e:
        print(f"Permission check error: {e}")
        return False

def send_discord_message(channel_id: str, content: str = None, embed: dict = None, components: list = None):
    """Send message to Discord channel"""
    try:
        if not DISCORD_BOT_TOKEN:
            return False
            
        headers = {
            'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {}
        if content:
            payload["content"] = content
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
    return {"message": "XTourney API", "status": "running", "version": "3.0.0"}

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
        
        # Filter to guilds where user has admin permissions or bot is present
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
                "auto_start": data.get("auto_start", True),
                "server_filter": data.get("server_filter", True)
            }
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            # Create initial bracket
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            # Send to Discord if channels are set
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{server_id}'")
                registration_channel = next((c for c in channels if c['channel_type'] == 'registrations'), None)
                
                if registration_channel and DISCORD_BOT_TOKEN:
                    # Create registration embed
                    start_time = datetime.fromisoformat(data["start_date"].replace('Z', '+00:00'))
                    
                    embed = {
                        "title": f"🎮 {data['name']} - Registration Open!",
                        "description": f"**{data['game']} Tournament**\n\nClick the register button below to join!",
                        "color": 5763719,
                        "fields": [
                            {"name": "Host", "value": f"<@{discord_id}>", "inline": True},
                            {"name": "Max Teams", "value": str(data.get("max_teams", 16)), "inline": True},
                            {"name": "Start Time", "value": start_time.strftime("%b %d, %I:%M %p"), "inline": True},
                            {"name": "Queue Time", "value": f"{data.get('queue_time_minutes', 10)} min", "inline": True},
                            {"name": "Players/Team", "value": str(data.get('max_players_per_team', 5)), "inline": True},
                            {"name": "Tournament ID", "value": f"`{result['id']}`", "inline": False}
                        ],
                        "footer": {"text": "Registration closes 10 minutes before start"}
                    }
                    
                    # Create button components
                    components = [
                        {
                            "type": 1,
                            "components": [
                                {
                                    "type": 2,
                                    "label": "🏆 Register Now",
                                    "style": 3,
                                    "custom_id": f"register_{result['id']}"
                                },
                                {
                                    "type": 2,
                                    "label": "📋 View Info",
                                    "style": 2,
                                    "custom_id": f"info_{result['id']}"
                                }
                            ]
                        }
                    ]
                    
                    send_discord_message(registration_channel["discord_channel_id"], "", embed, components)
                    
            except Exception as e:
                print(f"Failed to send Discord registration: {e}")
            
            return {"success": True, "tournament": result, "message": "Tournament created successfully!"}
        raise HTTPException(status_code=500, detail="Failed to create tournament")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def create_initial_bracket(tournament_id: str, max_teams: int):
    """Create initial bracket matches"""
    try:
        # Calculate number of rounds for bracket
        rounds = int(math.log2(max_teams))
        
        for round_num in range(1, rounds + 1):
            matches_in_round = max_teams // (2 ** round_num)
            
            for match_num in range(1, matches_in_round + 1):
                match_data = {
                    "tournament_id": tournament_id,
                    "round": round_num,
                    "match_number": match_num,
                    "status": "pending",
                    "created_at": datetime.utcnow().isoformat()
                }
                supabase_insert("brackets", match_data)
                
    except Exception as e:
        print(f"Create bracket error: {e}")

@app.get("/api/tournaments")
async def get_tournaments(token: dict = Depends(verify_token)):
    """Get user's tournaments"""
    try:
        user_id = token.get("sub")
        tournaments = supabase_select("tournaments", f"created_by=eq.{user_id}")
        
        # Add server names
        for tournament in tournaments:
            server_info = get_discord_guild_info(tournament.get('discord_server_id', ''))
            if server_info:
                tournament['server_name'] = server_info.get('name', 'Unknown Server')
            else:
                tournament['server_name'] = 'Unknown Server'
        
        return {"tournaments": tournaments}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str, token: dict = Depends(verify_token)):
    """Get specific tournament"""
    try:
        user_id = token.get("sub")
        
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Verify ownership (optional for viewing)
        if tournament.get('created_by') != user_id:
            # Check if user is host via Discord
            user = supabase_select("users", f"id=eq.{user_id}")
            if user and user[0].get('discord_id'):
                discord_id = user[0]['discord_id']
                if not check_host_permission(tournament.get('discord_server_id'), discord_id):
                    raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get teams
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Get player info for each team
        team_details = []
        for team in teams:
            players = []
            for player_id in team.get('players', []):
                player_info = get_discord_user_info(player_id)
                if player_info:
                    username = player_info.get('username', 'Unknown')
                    discriminator = player_info.get('discriminator', '0')
                    if discriminator != '0':
                        username = f"{username}#{discriminator}"
                    
                    players.append({
                        'discord_id': player_id,
                        'username': username,
                        'avatar': f"https://cdn.discordapp.com/avatars/{player_id}/{player_info.get('avatar')}.png" if player_info.get('avatar') else None
                    })
            
            team_details.append({
                'id': team['id'],
                'name': team['name'],
                'players': players,
                'captain': team.get('captain_discord_id'),
                'checked_in': team.get('checked_in', False)
            })
        
        # Get bracket
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        
        # Organize by round
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        # Sort rounds
        sorted_rounds = {k: rounds[k] for k in sorted(rounds.keys())}
        
        return {
            "tournament": tournament,
            "teams": team_details,
            "rounds": sorted_rounds
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tournaments/{tournament_id}/bracket")
async def get_tournament_bracket(tournament_id: str, token: dict = Depends(verify_token)):
    """Get tournament bracket"""
    try:
        # Use same logic as get_tournament but for bracket endpoint
        return await get_tournament(tournament_id, token)
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
            raise HTTPException(status_code=403, detail="Need HOST role to create tournaments")
        
        # Check if user exists in database
        users = supabase_select("users", f"discord_id=eq.'{user_id}'")
        if not users:
            # Create user if doesn't exist
            user_info = get_discord_user_info(user_id)
            username = f"Discord User {user_id[:8]}"
            if user_info:
                username = user_info.get('username', username)
                if user_info.get('discriminator') and user_info['discriminator'] != '0':
                    username = f"{username}#{user_info['discriminator']}"
            
            user_db = {
                "discord_id": user_id,
                "username": username,
                "avatar_url": f"https://cdn.discordapp.com/avatars/{user_id}/{user_info.get('avatar', '')}.png" if user_info and user_info.get('avatar') else None,
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
                "auto_start": data.get("auto_start", True),
                "server_filter": data.get("server_filter", True)
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
                    start_time = datetime.fromisoformat(data["start_date"].replace('Z', '+00:00'))
                    
                    embed = {
                        "title": f"🎮 {data['name']} - Bot Created!",
                        "description": f"**{data['game']} Tournament**\n\nUse `/team register {result['id']}` to join!",
                        "color": 5763719,
                        "fields": [
                            {"name": "Host", "value": f"<@{user_id}>", "inline": True},
                            {"name": "Max Teams", "value": str(data.get("max_teams", 16)), "inline": True},
                            {"name": "Start Time", "value": start_time.strftime("%b %d, %I:%M %p"), "inline": True},
                            {"name": "Tournament ID", "value": f"`{result['id']}`", "inline": False}
                        ]
                    }
                    
                    send_discord_message(registration_channel["discord_channel_id"], "", embed)
                    
            except Exception as e:
                print(f"Failed to send Discord message: {e}")
            
            return {"success": True, "tournament": result, "message": "Tournament created via bot!"}
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
                    username = player_info.get('username', 'Unknown')
                    discriminator = player_info.get('discriminator', '0')
                    if discriminator != '0':
                        username = f"{username}#{discriminator}"
                    
                    players.append({
                        'discord_id': player_id,
                        'username': username,
                        'mention': f"<@{player_id}>"
                    })
            
            team_details.append({
                'id': team['id'],
                'name': team['name'],
                'players': players,
                'captain': team.get('captain_discord_id'),
                'checked_in': team.get('checked_in', False)
            })
        
        rounds = {}
        for match in brackets:
            round_num = match["round"]
            if round_num not in rounds:
                rounds[round_num] = []
            rounds[round_num].append(match)
        
        # Sort rounds
        sorted_rounds = {k: rounds[k] for k in sorted(rounds.keys())}
        
        return {
            "tournament": tournament,
            "teams": team_details,
            "rounds": sorted_rounds
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bot/tournaments/server/{server_id}")
async def get_server_tournaments(server_id: str):
    """Get all tournaments for a server"""
    try:
        tournaments = supabase_select("tournaments", f"discord_server_id=eq.'{server_id}'")
        return {"tournaments": tournaments}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== TEAM REGISTRATION ==========
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
        existing_teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        for team in existing_teams:
            if captain_id in team.get('players', []):
                raise HTTPException(status_code=400, detail="Already registered in this tournament")
        
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
            
            # Send notification
            try:
                channels = supabase_select("server_channels", f"discord_server_id=eq.'{tournament['discord_server_id']}'")
                brackets_channel = next((c for c in channels if c['channel_type'] == 'brackets'), None)
                
                if brackets_channel:
                    player_info = get_discord_user_info(captain_id)
                    player_name = f"<@{captain_id}>"
                    if player_info:
                        username = player_info.get('username', 'Unknown')
                        discriminator = player_info.get('discriminator', '0')
                        if discriminator != '0':
                            username = f"{username}#{discriminator}"
                        player_name = f"{username} (<@{captain_id}>)"
                    
                    embed = {
                        "title": "✅ Team Registered!",
                        "description": f"**{team_name}** has joined **{tournament['name']}**",
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
            
            return {"success": True, "team": result, "message": "Team registered successfully!"}
        raise HTTPException(status_code=500, detail="Failed to register team")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/bot/teams/add_player")
async def add_player_to_team(data: dict):
    """Add player to existing team"""
    try:
        tournament_id = data.get("tournament_id")
        team_id = data.get("team_id")
        player_id = data.get("player_discord_id")
        
        if not all([tournament_id, team_id, player_id]):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
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
        
        # Check if player is captain
        if team.get('captain_discord_id') != data.get('requester_id'):
            raise HTTPException(status_code=403, detail="Only team captain can add players")
        
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
                username = player_info.get('username', 'Unknown')
                discriminator = player_info.get('discriminator', '0')
                if discriminator != '0':
                    username = f"{username}#{discriminator}"
                player_name = f"{username} (<@{player_id}>)"
            
            return {
                "success": True,
                "message": f"{player_name} added to {team['name']}",
                "team_size": len(updated_players)
            }
        else:
            raise HTTPException(status_code=400, detail="Player already in team")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== TOURNAMENT START ==========
@app.post("/api/bot/tournaments/{tournament_id}/start")
async def start_tournament_bot(tournament_id: str, data: dict = None):
    """Start tournament via bot"""
    try:
        tournament = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournament[0]
        
        # Check if user has permission to start
        requester_id = data.get('requester_id') if data else None
        if requester_id and not check_host_permission(tournament['discord_server_id'], requester_id):
            raise HTTPException(status_code=403, detail="Only host can start tournament")
        
        # Check if tournament has enough teams
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        if len(teams) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 teams to start")
        
        # Update tournament status
        supabase_update("tournaments", {"status": "ongoing"}, "id", tournament_id)
        
        # Generate final bracket
        generate_final_bracket(tournament_id, teams)
        
        # Send announcement
        try:
            channels = supabase_select("server_channels", f"discord_server_id=eq.'{tournament['discord_server_id']}'")
            announcements_channel = next((c for c in channels if c['channel_type'] == 'announcements'), None)
            
            if announcements_channel:
                embed = {
                    "title": "🏁 TOURNAMENT STARTED!",
                    "description": f"**{tournament['name']}** is now LIVE!",
                    "color": 16776960,
                    "fields": [
                        {"name": "Teams", "value": str(len(teams)), "inline": True},
                        {"name": "Game", "value": tournament['game'], "inline": True},
                        {"name": "Bracket", "value": "Check brackets channel for matches", "inline": False}
                    ]
                }
                
                send_discord_message(announcements_channel["discord_channel_id"], "@everyone", embed)
                
        except Exception as e:
            print(f"Failed to send announcement: {e}")
        
        return {"success": True, "message": "Tournament started successfully!"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def generate_final_bracket(tournament_id: str, teams: list):
    """Generate final bracket with all teams"""
    try:
        # Clear existing bracket assignments
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        
        # Shuffle teams for random seeding
        random.shuffle(teams)
        
        # Assign teams to first round matches
        first_round_matches = [m for m in brackets if m["round"] == 1]
        
        for i, team in enumerate(teams):
            if i < len(first_round_matches) * 2:  # 2 teams per match
                match_index = i // 2
                team_position = i % 2 + 1  # 1 or 2
                
                match = first_round_matches[match_index]
                update_data = {"status": "upcoming"}
                if team_position == 1:
                    update_data["team1_id"] = team["id"]
                else:
                    update_data["team2_id"] = team["id"]
                
                supabase_update("brackets", update_data, "id", match["id"])
        
        # Set remaining matches as byes
        for i in range(len(teams), len(first_round_matches) * 2):
            match_index = i // 2
            team_position = i % 2 + 1
            
            match = first_round_matches[match_index]
            if team_position == 1 and not match.get("team1_id"):
                supabase_update("brackets", {"team1_id": "BYE", "status": "completed"}, "id", match["id"])
            elif team_position == 2 and not match.get("team2_id"):
                supabase_update("brackets", {"team2_id": "BYE", "status": "completed"}, "id", match["id"])
    
    except Exception as e:
        print(f"Generate bracket error: {e}")

# ========== LIVE MATCHES ==========
@app.get("/api/bot/tournaments/{tournament_id}/live")
async def get_live_matches(tournament_id: str):
    """Get live matches for tournament"""
    try:
        brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        # Find ongoing matches
        live_matches = []
        for match in brackets:
            if match.get("status") == "ongoing":
                team1 = next((t for t in teams if t['id'] == match.get('team1_id')), None)
                team2 = next((t for t in teams if t['id'] == match.get('team2_id')), None)
                
                # Get player mentions
                team1_players = []
                team2_players = []
                
                if team1:
                    for player_id in team1.get('players', []):
                        team1_players.append(f"<@{player_id}>")
                
                if team2:
                    for player_id in team2.get('players', []):
                        team2_players.append(f"<@{player_id}>")
                
                live_matches.append({
                    "round": match["round"],
                    "match_number": match["match_number"],
                    "team1": {
                        "id": team1["id"] if team1 else None,
                        "name": team1["name"] if team1 else "BYE",
                        "players": team1_players,
                        "score": match.get("score_team1", 0)
                    },
                    "team2": {
                        "id": team2["id"] if team2 else None,
                        "name": team2["name"] if team2 else "BYE",
                        "players": team2_players,
                        "score": match.get("score_team2", 0)
                    },
                    "start_time": match.get("start_time"),
                    "estimated_end": match.get("estimated_end")
                })
        
        return {"live_matches": live_matches}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== AUTO-START BACKGROUND TASK ==========
async def check_auto_start_tournaments():
    """Background task to check and auto-start tournaments"""
    while True:
        try:
            # Get tournaments that should auto-start
            tournaments = supabase_select("tournaments", "status=eq.registration")
            
            for tournament in tournaments:
                settings = tournament.get('settings', {})
                
                if settings.get('auto_start', True):
                    # Check if max teams reached
                    if tournament['current_teams'] >= tournament['max_teams']:
                        # Auto-start tournament
                        await start_tournament_bot(tournament['id'], {"requester_id": "auto_start"})
                    
                    # Check if start time passed
                    start_time = datetime.fromisoformat(tournament['start_date'].replace('Z', '+00:00'))
                    if datetime.utcnow() >= start_time and tournament['current_teams'] >= 2:
                        # Auto-start tournament
                        await start_tournament_bot(tournament['id'], {"requester_id": "auto_start"})
            
            # Wait 1 minute before next check
            await asyncio.sleep(60)
            
        except Exception as e:
            print(f"Auto-start check error: {e}")
            await asyncio.sleep(60)

# Start background task on startup
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(check_auto_start_tournaments())

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
