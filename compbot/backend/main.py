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
import jwt

app = FastAPI(title="XTourney API", version="7.0.0")

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
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1445127821742575726")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "your-client-secret")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us/")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

# ========== PYDANTIC MODELS ==========
class DiscordAuthRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    token: str

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

# ========== DATABASE FUNCTIONS ==========
def supabase_insert(table: str, data: dict):
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        print(f"Insert response: {response.status_code} - {response.text[:200]}")
        if response.status_code in [200, 201]:
            return response.json()[0] if response.json() else None
        print(f"Insert error {response.status_code}: {response.text[:200]}")
        return None
    except Exception as e:
        print(f"Insert exception: {str(e)}")
        return None

def supabase_select(table: str, query: str = ""):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        print(f"Select URL: {url}")
        response = requests.get(url, headers=headers)
        print(f"Select response: {response.status_code} - {response.text[:200]}")
        if response.status_code == 200:
            return response.json()
        print(f"Select error {response.status_code}: {response.text[:200]}")
        return []
    except Exception as e:
        print(f"Select exception: {str(e)}")
        return []

def supabase_update(table: str, data: dict, column: str, value: str):
    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        print(f"Update response: {response.status_code} - {response.text[:200]}")
        if response.status_code == 200:
            return response.json()
        print(f"Update error {response.status_code}: {response.text[:200]}")
        return []
    except Exception as e:
        print(f"Update exception: {str(e)}")
        return []

# ========== JWT FUNCTIONS ==========
def create_jwt_token(data: dict):
    """Create JWT token using pyjwt"""
    payload = data.copy()
    payload['exp'] = datetime.utcnow() + timedelta(days=7)
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
    return {"message": "XTourney API", "status": "running", "version": "7.0.0"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ========== PUBLIC MATCHES (NO LOGIN REQUIRED) ==========
@app.get("/api/matches/live")
async def get_live_matches():
    """Get live matches - Public endpoint"""
    try:
        tournaments = supabase_select("tournaments", "status=eq.ongoing")
        
        matches = []
        for tournament in tournaments[:10]:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament['id']}")
            
            if len(teams) >= 2:
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
        
        return {
            "success": True,
            "matches": matches,
            "count": len(matches)
        }
    except Exception as e:
        print(f"Get live matches error: {str(e)}")
        return {"success": False, "matches": [], "count": 0}

@app.get("/api/tournaments/public")
async def get_public_tournaments():
    """Get public tournaments - No login required"""
    try:
        tournaments = supabase_select("tournaments", "limit=20")
        
        for tournament in tournaments:
            teams = supabase_select("teams", f"tournament_id=eq.{tournament['id']}")
            tournament['team_count'] = len(teams)
            tournament['registered_teams'] = len(teams)
            
        return {
            "success": True,
            "tournaments": tournaments,
            "count": len(tournaments)
        }
    except Exception as e:
        print(f"Get tournaments error: {str(e)}")
        return {"success": False, "tournaments": [], "count": 0}

@app.get("/api/tournaments/{tournament_id}/public")
async def get_tournament_public(tournament_id: str):
    """Get tournament details - Public"""
    try:
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
        
        return {
            "success": True,
            "tournament": tournament,
            "teams": teams,
            "team_count": len(teams)
        }
    except Exception as e:
        print(f"Get tournament error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== DISCORD AUTH ==========
@app.get("/api/auth/discord")
async def discord_auth():
    """Start Discord OAuth flow"""
    redirect_uri = f"{FRONTEND_URL}/auth/callback"
    
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope=identify%20email%20guilds&"
        f"prompt=consent"
    )
    return RedirectResponse(url=discord_auth_url)

@app.post("/api/auth/discord/token")
async def discord_auth_token(request: DiscordAuthRequest):
    """Exchange Discord code for token - FIXED USER CREATION"""
    try:
        print(f"Discord auth with code: {request.code[:20]}...")
        
        redirect_uri = request.redirect_uri or FRONTEND_URL
        
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': request.code,
            'redirect_uri': redirect_uri
        }
        
        print(f"Sending to Discord OAuth")
        response = requests.post('https://discord.com/api/oauth2/token', data=data)
        
        if response.status_code != 200:
            error_text = response.text[:200]
            print(f"Discord token error: {error_text}")
            raise HTTPException(status_code=400, detail=f"Discord auth failed: {error_text}")
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        user_response = requests.get('https://discord.com/api/users/@me', 
                                   headers={'Authorization': f'Bearer {access_token}'})
        user_data = user_response.json()
        
        print(f"Got Discord user: {user_data.get('id')} - {user_data.get('username')}")
        
        if 'id' not in user_data:
            raise HTTPException(status_code=400, detail="Invalid user data from Discord")
        
        discord_username = user_data['username']
        if user_data.get('global_name'):
            discord_username = user_data['global_name']
        
        # FIXED: Check if user exists by discord_id
        print(f"Checking for user with discord_id: {user_data['id']}")
        existing = supabase_select("users", f"discord_id=eq.'{user_data['id']}'")
        print(f"Existing users found: {len(existing)}")
        
        if existing and len(existing) > 0:
            # User exists - AUTO LOGIN (update last login)
            user = existing[0]
            user_id = user['id']
            print(f"User exists, ID: {user_id}")
            
            # Update user info
            update_data = {
                "last_login": datetime.utcnow().isoformat(),
                "username": discord_username
            }
            if user_data.get('avatar'):
                update_data["avatar_url"] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
            
            supabase_update("users", update_data, "id", user_id)
            print(f"Updated user last login")
            
        else:
            # User doesn't exist - create new user
            print("Creating new user...")
            user_db = {
                "discord_id": user_data["id"],
                "username": discord_username,
                "email": user_data.get("email"),
                "account_type": "discord",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            
            if user_data.get('avatar'):
                user_db["avatar_url"] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
            
            print(f"User data to insert: {user_db}")
            result = supabase_insert("users", user_db)
            
            if not result:
                print("Failed to create user in database")
                # Try to check if user was created anyway (race condition)
                existing = supabase_select("users", f"discord_id=eq.'{user_data['id']}'")
                if existing and len(existing) > 0:
                    user = existing[0]
                    user_id = user['id']
                    print(f"User found after failed insert, ID: {user_id}")
                else:
                    raise HTTPException(status_code=500, detail="Failed to create user")
            else:
                user_id = result['id']
                print(f"New user created with ID: {user_id}")
        
        # Get user's Discord servers
        servers = []
        try:
            guilds_response = requests.get('https://discord.com/api/users/@me/guilds', 
                                         headers={'Authorization': f'Bearer {access_token}'})
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
                print(f"Found {len(servers)} servers with admin permissions")
        except Exception as e:
            print(f"Error fetching guilds: {str(e)}")
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": discord_username,
            "discord_id": user_data["id"],
            "account_type": "discord"
        })
        
        print(f"Auth successful, returning user data")
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
        print(f"Discord auth error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ========== REFRESH ENDPOINT ==========
@app.post("/api/auth/refresh")
async def refresh_login(request: RefreshTokenRequest):
    """Direct login for returning users using stored token"""
    try:
        user_token = request.token
        
        if not user_token:
            raise HTTPException(status_code=400, detail="No token provided")
        
        payload = verify_jwt_token(user_token)
        
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        user_id = payload.get("sub")
        discord_id = payload.get("discord_id")
        username = payload.get("username")
        
        existing = supabase_select("users", f"id=eq.'{user_id}'")
        
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = existing[0]
        
        supabase_update("users", {
            "last_login": datetime.utcnow().isoformat()
        }, "id", user_id)
        
        jwt_token = create_jwt_token({
            "sub": user_id,
            "username": username,
            "discord_id": discord_id,
            "account_type": "discord"
        })
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "username": username,
                "avatar": user.get('avatar_url'),
                "discord_id": discord_id,
                "email": user.get("email")
            },
            "access_token": jwt_token,
            "servers": [],  # Can't get servers without Discord token
            "message": "Auto-login successful"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Refresh login error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== PROTECTED ENDPOINTS ==========
@app.get("/api/auth/me")
async def get_current_user(request: Request):
    """Get current user info"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    users = supabase_select("users", f"id=eq.'{user_id}'")
    
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users[0]
    return {"user": user}

@app.post("/api/tournaments")
async def create_tournament(request: Request):
    """Create a tournament"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    token = auth_header.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    data = await request.json()
    
    print(f"Creating tournament: {data.get('name')}")
    
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
        "max_players_per_team": data.get("max_players_per_team", 5),
        "region_filter": data.get("region_filter", False),
        "prize_pool": data.get("prize_pool", "")
    }
    
    result = supabase_insert("tournaments", tournament)
    
    if result:
        return {
            "success": True, 
            "tournament": result,
            "message": "Tournament created successfully!"
        }
    raise HTTPException(status_code=500, detail="Failed to create tournament")

@app.get("/api/user/tournaments")
async def get_user_tournaments(request: Request):
    """Get tournaments created by user"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    token = auth_header.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    tournaments = supabase_select("tournaments", f"created_by=eq.'{user_id}'")
    
    for tournament in tournaments:
        teams = supabase_select("teams", f"tournament_id=eq.'{tournament['id']}'")
        tournament['team_count'] = len(teams)
        tournament['registered_teams'] = len(teams)
    
    return {"success": True, "tournaments": tournaments}

@app.post("/api/teams")
async def register_team(request: Request):
    """Register a team for a tournament"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    token = auth_header.split(" ")[1]
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    data = await request.json()
    tournament_id = data.get("tournament_id")
    team_name = data.get("name")
    
    tournaments = supabase_select("tournaments", f"id=eq.'{tournament_id}'")
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    
    tournament = tournaments[0]
    
    if tournament["status"] != "registration":
        raise HTTPException(status_code=400, detail="Tournament registration is closed")
    
    teams = supabase_select("teams", f"tournament_id=eq.'{tournament_id}'")
    if len(teams) >= tournament["max_teams"]:
        raise HTTPException(status_code=400, detail="Tournament is full")
    
    for team in teams:
        if team['name'].lower() == team_name.lower():
            raise HTTPException(status_code=400, detail="Team name already taken")
    
    team = {
        "tournament_id": tournament_id,
        "name": team_name,
        "captain_discord_id": payload.get("discord_id", ""),
        "players": [payload.get("discord_id", "")],
        "created_at": datetime.utcnow().isoformat()
    }
    
    result = supabase_insert("teams", team)
    
    if result:
        supabase_update("tournaments", 
                      {"current_teams": len(teams) + 1}, 
                      "id", tournament_id)
        
        return {
            "success": True, 
            "team": result,
            "message": "Team registered successfully!"
        }
    raise HTTPException(status_code=500, detail="Failed to register team")

# ========== BOT ENDPOINTS ==========
@app.post("/api/bot/tournaments")
async def create_tournament_bot(request: Request):
    """Create tournament via Discord bot"""
    try:
        data = await request.json()
        
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
            "created_by": "00000000-0000-0000-0000-000000000000",
            "created_at": datetime.utcnow().isoformat(),
            "max_players_per_team": data.get("max_players_per_team", 5),
            "region_filter": data.get("region_filter", False)
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
        print(f"Bot tournament creation error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
