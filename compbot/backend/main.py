from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import os
import requests
import jwt
from typing import Optional

app = FastAPI(title="XTourney API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://xtourney.vercel.app", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("JWT_SECRET", "production-secret-key-change-in-production")
ALGORITHM = "HS256"

# ========== SUPABASE SETUP ==========
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")

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
async def discord_auth(code: str):
    """Production Discord OAuth2"""
    try:
        # Exchange code for token
        data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.getenv("DISCORD_REDIRECT_URI", "https://xtourney.vercel.app/auth/callback")
        }
        
        response = requests.post('https://discord.com/api/oauth2/token', data=data, 
                               headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        token_data = response.json()
        
        # Get user info
        user_headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=user_headers)
        user_data = user_response.json()
        
        # Get user's guilds (servers)
        guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=user_headers)
        guilds_data = guilds_response.json()
        
        # Filter to guilds where bot is admin
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
        
        # Save/update user
        user_db = {
            "discord_id": user_data["id"],
            "username": user_data["username"],
            "discriminator": user_data.get("discriminator", "0"),
            "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else f"https://cdn.discordapp.com/embed/avatars/{int(user_data.get('discriminator', '0')) % 5}.png",
            "email": user_data.get("email"),
            "last_login": datetime.utcnow().isoformat()
        }
        
        # Check if user exists
        existing = supabase_select("users", f"discord_id=eq.{user_db['discord_id']}")
        if existing:
            supabase_update("users", user_db, "discord_id", user_db['discord_id'])
        else:
            supabase_insert("users", user_db)
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": user_data["id"],
            "username": user_data["username"],
            "avatar": user_data.get("avatar")
        })
        
        return {
            "success": True,
            "user": {
                "id": user_data["id"],
                "username": user_data["username"],
                "avatar": user_db["avatar_url"],
                "email": user_data.get("email")
            },
            "servers": bot_guilds,
            "access_token": jwt_token,
            "token_type": "Bearer"
        }
        
    except Exception as e:
        print(f"Auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.get("/api/auth/me")
async def get_current_user(token: str = Depends(verify_token)):
    """Get current user from JWT"""
    return {"user": token}

# ========== SERVER MANAGEMENT ==========
@app.get("/api/servers")
async def get_user_servers(token: str = Depends(verify_token)):
    """Get user's Discord servers"""
    try:
        # Get fresh data from Discord
        # In production, you'd cache this
        return {"servers": []}  # Placeholder
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

