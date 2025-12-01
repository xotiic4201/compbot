from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os
import requests
import json

app = FastAPI(title="TournaBot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== SUPABASE ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
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
        return response.json()[0] if response.status_code in [200, 201] else None
    except:
        return None

def supabase_select(table, query=""):
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else []
    except:
        return []

def supabase_update(table, data, column, value):
    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers={**headers, "Prefer": "return=representation"}
        )
        return response.json() if response.status_code == 200 else []
    except:
        return []

# ========== DATABASE TABLES ==========
# Run these in Supabase SQL Editor:

"""
-- 1. Users table (Discord login)
CREATE TABLE users (
    discord_id VARCHAR(100) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    avatar_url TEXT,
    email VARCHAR(255),
    role VARCHAR(20) DEFAULT 'player', -- player, host, admin
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP DEFAULT NOW()
);

-- 2. Tournaments table
CREATE TABLE tournaments (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    game VARCHAR(50) NOT NULL,
    description TEXT,
    max_teams INTEGER DEFAULT 16,
    current_teams INTEGER DEFAULT 0,
    bracket_type VARCHAR(20) DEFAULT 'single_elimination',
    start_date TIMESTAMP,
    status VARCHAR(20) DEFAULT 'registration',
    discord_server_id VARCHAR(100),
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- 3. Teams table
CREATE TABLE teams (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tournament_id UUID REFERENCES tournaments(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    captain_discord_id VARCHAR(100) NOT NULL,
    players JSONB DEFAULT '[]',
    checked_in BOOLEAN DEFAULT FALSE,
    seed INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 4. Brackets table
CREATE TABLE brackets (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tournament_id UUID REFERENCES tournaments(id) ON DELETE CASCADE,
    round INTEGER NOT NULL,
    match_number INTEGER NOT NULL,
    team1_id UUID REFERENCES teams(id),
    team2_id UUID REFERENCES teams(id),
    winner_id UUID REFERENCES teams(id),
    score_team1 INTEGER DEFAULT 0,
    score_team2 INTEGER DEFAULT 0,
    scheduled_time TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW()
);

-- 5. Server channels config
CREATE TABLE server_channels (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    discord_server_id VARCHAR(100) NOT NULL,
    channel_type VARCHAR(50) NOT NULL,
    discord_channel_id VARCHAR(100) NOT NULL,
    channel_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(discord_server_id, channel_type)
);

-- 6. Server roles config
CREATE TABLE server_roles (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    discord_server_id VARCHAR(100) NOT NULL,
    role_type VARCHAR(50) NOT NULL, -- host, player, admin
    discord_role_id VARCHAR(100) NOT NULL,
    role_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(discord_server_id, role_type)
);
"""

# ========== API ENDPOINTS ==========

@app.get("/")
def root():
    return {"status": "online", "service": "TournaBot API"}

# ========== USER AUTH ==========
@app.post("/auth/discord")
async def discord_auth(code: str):
    """Exchange Discord OAuth2 code for user info"""
    try:
        # Exchange code for token
        data = {
            'client_id': os.getenv("DISCORD_CLIENT_ID"),
            'client_secret': os.getenv("DISCORD_CLIENT_SECRET"),
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.getenv("DISCORD_REDIRECT_URI", "http://localhost:3000/auth/callback")
        }
        
        response = requests.post('https://discord.com/api/oauth2/token', data=data)
        token_data = response.json()
        
        # Get user info
        headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=headers)
        user_data = user_response.json()
        
        # Save/update user
        user = {
            "discord_id": user_data["id"],
            "username": user_data["username"],
            "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png" if user_data.get("avatar") else None,
            "last_login": datetime.now().isoformat()
        }
        
        existing = supabase_select("users", f"discord_id=eq.{user['discord_id']}")
        if existing:
            supabase_update("users", user, "discord_id", user["discord_id"])
        else:
            supabase_insert("users", user)
        
        return {
            "success": True,
            "user": user_data,
            "access_token": token_data["access_token"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{discord_id}")
async def get_user(discord_id: str):
    """Get user profile"""
    users = supabase_select("users", f"discord_id=eq.{discord_id}")
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[0]

# ========== TOURNAMENT MANAGEMENT ==========
@app.post("/tournaments/create")
async def create_tournament(data: dict):
    """Create tournament with host role assignment"""
    try:
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
            "discord_server_id": data["discord_server_id"],
            "created_by": data["created_by"],
            "created_at": datetime.now().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament)
        
        # Assign host role to creator
        if data.get("assign_host_role", True):
            await assign_user_role(
                data["discord_server_id"],
                data["created_by"],
                "host"
            )
        
        return {"success": True, "tournament": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tournaments/{tournament_id}/bracket")
async def get_bracket(tournament_id: str):
    """Get tournament bracket with match schedule"""
    # Get tournament
    tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    
    tournament = tournaments[0]
    
    # Get teams
    teams = supabase_select("teams", f"tournament_id=eq.{tournament_id}")
    
    # Get bracket matches
    brackets = supabase_select("brackets", f"tournament_id=eq.{tournament_id}")
    
    # Format bracket structure
    bracket_structure = {
        "tournament": tournament,
        "teams": teams,
        "rounds": organize_brackets_by_round(brackets),
        "schedule": generate_schedule(brackets)
    }
    
    return bracket_structure

def organize_brackets_by_round(brackets):
    """Organize brackets by round number"""
    rounds = {}
    for match in brackets:
        round_num = match["round"]
        if round_num not in rounds:
            rounds[round_num] = []
        rounds[round_num].append(match)
    return rounds

def generate_schedule(brackets):
    """Generate match schedule"""
    schedule = []
    for match in brackets:
        if match.get("scheduled_time"):
            schedule.append({
                "match_id": match["id"],
                "round": match["round"],
                "match_number": match["match_number"],
                "scheduled_time": match["scheduled_time"],
                "status": match["status"]
            })
    return schedule

# ========== ROLE MANAGEMENT ==========
@app.post("/roles/assign")
async def assign_user_role(server_id: str, discord_id: str, role_type: str):
    """Assign role to user"""
    try:
        # Get role from database
        roles = supabase_select("server_roles", 
                               f"discord_server_id=eq.{server_id}&role_type=eq.{role_type}")
        if not roles:
            return {"success": False, "error": f"No {role_type} role configured"}
        
        # In real implementation, this would call Discord API
        # For now, we'll just log it
        print(f"Would assign role {roles[0]['discord_role_id']} to user {discord_id}")
        
        return {"success": True, "role": roles[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/roles/set")
async def set_server_role(data: dict):
    """Configure server roles"""
    try:
        # Check if exists
        existing = supabase_select("server_roles",
                                  f"discord_server_id=eq.{data['discord_server_id']}&role_type=eq.{data['role_type']}")
        
        if existing:
            supabase_update("server_roles", {
                "discord_role_id": data["discord_role_id"],
                "role_name": data["role_name"]
            }, "discord_server_id", data["discord_server_id"])
        else:
            supabase_insert("server_roles", {
                "discord_server_id": data["discord_server_id"],
                "role_type": data["role_type"],
                "discord_role_id": data["discord_role_id"],
                "role_name": data["role_name"],
                "created_at": datetime.now().isoformat()
            })
        
        return {"success": True, "role_type": data["role_type"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== TEAM REGISTRATION ==========
@app.post("/teams/register")
async def register_team(data: dict):
    """Register team for tournament"""
    try:
        # Check tournament exists and has space
        tournaments = supabase_select("tournaments", f"id=eq.{data['tournament_id']}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        if tournament["current_teams"] >= tournament["max_teams"]:
            raise HTTPException(status_code=400, detail="Tournament is full")
        
        # Create team
        team = {
            "tournament_id": data["tournament_id"],
            "name": data["name"],
            "captain_discord_id": data["captain_discord_id"],
            "players": data.get("players", [data["captain_discord_id"]]),
            "created_at": datetime.now().isoformat()
        }
        
        result = supabase_insert("teams", team)
        
        # Update tournament team count
        supabase_update("tournaments", {
            "current_teams": tournament["current_teams"] + 1
        }, "id", tournament["id"])
        
        # Assign player role to team members
        for player_id in team["players"]:
            await assign_user_role(
                tournament["discord_server_id"],
                player_id,
                "player"
            )
        
        return {"success": True, "team": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== LOGIN PAGE ENDPOINT ==========
@app.get("/auth/config")
async def get_auth_config():
    """Get OAuth2 configuration for frontend"""
    return {
        "discord_client_id": os.getenv("DISCORD_CLIENT_ID"),
        "redirect_uri": os.getenv("DISCORD_REDIRECT_URI", "http://localhost:3000/auth/callback"),
        "scope": "identify email guilds"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
