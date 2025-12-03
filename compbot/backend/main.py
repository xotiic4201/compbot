# Add these imports at the top
from typing import List, Dict
import asyncio

# Add these Pydantic models
class ChannelConfig(BaseModel):
    discord_server_id: str
    channel_type: str
    discord_channel_id: str
    channel_name: str

class DiscordMember(BaseModel):
    user_id: str
    guild_id: str

# Add these Discord utility functions after your existing functions
# ========== DISCORD BOT UTILITIES ==========
async def get_discord_guild_member(guild_id: str, user_id: str):
    """Get Discord guild member using bot token"""
    try:
        if not BOT_TOKEN:
            return None
            
        headers = {'Authorization': f'Bot {BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{guild_id}/members/{user_id}',
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting guild member: {e}")
        return None

async def get_guild_roles(guild_id: str):
    """Get all roles from a Discord guild"""
    try:
        if not BOT_TOKEN:
            return []
            
        headers = {'Authorization': f'Bot {BOT_TOKEN}'}
        response = requests.get(
            f'https://discord.com/api/guilds/{guild_id}/roles',
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        print(f"Error getting guild roles: {e}")
        return []

async def check_discord_permission(user_id: str, guild_id: str, permission_check: str = "host"):
    """Check if user has specific permission in Discord"""
    try:
        # Get user's roles in the guild
        member_data = await get_discord_guild_member(guild_id, user_id)
        if not member_data:
            return False
        
        user_roles = member_data.get('roles', [])
        
        # Get all guild roles
        guild_roles = await get_guild_roles(guild_id)
        if not guild_roles:
            return False
        
        # Check for specific role based on permission_check
        if permission_check == "host":
            # Look for HOST, Tournament Host, Organizer, or similar roles
            host_role_names = ['host', 'tournament host', 'organizer', 'tournament organizer']
            for role in guild_roles:
                if role['name'].lower() in host_role_names and role['id'] in user_roles:
                    return True
        elif permission_check == "admin":
            # Check for administrator permission
            for role in guild_roles:
                if role['id'] in user_roles:
                    permissions = int(role.get('permissions', 0))
                    if permissions & 0x8:  # ADMINISTRATOR permission
                        return True
        
        return False
    except Exception as e:
        print(f"Permission check error: {e}")
        return False

# ========== CHANNEL MANAGEMENT ENDPOINTS ==========
@app.post("/channels/set")
async def set_channel(channel: ChannelConfig):
    """Set a channel for specific tournament purposes"""
    try:
        # Check if channel already exists for this server and type
        existing = supabase_select("server_channels", 
                                 f"discord_server_id=eq.{channel.discord_server_id}&channel_type=eq.{channel.channel_type}")
        
        channel_data = {
            "discord_server_id": channel.discord_server_id,
            "channel_type": channel.channel_type,
            "discord_channel_id": channel.discord_channel_id,
            "channel_name": channel.channel_name,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if existing:
            # Update existing channel
            result = supabase_update("server_channels", channel_data, 
                                   "discord_server_id", channel.discord_server_id)
        else:
            # Add created_at for new channels
            channel_data["created_at"] = datetime.utcnow().isoformat()
            result = supabase_insert("server_channels", channel_data)
        
        if result:
            return {"success": True, "channel": result}
        else:
            raise HTTPException(status_code=500, detail="Failed to save channel configuration")
            
    except Exception as e:
        print(f"Set channel error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/channels/{server_id}")
async def get_channels(server_id: str):
    """Get all configured channels for a server"""
    try:
        channels = supabase_select("server_channels", f"discord_server_id=eq.{server_id}")
        return channels
    except Exception as e:
        print(f"Get channels error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== BOT TOURNAMENT ENDPOINTS ==========
@app.post("/api/bot/tournaments")
async def create_tournament_bot(data: dict):
    """Create tournament via Discord bot"""
    try:
        user_id = data.get("created_by")
        guild_id = data.get("discord_server_id")
        
        if not user_id or not guild_id:
            raise HTTPException(status_code=400, detail="Missing user or server ID")
        
        # Check if user has permission via Discord bot
        has_permission = await check_discord_permission(user_id, guild_id, "host")
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
            "discord_server_id": guild_id,
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_insert("tournaments", tournament)
        
        if result:
            # Create initial bracket
            create_initial_bracket(result["id"], data.get("max_teams", 16))
            
            return {"success": True, "tournament": result}
        else:
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
        # Get tournament
        tournaments = supabase_select("tournaments", f"id=eq.{tournament_id}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
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
            "tournament": tournament,
            "teams": teams,
            "rounds": rounds
        }
        
    except Exception as e:
        print(f"Get bracket error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== BOT TEAM ENDPOINTS ==========
@app.post("/api/bot/teams")
async def register_team_bot(data: dict):
    """Register team via Discord bot"""
    try:
        # Check tournament
        tournaments = supabase_select("tournaments", f"id=eq.{data['tournament_id']}")
        if not tournaments:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        tournament = tournaments[0]
        
        # Check if user is already in a team
        existing_teams = supabase_select("teams", f"tournament_id=eq.{data['tournament_id']}")
        for team in existing_teams:
            if data.get('captain_discord_id') in team.get('players', []):
                raise HTTPException(status_code=400, detail="Already registered in this tournament")
        
        # Create team
        team = {
            "tournament_id": data["tournament_id"],
            "name": data["name"],
            "captain_discord_id": data.get("captain_discord_id"),
            "players": [data.get("captain_discord_id")],
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
        print(f"Register team error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== UPDATE EXISTING TOURNAMENT ENDPOINT ==========
# Update your existing tournament creation to also check Discord permissions
@app.post("/api/tournaments")
async def create_tournament(data: dict, token: dict = Depends(verify_token)):
    """Create tournament - ONLY for users with HOST role"""
    try:
        user_id = token.get("sub")
        
        # Get user from database
        users = supabase_select("users", f"id=eq.{user_id}")
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users[0]
        discord_id = user.get("discord_id")
        server_id = data.get("discord_server_id")
        
        # Check permission - user must have Discord connected AND HOST role
        if not discord_id:
            raise HTTPException(status_code=403, detail="Connect Discord account to create tournaments")
        
        if not server_id:
            raise HTTPException(status_code=400, detail="Server ID is required")
        
        # Check HOST role permission via Discord bot
        has_permission = await check_discord_permission(discord_id, server_id, "host")
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
            
            return {"success": True, "tournament": result}
        else:
            raise HTTPException(status_code=500, detail="Failed to create tournament")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create tournament error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== DISCORD BOT HEALTH CHECK ==========
@app.get("/api/bot/health")
async def bot_health_check():
    """Health check for Discord bot"""
    try:
        # Test Discord API connection if bot token is available
        if BOT_TOKEN:
            headers = {'Authorization': f'Bot {BOT_TOKEN}'}
            response = requests.get('https://discord.com/api/v10/users/@me', headers=headers, timeout=5)
            
            discord_status = "connected" if response.status_code == 200 else "disconnected"
        else:
            discord_status = "no_token"
        
        return {
            "status": "healthy",
            "service": "XTourney Bot API",
            "discord_bot": discord_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "degraded",
            "service": "XTourney Bot API",
            "discord_bot": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# Add this to your database setup:
"""
CREATE TABLE IF NOT EXISTS server_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    discord_server_id TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    discord_channel_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(discord_server_id, channel_type)
);
"""
