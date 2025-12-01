from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import Optional
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

# ========== SUPABASE CONNECTION ==========
class SupabaseDB:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL", "")
        self.key = os.getenv("SUPABASE_KEY", "")
        self.headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json"
        }
        print(f"Supabase connected to: {self.url}")
    
    def insert(self, table: str, data: dict):
        """Insert data into table"""
        try:
            response = requests.post(
                f"{self.url}/rest/v1/{table}",
                json=data,
                headers={**self.headers, "Prefer": "return=representation"}
            )
            if response.status_code in [200, 201]:
                return response.json()[0]
            else:
                print(f"Insert error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Insert exception: {e}")
            return None
    
    def select(self, table: str, query: str = ""):
        """Select data from table"""
        try:
            url = f"{self.url}/rest/v1/{table}"
            if query:
                url += f"?{query}"
            
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Select error: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"Select exception: {e}")
            return []
    
    def update(self, table: str, data: dict, column: str, value: str):
        """Update data in table"""
        try:
            response = requests.patch(
                f"{self.url}/rest/v1/{table}?{column}=eq.{value}",
                json=data,
                headers={**self.headers, "Prefer": "return=representation"}
            )
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Update error: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"Update exception: {e}")
            return []

db = SupabaseDB()

# ========== API ENDPOINTS ==========
@app.get("/")
def root():
    return {"status": "online", "service": "TournaBot API", "time": datetime.now().isoformat()}

@app.get("/health")
def health():
    return {"status": "healthy"}

# CHANNELS
@app.post("/channels/set")
async def set_channel(data: dict):
    """Set a channel configuration"""
    try:
        # Check if exists
        existing = db.select("server_channels", 
                           f"discord_server_id=eq.{data['discord_server_id']}&channel_type=eq.{data['channel_type']}")
        
        if existing:
            # Update
            db.update("server_channels", {
                "discord_channel_id": data["discord_channel_id"],
                "channel_name": data["channel_name"],
                "updated_at": datetime.now().isoformat()
            }, "discord_server_id", data["discord_server_id"])
            action = "updated"
        else:
            # Insert
            db.insert("server_channels", {
                "discord_server_id": data["discord_server_id"],
                "channel_type": data["channel_type"],
                "discord_channel_id": data["discord_channel_id"],
                "channel_name": data["channel_name"],
                "created_at": datetime.now().isoformat()
            })
            action = "created"
        
        return {"success": True, "action": action, "channel_type": data["channel_type"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/channels/{server_id}")
async def get_channels(server_id: str):
    """Get all channels for a server"""
    channels = db.select("server_channels", f"discord_server_id=eq.{server_id}")
    return {"server_id": server_id, "channels": channels}

# TOURNAMENTS
@app.post("/tournaments/create")
async def create_tournament(data: dict):
    """Create a new tournament"""
    try:
        tournament_data = {
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
        
        tournament = db.insert("tournaments", tournament_data)
        
        if tournament:
            return {"success": True, "tournament": tournament}
        else:
            raise HTTPException(status_code=500, detail="Failed to create tournament")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str):
    """Get tournament details"""
    tournaments = db.select("tournaments", f"id=eq.{tournament_id}")
    if not tournaments:
        raise HTTPException(status_code=404, detail="Tournament not found")
    return tournaments[0]

@app.get("/tournaments/server/{server_id}")
async def get_server_tournaments(server_id: str):
    """Get all tournaments for a server"""
    tournaments = db.select("tournaments", f"discord_server_id=eq.{server_id}")
    return tournaments

# MATCH VERIFICATION
@app.post("/matches/report")
async def report_match(data: dict):
    """Report match result"""
    try:
        verification_data = {
            "match_id": data["match_id"],
            "team_id": data.get("team_id", "unknown"),
            "proof_image_url": data["proof_image_url"],
            "score": data["score"],
            "submitted_by": data["submitted_by"],
            "status": "pending",
            "created_at": datetime.now().isoformat()
        }
        
        verification = db.insert("match_verifications", verification_data)
        
        if verification:
            return {"success": True, "verification": verification}
        else:
            raise HTTPException(status_code=500, detail="Failed to submit verification")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/matches/verify/{verification_id}")
async def verify_match(verification_id: str, decision: str, reviewed_by: str, notes: Optional[str] = None):
    """Verify or reject match"""
    try:
        update_data = {
            "status": decision,
            "reviewed_by": reviewed_by,
            "review_notes": notes,
            "reviewed_at": datetime.now().isoformat()
        }
        
        result = db.update("match_verifications", update_data, "id", verification_id)
        
        if result:
            return {"success": True, "verification": result[0]}
        else:
            raise HTTPException(status_code=404, detail="Verification not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/matches/verifications/pending")
async def get_pending_verifications(server_id: str):
    """Get pending verifications for a server"""
    # First get tournaments for this server
    tournaments = db.select("tournaments", f"discord_server_id=eq.{server_id}")
    tournament_ids = [t["id"] for t in tournaments]
    
    if not tournament_ids:
        return []
    
    # Get pending verifications for these tournaments
    all_pending = []
    for t_id in tournament_ids:
        verifications = db.select("match_verifications", 
                                 f"tournament_id=eq.{t_id}&status=eq.pending")
        all_pending.extend(verifications)
    
    return all_pending

# ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
