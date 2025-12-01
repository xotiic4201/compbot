from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import datetime
from typing import Optional
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

# Simple Supabase helper
class Supabase:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_KEY")
        self.headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json"
        }
    
    def insert(self, table, data):
        response = requests.post(
            f"{self.url}/rest/v1/{table}",
            json=data,
            headers={**self.headers, "Prefer": "return=representation"}
        )
        if response.status_code == 201:
            return response.json()[0]
        raise Exception(f"Insert failed: {response.text}")
    
    def select(self, table, query=""):
        url = f"{self.url}/rest/v1/{table}"
        if query:
            url += f"?{query}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        return []
    
    def update(self, table, data, column, value):
        response = requests.patch(
            f"{self.url}/rest/v1/{table}?{column}=eq.{value}",
            json=data,
            headers={**self.headers, "Prefer": "return=representation"}
        )
        if response.status_code == 200:
            return response.json()
        raise Exception(f"Update failed: {response.text}")

supabase = Supabase()

# ========== CHANNELS API ==========
@app.post("/channels/set")
async def set_channel(data: dict):
    """Set a channel for tournament activities"""
    try:
        # Check if exists
        existing = supabase.select("server_channels", f"discord_server_id=eq.{data['discord_server_id']}&channel_type=eq.{data['channel_type']}")
        
        if existing:
            # Update
            supabase.update("server_channels", {
                "discord_channel_id": data["discord_channel_id"],
                "channel_name": data["channel_name"],
                "updated_at": datetime.now().isoformat()
            }, "discord_server_id", data["discord_server_id"])
        else:
            # Insert
            supabase.insert("server_channels", {
                "discord_server_id": data["discord_server_id"],
                "channel_type": data["channel_type"],
                "discord_channel_id": data["discord_channel_id"],
                "channel_name": data["channel_name"]
            })
        
        return {"success": True, "message": f"Channel set for {data['channel_type']}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/channels/{server_id}")
async def get_channels(server_id: str):
    """Get all configured channels for a server"""
    return supabase.select("server_channels", f"discord_server_id=eq.{server_id}")

# ========== TOURNAMENTS API ==========
@app.post("/tournaments/create")
async def create_tournament(data: dict):
    """Create a new tournament"""
    try:
        data["status"] = "registration"
        data["current_teams"] = 0
        data["created_at"] = datetime.now().isoformat()
        
        tournament = supabase.insert("tournaments", data)
        return {"success": True, "tournament": tournament}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tournaments/{tournament_id}")
async def get_tournament(tournament_id: str):
    """Get tournament details"""
    result = supabase.select("tournaments", f"id=eq.{tournament_id}")
    if not result:
        raise HTTPException(status_code=404, detail="Tournament not found")
    return result[0]

# ========== MATCH VERIFICATION ==========
@app.post("/matches/report")
async def report_match(data: dict):
    """Report match result with proof"""
    try:
        verification = supabase.insert("match_verifications", {
            "match_id": data["match_id"],
            "team_id": data.get("team_id", "temp"),
            "proof_image_url": data["proof_image_url"],
            "score": data["score"],
            "submitted_by": data["submitted_by"],
            "status": "pending",
            "created_at": datetime.now().isoformat()
        })
        return {"success": True, "verification": verification}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== HEALTH CHECK ==========
@app.get("/")
async def root():
    return {"status": "ok", "message": "TournaBot API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
