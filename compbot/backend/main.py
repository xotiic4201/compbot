# main.py - COMPLETE FLASK BACKEND (NO RUST)
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import hashlib
from datetime import datetime, timedelta
import uuid
import math
import random
import requests
import jwt
from functools import wraps
import logging

# ========== SETUP LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", "xtourney-secret-key-2024")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.xotiicsplaza.us")

# Headers for Supabase
headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SUPABASE_KEY}"
}

# ========== APP INITIALIZATION ==========
app = Flask(__name__)
CORS(app)

# ========== SUPABASE HELPER ==========
def supabase_request(method: str, endpoint: str, data: dict = None, params: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{endpoint}"
    
    if params:
        query_params = "&".join([f"{k}={v}" for k, v in params.items()])
        url = f"{url}?{query_params}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method == "PATCH":
            response = requests.patch(url, json=data, headers=headers)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)
        elif method == "PUT":
            response = requests.put(url, json=data, headers=headers)
        else:
            return {"success": False, "detail": f"Invalid method: {method}"}
        
        if response.status_code in [200, 201, 204]:
            try:
                return response.json()
            except:
                return {"success": True}
        elif response.status_code == 404:
            return []
        else:
            error_text = response.text[:500]
            logger.error(f"Supabase error {response.status_code}: {error_text}")
            return {"success": False, "detail": f"Database error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Supabase request error: {str(e)}")
        return {"success": False, "detail": f"Database connection failed: {str(e)}"}

# ========== AUTH HELPERS ==========
def create_token(user_data: dict) -> str:
    payload = {
        "sub": user_data.get("id"),
        "username": user_data.get("username"),
        "is_host": user_data.get("is_host", False),
        "is_admin": user_data.get("is_admin", False),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({"success": False, "detail": "Token is missing"}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({"success": False, "detail": "Invalid token"}), 401
        
        user_id = payload.get("sub")
        users = supabase_request("GET", f"users?id=eq.{user_id}")
        
        if isinstance(users, dict) and "success" in users and not users["success"]:
            return jsonify({"success": False, "detail": "Database error"}), 500
        
        if not users or len(users) == 0:
            return jsonify({"success": False, "detail": "User not found"}), 401
        
        request.current_user = users[0]
        return f(*args, **kwargs)
    
    return decorated

# ========== BRACKET HELPER FUNCTIONS ==========
def generate_bracket_structure(teams: list, tournament: dict) -> dict:
    """Generate complete bracket structure"""
    total_teams = len(teams)
    if total_teams < 2:
        return {"success": False, "detail": "Need at least 2 teams"}
    
    # Calculate rounds (power of 2)
    next_power_of_two = 2 ** math.ceil(math.log2(total_teams))
    total_rounds = int(math.log2(next_power_of_two))
    
    # Shuffle teams for random seeding
    shuffled_teams = teams.copy()
    random.shuffle(shuffled_teams)
    
    # Add BYEs if needed
    while len(shuffled_teams) < next_power_of_two:
        shuffled_teams.append({
            "id": f"bye_{uuid.uuid4().hex[:8]}",
            "name": "BYE",
            "is_bye": True
        })
    
    bracket = {
        "tournament_id": tournament["id"],
        "tournament_name": tournament["name"],
        "total_rounds": total_rounds,
        "current_round": 1,
        "teams_count": total_teams,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "rounds": []
    }
    
    # Generate first round matches
    round1_matches = []
    match_number = 1
    
    for i in range(0, len(shuffled_teams), 2):
        team1 = shuffled_teams[i]
        team2 = shuffled_teams[i + 1] if i + 1 < len(shuffled_teams) else {"id": "bye", "name": "BYE", "is_bye": True}
        
        match_id = f"match_{tournament['id']}_r1_m{match_number}"
        
        match = {
            "match_id": match_id,
            "round_number": 1,
            "match_number": match_number,
            "team1_id": team1["id"],
            "team1_name": team1["name"],
            "team1_seed": i + 1,
            "team2_id": team2["id"],
            "team2_name": team2["name"],
            "team2_seed": i + 2,
            "winner_id": None,
            "team1_score": 0,
            "team2_score": 0,
            "status": "pending",
            "is_bye": team1.get("is_bye") or team2.get("is_bye"),
            "next_match": None,
            "next_team_slot": None
        }
        
        round1_matches.append(match)
        match_number += 1
    
    bracket["rounds"].append({
        "round_number": 1,
        "matches": round1_matches
    })
    
    # Generate empty future rounds with connections
    for round_num in range(2, total_rounds + 1):
        matches_in_round = next_power_of_two // (2 ** round_num)
        round_matches = []
        
        for match_num in range(1, matches_in_round + 1):
            match_id = f"match_{tournament['id']}_r{round_num}_m{match_num}"
            
            # Calculate which matches from previous round feed into this one
            prev_match1_num = (match_num * 2) - 1
            prev_match2_num = match_num * 2
            
            match = {
                "match_id": match_id,
                "round_number": round_num,
                "match_number": match_num,
                "team1_id": None,
                "team1_name": "TBD",
                "team1_seed": None,
                "team2_id": None,
                "team2_name": "TBD",
                "team2_seed": None,
                "winner_id": None,
                "team1_score": 0,
                "team2_score": 0,
                "status": "pending",
                "is_bye": False,
                "next_match": None,
                "next_team_slot": None,
                "source_matches": [
                    f"match_{tournament['id']}_r{round_num-1}_m{prev_match1_num}",
                    f"match_{tournament['id']}_r{round_num-1}_m{prev_match2_num}"
                ]
            }
            
            # Update previous matches to point to this one
            if round_num > 1:
                prev_round = bracket["rounds"][round_num - 2]
                if prev_match1_num <= len(prev_round["matches"]):
                    prev_round["matches"][prev_match1_num - 1]["next_match"] = match_id
                    prev_round["matches"][prev_match1_num - 1]["next_team_slot"] = "team1"
                if prev_match2_num <= len(prev_round["matches"]):
                    prev_round["matches"][prev_match2_num - 1]["next_match"] = match_id
                    prev_round["matches"][prev_match2_num - 1]["next_team_slot"] = "team2"
            
            round_matches.append(match)
        
        bracket["rounds"].append({
            "round_number": round_num,
            "matches": round_matches
        })
    
    return bracket

def calculate_total_rounds(max_teams: int) -> int:
    """Calculate total rounds based on max teams"""
    if max_teams <= 2:
        return 1
    elif max_teams <= 4:
        return 2
    elif max_teams <= 8:
        return 3
    elif max_teams <= 16:
        return 4
    elif max_teams <= 32:
        return 5
    else:
        return 6

# ========== ROUTES ==========
@app.route('/')
def root():
    return jsonify({"message": "XTourney API", "status": "running", "backend": "flask", "version": "3.0"})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        users = supabase_request("GET", "users?limit=1")
        tournaments = supabase_request("GET", "tournaments?limit=1")
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "detail": str(e)}), 500

# ========== USER ROUTES ==========
@app.route('/api/register', methods=['POST'])
def register():
    """Register new user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"success": False, "detail": "Missing username or password"}), 400
        
        username = data['username']
        password = data['password']
        email = data.get('email')
        
        # Check if username exists
        existing = supabase_request("GET", f"users?username=eq.{username}")
        if isinstance(existing, list) and len(existing) > 0:
            return jsonify({"success": False, "detail": "Username already exists"}), 400
        
        # Check if email exists (if provided)
        if email:
            existing_email = supabase_request("GET", f"users?email=eq.{email}")
            if isinstance(existing_email, list) and len(existing_email) > 0:
                return jsonify({"success": False, "detail": "Email already registered"}), 400
        
        # Hash password - using SHA256 to match SQL schema
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Create user
        user_id = str(uuid.uuid4())
        user_data = {
            "id": user_id,
            "username": username,
            "email": email if email else None,
            "password_hash": password_hash,
            "account_type": "email",
            "is_verified": False,
            "is_host": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Creating user: {username}")
        result = supabase_request("POST", "users", user_data)
        
        # Create token without sensitive data
        token_data = {
            "id": user_id,
            "username": username,
            "email": email if email else None,
            "is_host": False,
            "is_admin": False
        }
        
        token = create_token(token_data)
        
        return jsonify({
            "success": True,
            "token": token,
            "user": token_data
        })
        
    except Exception as e:
        logger.error(f"Register error: {str(e)}")
        return jsonify({"success": False, "detail": "Registration failed"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"success": False, "detail": "Missing username or password"}), 400
        
        username = data['username']
        password = data['password']
        
        # Find user by username
        users = supabase_request("GET", f"users?username=eq.{username}")
        if isinstance(users, dict) or not users or len(users) == 0:
            return jsonify({"success": False, "detail": "Invalid credentials"}), 401
        
        db_user = users[0]
        
        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if password_hash != db_user.get("password_hash"):
            return jsonify({"success": False, "detail": "Invalid credentials"}), 401
        
        # Update last login
        update_data = {
            "last_login": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_request("PATCH", f"users?id=eq.{db_user['id']}", update_data)
        
        # Create token without sensitive data
        token_data = {
            "id": db_user["id"],
            "username": db_user["username"],
            "email": db_user.get("email"),
            "is_host": db_user.get("is_host", False),
            "is_admin": db_user.get("is_admin", False)
        }
        
        token = create_token(token_data)
        
        return jsonify({
            "success": True,
            "token": token,
            "user": token_data
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "detail": "Login failed"}), 500

# ========== TOURNAMENT ROUTES ==========
@app.route('/api/tournaments', methods=['GET'])
def get_tournaments():
    """Get all tournaments"""
    try:
        tournaments = supabase_request("GET", "tournaments?order=created_at.desc")
        
        if isinstance(tournaments, dict) and "success" in tournaments and not tournaments["success"]:
            return jsonify({"success": True, "tournaments": [], "count": 0})
        
        if tournaments:
            for tournament in tournaments:
                # Get team counts for each tournament
                teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament['id']}")
                tournament["team_count"] = len(teams) if teams else 0
                
                # Make sure fields exist for frontend
                tournament["current_teams"] = tournament.get("team_count", 0)
                tournament["currentTeams"] = tournament.get("team_count", 0)
                tournament["max_players"] = tournament.get("max_players_per_team", 5)
        
        return jsonify({
            "success": True,
            "tournaments": tournaments if tournaments else [],
            "count": len(tournaments) if tournaments else 0
        })
        
    except Exception as e:
        logger.error(f"Get tournaments error: {e}")
        return jsonify({"success": True, "tournaments": [], "count": 0})

@app.route('/api/tournaments/<tournament_id>', methods=['GET'])
def get_tournament(tournament_id):
    """Get specific tournament by ID"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        tournament = tournaments[0]
        
        # Get teams for this tournament
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        tournament["teams"] = teams if teams else []
        tournament["team_count"] = len(teams) if teams else 0
        
        # Get bracket if exists
        brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        if brackets and len(brackets) > 0:
            tournament["bracket"] = brackets[0]
        
        return jsonify({
            "success": True,
            "tournament": tournament
        })
        
    except Exception as e:
        logger.error(f"Get tournament error: {e}")
        return jsonify({"success": False, "detail": "Failed to get tournament"}), 500

@app.route('/api/tournaments/discord', methods=['POST'])
def create_tournament_discord():
    """Create tournament from Discord bot"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ["name", "game", "max_teams", "max_players_per_team", "tournament_pass", "host_id", "created_by"]
        for field in required:
            if field not in data:
                return jsonify({"success": False, "detail": f"Missing field: {field}"}), 400
        
        # Calculate total rounds
        total_rounds = calculate_total_rounds(data["max_teams"])
        
        # Generate tournament ID
        tournament_id = str(uuid.uuid4())
        
        # Prepare tournament data according to new schema
        tournament_data = {
            "id": tournament_id,
            "name": data["name"],
            "game": data["game"],
            "description": data.get("description", ""),
            "status": "registration",
            "max_teams": data["max_teams"],
            "max_players_per_team": data["max_players_per_team"],
            "prize_pool": data.get("prize_pool", ""),
            "tournament_pass": data["tournament_pass"],
            "host_id": data["host_id"],
            "created_by": data["created_by"],
            "discord_server_id": data.get("discord_server_id"),
            "current_round": 1,
            "total_rounds": total_rounds,
            "team_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Creating tournament: {data['name']}")
        result = supabase_request("POST", "tournaments", tournament_data)
        
        return jsonify({
            "success": True,
            "tournament_id": tournament_id,
            "tournament": tournament_data,
            "tournament_pass": data["tournament_pass"],
            "message": "Tournament created successfully"
        })
        
    except Exception as e:
        logger.error(f"Discord tournament creation error: {e}")
        return jsonify({"success": False, "detail": "Failed to create tournament"}), 500

# ========== DISCORD BOT ENDPOINTS ==========
@app.route('/api/tournaments/<tournament_id>/start', methods=['POST'])
def start_tournament(tournament_id):
    """Start tournament (set status to ongoing)"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        tournament = tournaments[0]
        
        # Update tournament status to ongoing
        update_data = {
            "status": "ongoing",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return jsonify({
            "success": True,
            "message": "Tournament started successfully",
            "tournament_id": tournament_id
        })
        
    except Exception as e:
        logger.error(f"Start tournament error: {e}")
        return jsonify({"success": False, "detail": "Failed to start tournament"}), 500

@app.route('/api/tournaments/<tournament_id>/generate-bracket', methods=['POST'])
def generate_bracket_simple(tournament_id):
    """Simple bracket generation endpoint"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        tournament = tournaments[0]
        
        # Get teams
        teams = supabase_request("GET", f"teams?tournament_id=eq.{tournament_id}")
        if isinstance(teams, dict) or not teams or len(teams) < 2:
            return jsonify({"success": False, "detail": "Need at least 2 teams to generate bracket"}), 400
        
        # Prepare teams data
        teams_data = []
        for team in teams:
            teams_data.append({
                "id": team["id"],
                "name": team["name"],
                "captain_name": team.get("captain_name", "Unknown")
            })
        
        # Generate bracket structure
        bracket = generate_bracket_structure(teams_data, tournament)
        if isinstance(bracket, dict) and "success" in bracket and not bracket["success"]:
            return jsonify(bracket), 400
        
        # Save bracket
        bracket_record = {
            "id": str(uuid.uuid4()),
            "tournament_id": tournament_id,
            "bracket_data": json.dumps(bracket),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Check if bracket exists
        existing_brackets = supabase_request("GET", f"brackets?tournament_id=eq.{tournament_id}")
        if existing_brackets and len(existing_brackets) > 0:
            supabase_request("PATCH", f"brackets?tournament_id=eq.{tournament_id}", {
                "bracket_data": json.dumps(bracket),
                "updated_at": datetime.utcnow().isoformat()
            })
        else:
            supabase_request("POST", "brackets", bracket_record)
        
        # Create match records from bracket
        for round_data in bracket.get("rounds", []):
            round_number = round_data["round_number"]
            
            for match in round_data.get("matches", []):
                match_record = {
                    "id": match["match_id"],
                    "tournament_id": tournament_id,
                    "round_number": round_number,
                    "round": round_number,  # For compatibility
                    "match_number": match["match_number"],
                    "team1_id": match.get("team1_id"),
                    "team2_id": match.get("team2_id"),
                    "team1_name": match["team1_name"],
                    "team2_name": match["team2_name"],
                    "status": match["status"],
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                # Check if match exists
                existing_matches = supabase_request("GET", f"matches?id=eq.{match['match_id']}")
                if isinstance(existing_matches, list) and (not existing_matches or len(existing_matches) == 0):
                    supabase_request("POST", "matches", match_record)
        
        # Update tournament status
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", {
            "status": "ongoing",
            "current_round": 1,
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return jsonify({
            "success": True,
            "message": "Bracket generated successfully",
            "tournament_id": tournament_id
        })
        
    except Exception as e:
        logger.error(f"Generate bracket error: {e}")
        return jsonify({"success": False, "detail": "Failed to generate bracket"}), 500

@app.route('/api/tournaments/<tournament_id>/status', methods=['PUT'])
def update_tournament_status(tournament_id):
    """Update tournament status"""
    try:
        data = request.get_json()
        
        if not data or 'status' not in data:
            return jsonify({"success": False, "detail": "Missing status field"}), 400
        
        status_value = data['status']
        
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        tournament = tournaments[0]
        
        # Validate status
        valid_statuses = ["registration", "ongoing", "completed", "cancelled"]
        if status_value not in valid_statuses:
            return jsonify({"success": False, "detail": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}), 400
        
        # Update tournament status
        update_data = {
            "status": status_value,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"tournaments?id=eq.{tournament_id}", update_data)
        
        return jsonify({
            "success": True,
            "message": f"Tournament status updated to {status_value}",
            "tournament_id": tournament_id
        })
        
    except Exception as e:
        logger.error(f"Update tournament status error: {e}")
        return jsonify({"success": False, "detail": "Failed to update tournament status"}), 500

@app.route('/api/tournaments/<tournament_id>/matches', methods=['GET'])
def get_tournament_matches(tournament_id):
    """Get all matches for a tournament"""
    try:
        tournaments = supabase_request("GET", f"tournaments?id=eq.{tournament_id}")
        
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        matches = supabase_request("GET", f"matches?tournament_id=eq.{tournament_id}&order=round_number.asc,match_number.asc")
        
        if isinstance(matches, dict):
            matches = []
        
        return jsonify({
            "success": True,
            "matches": matches if matches else [],
            "tournament_id": tournament_id,
            "count": len(matches) if matches else 0
        })
        
    except Exception as e:
        logger.error(f"Get tournament matches error: {e}")
        return jsonify({"success": False, "detail": "Failed to get tournament matches"}), 500

@app.route('/api/matches/<match_id>', methods=['GET'])
def get_match(match_id):
    """Get specific match by ID"""
    try:
        matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        if isinstance(matches, dict) or not matches or len(matches) == 0:
            return jsonify({"success": False, "detail": "Match not found"}), 404
        
        match_data = matches[0]
        
        return jsonify({
            "success": True,
            "match": match_data
        })
        
    except Exception as e:
        logger.error(f"Get match error: {e}")
        return jsonify({"success": False, "detail": "Failed to get match"}), 500

@app.route('/api/matches/<match_id>/update-score', methods=['POST'])
def update_match_score(match_id):
    """Update match score"""
    try:
        data = request.get_json()
        
        if not data or 'team1_score' not in data or 'team2_score' not in data:
            return jsonify({"success": False, "detail": "Missing score data"}), 400
        
        team1_score = int(data['team1_score'])
        team2_score = int(data['team2_score'])
        
        matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        if isinstance(matches, dict) or not matches or len(matches) == 0:
            return jsonify({"success": False, "detail": "Match not found"}), 404
        
        match_data = matches[0]
        
        # Determine winner
        if team1_score > team2_score:
            winner_id = match_data.get("team1_id")
        elif team2_score > team1_score:
            winner_id = match_data.get("team2_id")
        else:
            winner_id = None
        
        # Update match
        update_data = {
            "team1_score": team1_score,
            "team2_score": team2_score,
            "winner_id": winner_id,
            "status": "completed",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        supabase_request("PATCH", f"matches?id=eq.{match_id}", update_data)
        
        # Get updated match data
        updated_matches = supabase_request("GET", f"matches?id=eq.{match_id}")
        
        return jsonify({
            "success": True,
            "match": updated_matches[0] if updated_matches and len(updated_matches) > 0 else match_data,
            "message": "Match score updated successfully"
        })
        
    except Exception as e:
        logger.error(f"Update match score error: {e}")
        return jsonify({"success": False, "detail": "Failed to update match score"}), 500

# ========== TEAM ROUTES ==========
@app.route('/api/teams/register', methods=['POST'])
def register_team():
    """Register a team for tournament"""
    try:
        data = request.get_json()
        
        # Check required fields
        required = ["team_name", "tournament_id", "captain_id", "captain_name", "members"]
        for field in required:
            if field not in data:
                return jsonify({"success": False, "detail": f"Missing field: {field}"}), 400
        
        # Check if tournament exists
        tournaments = supabase_request("GET", f"tournaments?id=eq.{data['tournament_id']}")
        if isinstance(tournaments, dict) or not tournaments or len(tournaments) == 0:
            return jsonify({"success": False, "detail": "Tournament not found"}), 404
        
        tournament = tournaments[0]
        
        # Check if tournament is accepting registrations
        if tournament["status"] != "registration":
            return jsonify({"success": False, "detail": "Tournament is not accepting registrations"}), 400
        
        # Check team count
        teams = supabase_request("GET", f"teams?tournament_id=eq.{data['tournament_id']}")
        current_teams = len(teams) if teams else 0
        
        if current_teams >= tournament["max_teams"]:
            return jsonify({"success": False, "detail": "Tournament is full"}), 400
        
        # Check if team name is already taken in this tournament
        existing_teams = supabase_request("GET", f"teams?tournament_id=eq.{data['tournament_id']}&name=eq.{data['team_name']}")
        if existing_teams and len(existing_teams) > 0:
            return jsonify({"success": False, "detail": "Team name already taken in this tournament"}), 400
        
        # Create team
        team_id = str(uuid.uuid4())
        team_record = {
            "id": team_id,
            "tournament_id": data["tournament_id"],
            "name": data["team_name"],
            "captain_discord_id": data["captain_id"],
            "captain_name": data["captain_name"],
            "region": data.get("region", "GLOBAL"),
            "members": json.dumps(data["members"]),
            "status": "registered",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if data.get("tag"):
            team_record["name"] = f"[{data['tag']}] {data['team_name']}"
        
        result = supabase_request("POST", "teams", team_record)
        
        # Update tournament team count
        supabase_request("PATCH", f"tournaments?id=eq.{data['tournament_id']}", {
            "team_count": current_teams + 1,
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return jsonify({
            "success": True,
            "team": {
                "id": team_id,
                "name": team_record["name"],
                "captain_name": data["captain_name"],
                "region": data.get("region", "GLOBAL"),
                "members": data["members"]
            },
            "message": "Team registered successfully"
        })
        
    except Exception as e:
        logger.error(f"Team registration error: {e}")
        return jsonify({"success": False, "detail": "Failed to register team"}), 500

# ========== STATS & MISC ROUTES ==========
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get platform statistics"""
    try:
        tournaments = supabase_request("GET", "tournaments?status=in.(registration,ongoing)")
        teams = supabase_request("GET", "teams")
        servers = supabase_request("GET", "bot_servers")
        matches = supabase_request("GET", "matches?status=eq.ongoing")
        
        return jsonify({
            "success": True,
            "stats": {
                "active_tournaments": len(tournaments) if isinstance(tournaments, list) else 0,
                "total_teams": len(teams) if isinstance(teams, list) else 0,
                "connected_servers": len(servers) if isinstance(servers, list) else 0,
                "live_matches": len(matches) if isinstance(matches, list) else 0
            }
        })
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({
            "success": True,
            "stats": {
                "active_tournaments": 0,
                "total_teams": 0,
                "connected_servers": 0,
                "live_matches": 0
            }
        })

@app.route('/api/bot/server-stats', methods=['POST'])
def update_server_stats():
    """Update server stats from bot"""
    try:
        data = request.get_json()
        
        server_id = data.get("server_id")
        server_name = data.get("server_name")
        member_count = data.get("member_count", 0)
        icon_url = data.get("icon_url")
        
        if not server_id:
            return jsonify({"success": False, "detail": "Server ID required"}), 400
        
        # Check if server exists
        servers = supabase_request("GET", f"bot_servers?server_id=eq.{server_id}")
        
        server_data = {
            "server_id": server_id,
            "server_name": server_name,
            "member_count": member_count,
            "icon_url": icon_url,
            "last_updated": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if isinstance(servers, list) and servers and len(servers) > 0:
            supabase_request("PATCH", f"bot_servers?server_id=eq.{server_id}", server_data)
        else:
            server_data["id"] = str(uuid.uuid4())
            server_data["created_at"] = datetime.utcnow().isoformat()
            supabase_request("POST", "bot_servers", server_data)
        
        return jsonify({"success": True, "message": "Server stats updated"})
        
    except Exception as e:
        logger.error(f"Server stats error: {e}")
        return jsonify({"success": False, "detail": "Failed to update server stats"}), 500

# ========== RUN APP ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
