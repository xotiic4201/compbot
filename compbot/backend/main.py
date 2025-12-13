const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Simple in-memory storage
const db = {
    users: {},
    tournaments: {},
    matches: {},
    teams: {},
    brackets: {},
    proofs: {}
};

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'tourney-secret-key-' + Date.now();

// ========== MIDDLEWARE ==========
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Admin middleware
const isAdmin = (req, res, next) => {
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
};

// Host middleware
const isHost = (req, res, next) => {
    if (req.user && (req.user.isHost || req.user.isAdmin)) {
        next();
    } else {
        res.status(403).json({ error: 'Host access required' });
    }
};

// ========== AUTH ENDPOINTS ==========
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        if (db.users[username]) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        
        db.users[username] = {
            id: userId,
            username,
            email: email || '',
            password: hashedPassword,
            isHost: false,
            isAdmin: false,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };
        
        const token = jwt.sign(
            { 
                id: userId, 
                username, 
                isHost: false,
                isAdmin: false 
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                id: userId,
                username,
                email: email || '',
                isHost: false,
                isAdmin: false
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const user = db.users[username];
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        user.lastLogin = new Date().toISOString();
        
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                isHost: user.isHost,
                isAdmin: user.isAdmin 
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isHost: user.isHost,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ========== ADMIN ENDPOINTS ==========
app.post('/api/admin/make-host', authenticateToken, isAdmin, (req, res) => {
    try {
        const { username } = req.body;
        
        if (!db.users[username]) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        db.users[username].isHost = true;
        
        res.json({
            success: true,
            message: `${username} is now a tournament host`,
            user: {
                username: db.users[username].username,
                isHost: true
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// ========== TOURNAMENT ENDPOINTS ==========
app.post('/api/tournaments', authenticateToken, isHost, (req, res) => {
    try {
        const { name, game, description, maxTeams, maxPlayers, prizePool, startDate, region } = req.body;
        
        if (!name || !game || !maxTeams) {
            return res.status(400).json({ error: 'Required fields: name, game, maxTeams' });
        }
        
        const tournamentId = uuidv4();
        const tournamentPass = generateTournamentPass();
        
        db.tournaments[tournamentId] = {
            id: tournamentId,
            name,
            game,
            description: description || '',
            maxTeams: parseInt(maxTeams),
            maxPlayers: parseInt(maxPlayers) || 5,
            prizePool: prizePool || '',
            startDate: startDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
            region: region || 'global',
            status: 'registration',
            createdBy: req.user.username,
            hostId: req.user.id,
            tournamentPass, // Secret pass for host management
            createdAt: new Date().toISOString(),
            teams: [],
            matches: [],
            currentRound: 0,
            totalRounds: calculateRounds(maxTeams)
        };
        
        res.json({
            success: true,
            tournament: db.tournaments[tournamentId],
            message: 'Tournament created successfully'
        });
    } catch (error) {
        console.error('Tournament creation error:', error);
        res.status(500).json({ error: 'Failed to create tournament' });
    }
});

app.get('/api/tournaments', (req, res) => {
    try {
        const tournaments = Object.values(db.tournaments).filter(t => t.status !== 'completed');
        
        res.json({
            success: true,
            tournaments: tournaments.map(t => ({
                id: t.id,
                name: t.name,
                game: t.game,
                description: t.description,
                maxTeams: t.maxTeams,
                currentTeams: t.teams.length,
                status: t.status,
                prizePool: t.prizePool,
                startDate: t.startDate,
                region: t.region,
                createdBy: t.createdBy
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch tournaments' });
    }
});

app.get('/api/tournaments/:id', (req, res) => {
    try {
        const tournament = db.tournaments[req.params.id];
        
        if (!tournament) {
            return res.status(404).json({ error: 'Tournament not found' });
        }
        
        res.json({
            success: true,
            tournament: {
                ...tournament,
                teams: tournament.teams.map(teamId => db.teams[teamId]).filter(Boolean),
                matches: tournament.matches.map(matchId => db.matches[matchId]).filter(Boolean)
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch tournament' });
    }
});

app.post('/api/tournaments/:id/register', authenticateToken, (req, res) => {
    try {
        const tournament = db.tournaments[req.params.id];
        const { teamName, players } = req.body;
        
        if (!tournament) {
            return res.status(404).json({ error: 'Tournament not found' });
        }
        
        if (tournament.status !== 'registration') {
            return res.status(400).json({ error: 'Tournament not accepting registrations' });
        }
        
        if (tournament.teams.length >= tournament.maxTeams) {
            return res.status(400).json({ error: 'Tournament is full' });
        }
        
        // Check if user already has a team
        const existingTeam = Object.values(db.teams).find(
            t => t.tournamentId === tournament.id && t.captainId === req.user.id
        );
        
        if (existingTeam) {
            return res.status(400).json({ error: 'You already have a team in this tournament' });
        }
        
        const teamId = uuidv4();
        
        db.teams[teamId] = {
            id: teamId,
            name: teamName,
            tournamentId: tournament.id,
            captainId: req.user.id,
            captainName: req.user.username,
            players: players || [req.user.username],
            createdAt: new Date().toISOString(),
            wins: 0,
            losses: 0,
            seed: tournament.teams.length + 1
        };
        
        tournament.teams.push(teamId);
        
        res.json({
            success: true,
            team: db.teams[teamId],
            message: 'Team registered successfully'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to register team' });
    }
});

app.post('/api/tournaments/:id/start', authenticateToken, (req, res) => {
    try {
        const tournament = db.tournaments[req.params.id];
        
        if (!tournament) {
            return res.status(404).json({ error: 'Tournament not found' });
        }
        
        // Verify host access
        if (tournament.hostId !== req.user.id && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Only the tournament host can start the tournament' });
        }
        
        if (tournament.status !== 'registration') {
            return res.status(400).json({ error: 'Tournament already started or completed' });
        }
        
        if (tournament.teams.length < 2) {
            return res.status(400).json({ error: 'Need at least 2 teams to start' });
        }
        
        tournament.status = 'ongoing';
        tournament.currentRound = 1;
        
        // Generate bracket
        const bracket = generateBracket(tournament);
        db.brackets[tournament.id] = bracket;
        
        // Create matches for first round
        createMatchesFromBracket(tournament.id, bracket);
        
        res.json({
            success: true,
            tournament,
            bracket,
            message: 'Tournament started successfully'
        });
    } catch (error) {
        console.error('Start tournament error:', error);
        res.status(500).json({ error: 'Failed to start tournament' });
    }
});

app.post('/api/tournaments/:id/manage', authenticateToken, (req, res) => {
    try {
        const { tournamentPass, action, data } = req.body;
        const tournament = db.tournaments[req.params.id];
        
        if (!tournament) {
            return res.status(404).json({ error: 'Tournament not found' });
        }
        
        // Verify host access using tournament pass or ownership
        const isOwner = tournament.hostId === req.user.id || req.user.isAdmin;
        const hasValidPass = tournamentPass === tournament.tournamentPass;
        
        if (!isOwner && !hasValidPass) {
            return res.status(403).json({ error: 'Invalid tournament pass or access denied' });
        }
        
        // Handle different management actions
        switch (action) {
            case 'update_match':
                updateMatchResult(data.matchId, data.winnerId, data.scores);
                break;
                
            case 'advance_round':
                advanceTournamentRound(tournament.id);
                break;
                
            case 'update_status':
                tournament.status = data.status;
                break;
                
            case 'add_admin':
                // Grant temporary admin access
                if (isOwner) {
                    // Would need to implement session-based admin access
                }
                break;
        }
        
        res.json({
            success: true,
            tournament,
            message: 'Tournament updated successfully'
        });
    } catch (error) {
        console.error('Tournament management error:', error);
        res.status(500).json({ error: 'Failed to manage tournament' });
    }
});

// ========== MATCH MANAGEMENT ==========
app.post('/api/matches/:id/submit-proof', authenticateToken, (req, res) => {
    try {
        const { imageUrl, description } = req.body;
        const match = db.matches[req.params.id];
        
        if (!match) {
            return res.status(404).json({ error: 'Match not found' });
        }
        
        const proofId = uuidv4();
        db.proofs[proofId] = {
            id: proofId,
            matchId: match.id,
            tournamentId: match.tournamentId,
            submittedBy: req.user.id,
            submittedByName: req.user.username,
            imageUrl,
            description,
            status: 'pending',
            submittedAt: new Date().toISOString()
        };
        
        res.json({
            success: true,
            proof: db.proofs[proofId],
            message: 'Proof submitted successfully'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit proof' });
    }
});

// ========== HELPER FUNCTIONS ==========
function generateTournamentPass() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let pass = '';
    for (let i = 0; i < 8; i++) {
        pass += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return pass;
}

function calculateRounds(teamCount) {
    return Math.ceil(Math.log2(teamCount));
}

function generateBracket(tournament) {
    const teams = tournament.teams.map(id => db.teams[id]);
    const bracket = {
        tournamentId: tournament.id,
        type: 'single_elimination',
        rounds: [],
        createdAt: new Date().toISOString()
    };
    
    // Shuffle teams for seeding
    const shuffledTeams = [...teams].sort(() => Math.random() - 0.5);
    
    // Create first round
    const round1 = {
        round: 1,
        matches: []
    };
    
    for (let i = 0; i < shuffledTeams.length; i += 2) {
        const matchId = uuidv4();
        round1.matches.push({
            matchId,
            team1Id: shuffledTeams[i].id,
            team2Id: shuffledTeams[i + 1]?.id || null,
            team1Name: shuffledTeams[i].name,
            team2Name: shuffledTeams[i + 1]?.name || 'BYE',
            winnerId: null,
            status: 'scheduled'
        });
    }
    
    bracket.rounds.push(round1);
    
    // Create empty rounds for bracket structure
    for (let round = 2; round <= tournament.totalRounds; round++) {
        const roundMatches = [];
        const matchesInRound = Math.pow(2, tournament.totalRounds - round);
        
        for (let i = 0; i < matchesInRound; i++) {
            const matchId = uuidv4();
            roundMatches.push({
                matchId,
                team1Id: null,
                team2Id: null,
                team1Name: 'TBD',
                team2Name: 'TBD',
                winnerId: null,
                status: 'pending'
            });
        }
        
        bracket.rounds.push({
            round,
            matches: roundMatches
        });
    }
    
    return bracket;
}

function createMatchesFromBracket(tournamentId, bracket) {
    const tournament = db.tournaments[tournamentId];
    
    bracket.rounds.forEach(round => {
        round.matches.forEach(match => {
            if (match.team1Id) {
                db.matches[match.matchId] = {
                    id: match.matchId,
                    tournamentId,
                    round: round.round,
                    team1Id: match.team1Id,
                    team2Id: match.team2Id,
                    team1Name: match.team1Name,
                    team2Name: match.team2Name,
                    winnerId: null,
                    status: match.status,
                    createdAt: new Date().toISOString()
                };
                tournament.matches.push(match.matchId);
            }
        });
    });
}

function updateMatchResult(matchId, winnerId, scores) {
    const match = db.matches[matchId];
    if (!match) return;
    
    match.winnerId = winnerId;
    match.scores = scores;
    match.status = 'completed';
    match.completedAt = new Date().toISOString();
    
    // Update team stats
    const winnerTeam = db.teams[winnerId];
    const loserTeam = db.teams[match.team1Id === winnerId ? match.team2Id : match.team1Id];
    
    if (winnerTeam) winnerTeam.wins++;
    if (loserTeam) loserTeam.losses++;
}

function advanceTournamentRound(tournamentId) {
    const tournament = db.tournaments[tournamentId];
    const bracket = db.brackets[tournamentId];
    
    if (!tournament || !bracket) return;
    
    const currentRound = tournament.currentRound;
    const nextRound = currentRound + 1;
    
    if (nextRound > tournament.totalRounds) {
        tournament.status = 'completed';
        return;
    }
    
    // Get winners from current round
    const currentMatches = bracket.rounds[currentRound - 1].matches;
    const winners = [];
    
    currentMatches.forEach(match => {
        if (match.winnerId) {
            winners.push(match.winnerId);
        }
    });
    
    // Update next round matches
    const nextRoundMatches = bracket.rounds[nextRound - 1].matches;
    let winnerIndex = 0;
    
    nextRoundMatches.forEach(match => {
        if (winnerIndex < winners.length) {
            match.team1Id = winners[winnerIndex];
            match.team1Name = db.teams[winners[winnerIndex]]?.name || 'TBD';
            winnerIndex++;
        }
        
        if (winnerIndex < winners.length) {
            match.team2Id = winners[winnerIndex];
            match.team2Name = db.teams[winners[winnerIndex]]?.name || 'TBD';
            winnerIndex++;
        }
        
        match.status = 'scheduled';
        
        // Create match in database
        if (match.team1Id && match.team2Id) {
            const matchId = uuidv4();
            db.matches[matchId] = {
                id: matchId,
                tournamentId,
                round: nextRound,
                team1Id: match.team1Id,
                team2Id: match.team2Id,
                team1Name: match.team1Name,
                team2Name: match.team2Name,
                winnerId: null,
                status: 'scheduled',
                createdAt: new Date().toISOString()
            };
            tournament.matches.push(matchId);
        }
    });
    
    tournament.currentRound = nextRound;
}

// ========== STATS & DASHBOARD ==========
app.get('/api/stats', (req, res) => {
    try {
        const activeTournaments = Object.values(db.tournaments).filter(t => t.status === 'ongoing').length;
        const totalTeams = Object.keys(db.teams).length;
        const totalUsers = Object.keys(db.users).length;
        
        res.json({
            success: true,
            stats: {
                activeTournaments,
                totalTeams,
                totalUsers,
                liveMatches: Object.values(db.matches).filter(m => m.status === 'ongoing').length
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ========== WEBSOCKET FOR LIVE UPDATES ==========
const WebSocket = require('ws');
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        const data = JSON.parse(message);
        
        if (data.type === 'subscribe') {
            ws.tournamentId = data.tournamentId;
        }
    });
    
    ws.on('close', () => {
        // Clean up
    });
});

function broadcastToTournament(tournamentId, message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.tournamentId === tournamentId) {
            client.send(JSON.stringify(message));
        }
    });
}

// ========== SERVER SETUP ==========
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    print(f"Server running on port {PORT}")

    console.log(`🌐 API available at http://localhost:${PORT}/api`);
});

// Attach WebSocket server
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

// Create default admin user on startup
(async () => {
    if (!db.users['admin']) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        db.users['admin'] = {
            id: uuidv4(),
            username: 'admin',
            password: hashedPassword,
            email: 'admin@tourney.com',
            isHost: true,
            isAdmin: true,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };
        console.log('✅ Default admin user created (admin:admin123)');
    }
    
    // Create some sample tournaments for testing
    if (Object.keys(db.tournaments).length === 0) {
        const tournamentId = uuidv4();
        db.tournaments[tournamentId] = {
            id: tournamentId,
            name: 'Summer Championship 2024',
            game: 'Valorant',
            description: 'Annual summer tournament with cash prizes',
            maxTeams: 16,
            maxPlayers: 5,
            prizePool: '$5,000',
            startDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
            region: 'global',
            status: 'registration',
            createdBy: 'admin',
            hostId: db.users['admin'].id,
            tournamentPass: generateTournamentPass(),
            createdAt: new Date().toISOString(),
            teams: [],
            matches: [],
            currentRound: 0,
            totalRounds: 4
        };
        console.log('✅ Sample tournament created');
    }
})();

module.exports = { app, db };

