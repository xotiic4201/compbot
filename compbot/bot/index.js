const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes, ChannelType, PermissionFlagsBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle } = require('discord.js');
const axios = require('axios');

// USE ENVIRONMENT VARIABLES
const DISCORD_TOKEN = process.env.DISCORD_TOKEN || "your-bot-token";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "1445127821742575726";
const API_URL = process.env.API_URL || "https://compbot-lhuy.onrender.com";

console.log('🚀 Starting XTourney Bot v2.0...');
console.log('API URL:', API_URL);

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessageReactions
    ]
});

// Tournament settings
const TOURNAMENT_SETTINGS = {
    maxPlayersPerTeam: 5,
    defaultQueueTime: 10, // minutes
    defaultMatchDuration: 30, // minutes
    regions: ['NA', 'EU', 'ASIA', 'GLOBAL']
};

// Slash Commands
const commands = [
    // TOURNAMENT COMMAND WITH ALL OPTIONS
    new SlashCommandBuilder()
        .setName('tournament')
        .setDescription('Tournament management')
        .addSubcommand(sub => sub
            .setName('create')
            .setDescription('Create new tournament (HOST role required)')
            .addStringOption(opt => opt.setName('name').setDescription('Tournament name').setRequired(true))
            .addStringOption(opt => opt.setName('game').setDescription('Game name').setRequired(true))
            .addStringOption(opt => opt.setName('date').setDescription('Start date (YYYY-MM-DD HH:MM)').setRequired(true))
            .addIntegerOption(opt => opt.setName('teams').setDescription('Max teams (8, 16, 32, 64)').setRequired(false)
                .addChoices(
                    { name: '8 Teams', value: 8 },
                    { name: '16 Teams', value: 16 },
                    { name: '32 Teams', value: 32 },
                    { name: '64 Teams', value: 64 }
                ))
            .addStringOption(opt => opt.setName('description').setDescription('Tournament description').setRequired(false))
            .addIntegerOption(opt => opt.setName('queue_time').setDescription('Queue time in minutes (default: 10)').setRequired(false))
            .addIntegerOption(opt => opt.setName('match_duration').setDescription('Match duration in minutes (default: 30)').setRequired(false))
            .addIntegerOption(opt => opt.setName('players_per_team').setDescription('Max players per team (default: 5)').setRequired(false))
            .addBooleanOption(opt => opt.setName('region_filter').setDescription('Filter by server region').setRequired(false))
            .addBooleanOption(opt => opt.setName('auto_start').setDescription('Auto-start when full (default: true)').setRequired(false)))
        .addSubcommand(sub => sub
            .setName('bracket')
            .setDescription('View tournament bracket')
            .addStringOption(opt => opt.setName('id').setDescription('Tournament ID').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('start')
            .setDescription('Manually start tournament')
            .addStringOption(opt => opt.setName('id').setDescription('Tournament ID').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('settings')
            .setDescription('Configure tournament settings')
            .addStringOption(opt => opt.setName('id').setDescription('Tournament ID').setRequired(true))),
    
    // TEAM REGISTRATION WITH MODAL
    new SlashCommandBuilder()
        .setName('team')
        .setDescription('Team management')
        .addSubcommand(sub => sub
            .setName('register')
            .setDescription('Register a team')
            .addStringOption(opt => opt.setName('tournament_id').setDescription('Tournament ID').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('add')
            .setDescription('Add player to your team')
            .addStringOption(opt => opt.setName('tournament_id').setDescription('Tournament ID').setRequired(true))
            .addUserOption(opt => opt.setName('player').setDescription('Player to add').setRequired(true))),
    
    // QUICK SETUP
    new SlashCommandBuilder()
        .setName('setup')
        .setDescription('Quick server setup (Admin only)')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
    
    // HELP COMMAND
    new SlashCommandBuilder()
        .setName('xtourney')
        .setDescription('XTourney bot information'),
    
    // LIVE BRACKETS COMMAND
    new SlashCommandBuilder()
        .setName('live')
        .setDescription('View live matches')
        .addStringOption(opt => opt.setName('tournament_id').setDescription('Tournament ID').setRequired(false))
];

const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);

// Store active tournaments
const activeTournaments = new Map();

client.once('ready', async () => {
    console.log(`✅ ${client.user.tag} is ready!`);
    console.log(`🤖 Bot ID: ${client.user.id}`);
    console.log(`🌐 Serving ${client.guilds.cache.size} servers`);
    
    client.user.setActivity('/xtourney | Live Tournaments', { type: 'PLAYING' });
    
    try {
        console.log('📝 Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(DISCORD_CLIENT_ID),
            { body: commands }
        );
        console.log('✅ Commands registered!');
    } catch (error) {
        console.error('❌ Command registration failed:', error);
    }
});

// Interaction handler for buttons/modals
client.on('interactionCreate', async interaction => {
    if (interaction.isCommand()) {
        await handleCommand(interaction);
    } else if (interaction.isButton()) {
        await handleButton(interaction);
    } else if (interaction.isModalSubmit()) {
        await handleModal(interaction);
    }
});

async function handleCommand(interaction) {
    const { commandName, options } = interaction;

    try {
        switch (commandName) {
            case 'tournament':
                await handleTournament(interaction, options);
                break;
            case 'team':
                await handleTeam(interaction, options);
                break;
            case 'setup':
                await handleSetup(interaction);
                break;
            case 'xtourney':
                await handleXTourney(interaction);
                break;
            case 'live':
                await handleLive(interaction, options);
                break;
        }
    } catch (error) {
        console.error(error);
        await interaction.reply({ 
            content: '❌ Error: ' + (error.response?.data?.detail || error.message), 
            flags: 64
        });
    }
}

async function handleTournament(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'create') {
        await interaction.deferReply();
        
        // Parse date
        let startDate;
        try {
            const dateString = options.getString('date');
            startDate = new Date(dateString).toISOString();
        } catch (e) {
            startDate = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        }
        
        const tournamentData = {
            name: options.getString('name'),
            game: options.getString('game'),
            description: options.getString('description') || '',
            max_teams: options.getInteger('teams') || 16,
            start_date: startDate,
            discord_server_id: interaction.guildId,
            created_by: interaction.user.id,
            bracket_type: 'single_elimination',
            queue_time_minutes: options.getInteger('queue_time') || 10,
            match_duration_minutes: options.getInteger('match_duration') || 30,
            max_players_per_team: options.getInteger('players_per_team') || 5,
            region_filter: options.getBoolean('region_filter') || false,
            auto_start: options.getBoolean('auto_start') ?? true
        };
        
        try {
            console.log('Creating tournament with data:', tournamentData);
            
            const response = await axios.post(`${API_URL}/api/bot/tournaments`, tournamentData, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.data.success) {
                const tournament = response.data.tournament;
                
                // Store in active tournaments
                activeTournaments.set(tournament.id, {
                    ...tournament,
                    registeredTeams: 0,
                    startTime: new Date(tournament.start_date)
                });
                
                // Create embed
                const embed = new EmbedBuilder()
                    .setTitle(`🎮 ${tournament.name}`)
                    .setDescription(`New ${tournament.game} tournament created!`)
                    .addFields(
                        { name: 'ID', value: `\`${tournament.id}\``, inline: true },
                        { name: 'Max Teams', value: `${tournament.max_teams}`, inline: true },
                        { name: 'Queue Time', value: `${tournamentData.queue_time_minutes} min`, inline: true },
                        { name: 'Starts', value: new Date(tournament.start_date).toLocaleString(), inline: true },
                        { name: 'Players/Team', value: `${tournamentData.max_players_per_team}`, inline: true },
                        { name: 'Region Filter', value: tournamentData.region_filter ? '✅ Enabled' : '❌ Disabled', inline: true },
                        { name: 'Auto Start', value: tournamentData.auto_start ? '✅ Yes' : '❌ No', inline: true },
                        { name: 'Host', value: `<@${interaction.user.id}>`, inline: true }
                    )
                    .setColor('#5865F2')
                    .setTimestamp();
                
                // Create registration buttons
                const row = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setCustomId(`register_${tournament.id}`)
                            .setLabel('🏆 Register Team')
                            .setStyle(ButtonStyle.Primary),
                        new ButtonBuilder()
                            .setCustomId(`bracket_${tournament.id}`)
                            .setLabel('📋 View Bracket')
                            .setStyle(ButtonStyle.Secondary),
                        new ButtonBuilder()
                            .setCustomId(`info_${tournament.id}`)
                            .setLabel('❓ Info')
                            .setStyle(ButtonStyle.Secondary)
                    );
                
                await interaction.editReply({ 
                    content: '✅ Tournament created successfully! Registration is open.',
                    embeds: [embed],
                    components: [row]
                });
                
                // Schedule auto-start check
                if (tournamentData.auto_start) {
                    setTimeout(() => checkAutoStart(tournament.id, interaction.guildId), 60000); // Check every minute
                }
                
            } else {
                throw new Error(response.data.detail || 'Failed to create tournament');
            }
            
        } catch (error) {
            console.error('Tournament creation error:', error.response?.data || error.message);
            await interaction.editReply({ 
                content: '❌ Failed to create tournament: ' + (error.response?.data?.detail || error.message) 
            });
        }
    }
    
    else if (subcommand === 'bracket') {
        const tournamentId = options.getString('id');
        await viewBracket(interaction, tournamentId);
    }
    
    else if (subcommand === 'start') {
        const tournamentId = options.getString('id');
        await startTournament(interaction, tournamentId);
    }
    
    else if (subcommand === 'settings') {
        const tournamentId = options.getString('id');
        await viewSettings(interaction, tournamentId);
    }
}

async function handleTeam(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'register') {
        const tournamentId = options.getString('tournament_id');
        
        // Create modal for team registration
        const modal = new ModalBuilder()
            .setCustomId(`team_register_${tournamentId}`)
            .setTitle('Register Team');
        
        const teamNameInput = new TextInputBuilder()
            .setCustomId('teamName')
            .setLabel("Team Name")
            .setStyle(TextInputStyle.Short)
            .setRequired(true)
            .setMinLength(3)
            .setMaxLength(32)
            .setPlaceholder('Enter your team name');
        
        const playerTagsInput = new TextInputBuilder()
            .setCustomId('playerTags')
            .setLabel("Player Discord Tags (optional)")
            .setStyle(TextInputStyle.Paragraph)
            .setRequired(false)
            .setPlaceholder('@player1, @player2, @player3\nSeparate with commas');
        
        const firstActionRow = new ActionRowBuilder().addComponents(teamNameInput);
        const secondActionRow = new ActionRowBuilder().addComponents(playerTagsInput);
        
        modal.addComponents(firstActionRow, secondActionRow);
        
        await interaction.showModal(modal);
    }
    
    else if (subcommand === 'add') {
        const tournamentId = options.getString('tournament_id');
        const player = options.getUser('player');
        
        await interaction.deferReply({ flags: 64 });
        
        try {
            const response = await axios.post(`${API_URL}/api/bot/teams/add_player`, {
                tournament_id: tournamentId,
                player_discord_id: player.id
            }, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.data.success) {
                await interaction.editReply({
                    content: `✅ ${player} added to your team!\nTeam size: ${response.data.team_size} players`
                });
            } else {
                throw new Error(response.data.detail || 'Failed to add player');
            }
            
        } catch (error) {
            await interaction.editReply({
                content: '❌ Failed to add player: ' + (error.response?.data?.detail || error.message)
            });
        }
    }
}

async function handleButton(interaction) {
    const customId = interaction.customId;
    
    if (customId.startsWith('register_')) {
        const tournamentId = customId.split('_')[1];
        
        // Show registration modal
        const modal = new ModalBuilder()
            .setCustomId(`team_register_${tournamentId}`)
            .setTitle('Register Team');
        
        const teamNameInput = new TextInputBuilder()
            .setCustomId('teamName')
            .setLabel("Team Name")
            .setStyle(TextInputStyle.Short)
            .setRequired(true)
            .setMinLength(3)
            .setMaxLength(32);
        
        const actionRow = new ActionRowBuilder().addComponents(teamNameInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
    }
    
    else if (customId.startsWith('bracket_')) {
        const tournamentId = customId.split('_')[1];
        await viewBracket(interaction, tournamentId);
    }
    
    else if (customId.startsWith('info_')) {
        const tournamentId = customId.split('_')[1];
        await interaction.deferReply({ flags: 64 });
        
        try {
            const response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
            
            if (response.data) {
                const tournament = response.data.tournament;
                
                const embed = new EmbedBuilder()
                    .setTitle(`ℹ️ ${tournament.name} Info`)
                    .setDescription(tournament.description || 'No description provided')
                    .addFields(
                        { name: 'Game', value: tournament.game, inline: true },
                        { name: 'Status', value: tournament.status.toUpperCase(), inline: true },
                        { name: 'Teams', value: `${tournament.current_teams}/${tournament.max_teams}`, inline: true },
                        { name: 'Start Time', value: new Date(tournament.start_date).toLocaleString(), inline: true },
                        { name: 'Tournament ID', value: `\`${tournament.id}\``, inline: true }
                    )
                    .setColor('#5865F2');
                
                await interaction.editReply({ embeds: [embed] });
            }
        } catch (error) {
            await interaction.editReply({ content: '❌ Error loading tournament info' });
        }
    }
}

async function handleModal(interaction) {
    if (!interaction.isModalSubmit()) return;
    
    const customId = interaction.customId;
    
    if (customId.startsWith('team_register_')) {
        const tournamentId = customId.split('_')[2];
        const teamName = interaction.fields.getTextInputValue('teamName');
        
        await interaction.deferReply({ flags: 64 });
        
        try {
            const response = await axios.post(`${API_URL}/api/bot/teams`, {
                tournament_id: tournamentId,
                name: teamName,
                captain_discord_id: interaction.user.id
            }, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.data.success) {
                const embed = new EmbedBuilder()
                    .setTitle('✅ Team Registered!')
                    .setDescription(`**${teamName}** has been registered`)
                    .addFields(
                        { name: 'Captain', value: `<@${interaction.user.id}>`, inline: true },
                        { name: 'Next Steps', value: 'Wait for tournament to start!\nAdd more players with `/team add`', inline: false }
                    )
                    .setColor('#57F287');
                
                await interaction.editReply({ 
                    content: `✅ Team **${teamName}** registered successfully!`,
                    embeds: [embed]
                });
            } else {
                throw new Error(response.data.detail || 'Registration failed');
            }
            
        } catch (error) {
            await interaction.editReply({ 
                content: '❌ Registration failed: ' + (error.response?.data?.detail || error.message) 
            });
        }
    }
}

async function viewBracket(interaction, tournamentId) {
    await interaction.deferReply();
    
    try {
        const response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
        
        if (response.data) {
            const { tournament, teams, rounds } = response.data;
            
            const embed = new EmbedBuilder()
                .setTitle(`📋 ${tournament.name} Bracket`)
                .setDescription(`**${tournament.game}** - ${tournament.status.toUpperCase()}`)
                .addFields(
                    { name: 'Teams', value: `${tournament.current_teams}/${tournament.max_teams}`, inline: true },
                    { name: 'Type', value: tournament.bracket_type.replace('_', ' ').toUpperCase(), inline: true },
                    { name: 'Round', value: Object.keys(rounds).length > 0 ? `Round ${Math.max(...Object.keys(rounds).map(Number))}` : 'Not started', inline: true }
                )
                .setColor('#F1C40F');
            
            // Add match details if available
            if (Object.keys(rounds).length > 0) {
                const currentRound = Math.min(...Object.keys(rounds).map(Number));
                const roundMatches = rounds[currentRound];
                
                let matchText = '';
                roundMatches.slice(0, 5).forEach(match => {
                    const team1 = teams.find(t => t.id === match.team1_id);
                    const team2 = teams.find(t => t.id === match.team2_id);
                    
                    matchText += `\n**Match ${match.match_number}:**\n`;
                    matchText += `${team1 ? `🟢 ${team1.name}` : '⚪ TBD'} vs ${team2 ? `🔴 ${team2.name}` : '⚪ TBD'}\n`;
                    
                    // Show player @mentions
                    if (team1 && team1.players) {
                        matchText += `Team 1: ${team1.players.map(p => `<@${p.discord_id}>`).join(', ')}\n`;
                    }
                    if (team2 && team2.players) {
                        matchText += `Team 2: ${team2.players.map(p => `<@${p.discord_id}>`).join(', ')}\n`;
                    }
                });
                
                embed.addFields({
                    name: `Round ${currentRound} Matches`,
                    value: matchText.substring(0, 1024)
                });
            }
            
            // Add registered teams list
            if (teams.length > 0) {
                let teamsText = teams.map(team => 
                    `${team.name} (${team.players ? team.players.length : 1} players)`
                ).join('\n');
                
                if (teamsText.length > 1024) {
                    teamsText = teamsText.substring(0, 1000) + '...';
                }
                
                embed.addFields({
                    name: 'Registered Teams',
                    value: teamsText || 'No teams yet'
                });
            }
            
            embed.setFooter({ text: `Tournament ID: ${tournament.id}` });
            
            await interaction.editReply({ embeds: [embed] });
        } else {
            throw new Error('Tournament not found');
        }
        
    } catch (error) {
        await interaction.editReply({ 
            content: '❌ Error loading bracket: ' + (error.response?.data?.detail || error.message) 
        });
    }
}

async function startTournament(interaction, tournamentId) {
    await interaction.deferReply();
    
    try {
        // Check if user is host
        const response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
        
        if (!response.data) {
            throw new Error('Tournament not found');
        }
        
        const tournament = response.data.tournament;
        
        // Verify host permission
        if (interaction.user.id !== tournament.created_by) {
            // Check Discord roles
            const member = await interaction.guild.members.fetch(interaction.user.id);
            const hasHostRole = member.roles.cache.some(role => 
                role.name.toLowerCase().includes('host') || 
                role.name.toLowerCase().includes('tournament')
            );
            
            if (!hasHostRole) {
                throw new Error('Only the host or users with HOST role can start the tournament');
            }
        }
        
        // Update tournament status
        await axios.patch(`${API_URL}/tournaments/${tournamentId}/status`, {
            status: 'ongoing'
        });
        
        // Generate bracket matches
        await axios.post(`${API_URL}/tournaments/${tournamentId}/generate_bracket`);
        
        const embed = new EmbedBuilder()
            .setTitle('🏁 Tournament Started!')
            .setDescription(`**${tournament.name}** is now LIVE!`)
            .addFields(
                { name: 'Teams', value: `${tournament.current_teams}`, inline: true },
                { name: 'First Round', value: 'Matches have been generated', inline: true },
                { name: 'Bracket', value: 'Check `/live` for match updates', inline: true }
            )
            .setColor('#57F287');
        
        await interaction.editReply({ 
            content: '✅ Tournament started successfully!',
            embeds: [embed]
        });
        
        // Announce in server
        const channels = await interaction.guild.channels.fetch();
        const announcementsChannel = channels.find(c => 
            c.type === ChannelType.GuildText && 
            (c.name.includes('announce') || c.name.includes('general'))
        );
        
        if (announcementsChannel) {
            const announceEmbed = new EmbedBuilder()
                .setTitle('🎮 TOURNAMENT LIVE!')
                .setDescription(`**${tournament.name}** has started!\n\nUse \`/live ${tournamentId}\` to view matches`)
                .setColor('#FFD700')
                .setTimestamp();
            
            await announcementsChannel.send({ embeds: [announceEmbed] });
        }
        
    } catch (error) {
        await interaction.editReply({ 
            content: '❌ Failed to start tournament: ' + (error.response?.data?.detail || error.message) 
        });
    }
}

async function handleLive(interaction, options) {
    await interaction.deferReply();
    
    const tournamentId = options.getString('tournament_id');
    
    try {
        let response;
        if (tournamentId) {
            response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
        } else {
            // Get all active tournaments in server
            response = await axios.get(`${API_URL}/api/bot/tournaments/server/${interaction.guildId}`);
        }
        
        if (!response.data) {
            throw new Error('No active tournaments found');
        }
        
        const embed = new EmbedBuilder()
            .setTitle('🔴 LIVE TOURNAMENTS')
            .setDescription('Currently active matches:')
            .setColor('#FF0000');
        
        if (tournamentId) {
            const { tournament, teams, rounds } = response.data;
            
            // Find ongoing matches
            let liveMatches = [];
            for (const roundNum in rounds) {
                for (const match of rounds[roundNum]) {
                    if (match.status === 'ongoing') {
                        const team1 = teams.find(t => t.id === match.team1_id);
                        const team2 = teams.find(t => t.id === match.team2_id);
                        
                        liveMatches.push({
                            round: roundNum,
                            match: match.match_number,
                            team1: team1?.name || 'TBD',
                            team2: team2?.name || 'TBD',
                            score: `${match.score_team1 || 0}-${match.score_team2 || 0}`
                        });
                    }
                }
            }
            
            if (liveMatches.length > 0) {
                embed.addFields({
                    name: `Live in ${tournament.name}`,
                    value: liveMatches.map(m => 
                        `**Match ${m.match} (R${m.round}):** ${m.team1} ${m.score} ${m.team2}`
                    ).join('\n')
                });
            } else {
                embed.addFields({
                    name: tournament.name,
                    value: 'No live matches currently. Next round starting soon...'
                });
            }
        } else {
            // Show all tournaments
            const tournaments = response.data.tournaments || [];
            const active = tournaments.filter(t => t.status === 'ongoing');
            
            if (active.length > 0) {
                active.forEach(tournament => {
                    embed.addFields({
                        name: tournament.name,
                        value: `${tournament.game} • ${tournament.current_teams} teams\n\`/live ${tournament.id}\` for matches`,
                        inline: true
                    });
                });
            } else {
                embed.setDescription('No live tournaments currently. Check back later!');
            }
        }
        
        await interaction.editReply({ embeds: [embed] });
        
    } catch (error) {
        await interaction.editReply({ 
            content: '❌ Error loading live matches: ' + (error.response?.data?.detail || error.message) 
        });
    }
}

async function checkAutoStart(tournamentId, guildId) {
    try {
        const response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
        
        if (response.data) {
            const tournament = response.data.tournament;
            
            // Check if should auto-start
            const now = new Date();
            const startTime = new Date(tournament.start_date);
            const timeUntilStart = (startTime - now) / (1000 * 60); // minutes
            
            // Auto-start if full or start time reached
            if (tournament.current_teams >= tournament.max_teams || timeUntilStart <= 0) {
                // Start tournament
                await startTournamentAutomatically(tournamentId, guildId);
            } else {
                // Schedule next check
                setTimeout(() => checkAutoStart(tournamentId, guildId), 60000);
            }
        }
    } catch (error) {
        console.error('Auto-start check error:', error);
    }
}

async function startTournamentAutomatically(tournamentId, guildId) {
    try {
        // Update status
        await axios.patch(`${API_URL}/tournaments/${tournamentId}/status`, {
            status: 'ongoing'
        });
        
        // Generate bracket
        await axios.post(`${API_URL}/tournaments/${tournamentId}/generate_bracket`);
        
        // Send notification
        const guild = await client.guilds.fetch(guildId);
        const channels = await guild.channels.fetch();
        const announcementsChannel = channels.find(c => 
            c.type === ChannelType.GuildText && 
            c.name.includes('announce')
        );
        
        if (announcementsChannel) {
            const embed = new EmbedBuilder()
                .setTitle('⏰ Tournament Auto-Started!')
                .setDescription('Tournament has automatically started because all slots are filled!')
                .setColor('#00FF00')
                .setTimestamp();
            
            await announcementsChannel.send({ embeds: [embed] });
        }
        
        console.log(`Tournament ${tournamentId} auto-started`);
        
    } catch (error) {
        console.error('Auto-start error:', error);
    }
}

// Setup and other handlers remain similar to previous code...
// [Rest of the code remains the same as your previous bot.js]

client.login(DISCORD_TOKEN).catch(console.error);
