const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes, ChannelType } = require('discord.js');
require('dotenv').config();
const axios = require('axios');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers
    ]
});

const API_URL = process.env.API_URL || "https://compbot-lhuy.onrender.com";

// Channel types for tournament management
const CHANNEL_TYPES = [
    { name: '📢 Announcements', value: 'announcements', description: 'Tournament announcements' },
    { name: '📝 Registrations', value: 'registrations', description: 'Team registration' },
    { name: '🏆 Brackets', value: 'brackets', description: 'Live brackets & results' },
    { name: '👥 LFG', value: 'lfg', description: 'Looking for players' },
    { name: '🎮 Clips', value: 'clips', description: 'Game highlights' },
    { name: '✅ Verifications', value: 'verifications', description: 'Match proof review' },
    { name: '📊 Logs', value: 'logs', description: 'Activity logs' }
];

// Slash Commands
const commands = [
    // CHANNELS COMMAND
    new SlashCommandBuilder()
        .setName('channels')
        .setDescription('Configure tournament channels')
        .addSubcommand(sub => sub
            .setName('set')
            .setDescription('Set a channel type')
            .addStringOption(opt => opt
                .setName('type')
                .setDescription('What this channel is for')
                .setRequired(true)
                .addChoices(...CHANNEL_TYPES.map(ct => ({ name: ct.name, value: ct.value }))))
            .addChannelOption(opt => opt
                .setName('channel')
                .setDescription('Select the channel')
                .setRequired(true)
                .addChannelTypes(ChannelType.GuildText)))
        .addSubcommand(sub => sub
            .setName('view')
            .setDescription('See current channel setup')),
    
    // TOURNAMENT COMMANDS
    new SlashCommandBuilder()
        .setName('tournament')
        .setDescription('Tournament management')
        .addSubcommand(sub => sub
            .setName('create')
            .setDescription('Create new tournament (HOST role required)')
            .addStringOption(opt => opt.setName('name').setDescription('Tournament name').setRequired(true))
            .addStringOption(opt => opt.setName('game').setDescription('Game name').setRequired(true))
            .addStringOption(opt => opt.setName('date').setDescription('Start date (YYYY-MM-DD HH:MM)').setRequired(true))
            .addIntegerOption(opt => opt.setName('teams').setDescription('Max teams (8, 16, 32, 64)').setRequired(false))
            .addStringOption(opt => opt.setName('description').setDescription('Tournament description').setRequired(false)))
        .addSubcommand(sub => sub
            .setName('bracket')
            .setDescription('View tournament bracket')
            .addStringOption(opt => opt.setName('id').setDescription('Tournament ID').setRequired(true))),
    
    // TEAM REGISTRATION
    new SlashCommandBuilder()
        .setName('team')
        .setDescription('Team management')
        .addSubcommand(sub => sub
            .setName('register')
            .setDescription('Register a team')
            .addStringOption(opt => opt.setName('tournament_id').setDescription('Tournament ID').setRequired(true))
            .addStringOption(opt => opt.setName('name').setDescription('Team name').setRequired(true))),
    
    // QUICK SETUP
    new SlashCommandBuilder()
        .setName('setup')
        .setDescription('Quick server setup (Admin only)')
];

// Register commands
const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

client.once('ready', async () => {
    console.log(`✅ ${client.user.tag} is ready!`);
    client.user.setActivity('/help | XTourney');
    
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
            { body: commands }
        );
        console.log('✅ Commands registered!');
    } catch (error) {
        console.error('❌ Command registration failed:', error);
    }
});

// Command handler
client.on('interactionCreate', async interaction => {
    if (!interaction.isCommand()) return;

    const { commandName, options } = interaction;

    try {
        switch (commandName) {
            case 'channels':
                await handleChannels(interaction, options);
                break;
            case 'tournament':
                await handleTournament(interaction, options);
                break;
            case 'team':
                await handleTeam(interaction, options);
                break;
            case 'setup':
                await handleSetup(interaction);
                break;
        }
    } catch (error) {
        console.error(error);
        await interaction.reply({ 
            content: '❌ Error: ' + (error.response?.data?.detail || error.message), 
            ephemeral: true 
        });
    }
});

// Channels handler
async function handleChannels(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'set') {
        if (!interaction.member.permissions.has('ADMINISTRATOR')) {
            await interaction.reply({ content: '❌ Need admin permissions!', ephemeral: true });
            return;
        }
        
        const channelType = options.getString('type');
        const channel = options.getChannel('channel');
        
        await interaction.deferReply({ ephemeral: true });
        
        try {
            await axios.post(`${API_URL}/channels/set`, {
                discord_server_id: interaction.guildId,
                channel_type: channelType,
                discord_channel_id: channel.id,
                channel_name: channel.name
            });
            
            const channelInfo = CHANNEL_TYPES.find(ct => ct.value === channelType);
            
            const embed = new EmbedBuilder()
                .setTitle('✅ Channel Configured')
                .setDescription(`**${channelInfo.name}** will now use ${channel}`)
                .addFields(
                    { name: 'Type', value: channelInfo.description, inline: true },
                    { name: 'Channel', value: `<#${channel.id}>`, inline: true }
                )
                .setColor('#57F287');
            
            await interaction.editReply({ embeds: [embed] });
            
        } catch (error) {
            await interaction.editReply({ 
                content: '❌ Failed to set channel: ' + (error.response?.data?.detail || error.message) 
            });
        }
    }
    
    else if (subcommand === 'view') {
        try {
            const response = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
            const channels = response.data;
            
            const embed = new EmbedBuilder()
                .setTitle('📋 Configured Channels')
                .setDescription('Tournament channels:')
                .setColor('#5865F2');
            
            if (!channels || channels.length === 0) {
                embed.setDescription('❌ No channels configured yet!\nUse `/channels set` or `/setup`');
            } else {
                channels.forEach(ch => {
                    const channelInfo = CHANNEL_TYPES.find(ct => ct.value === ch.channel_type);
                    embed.addFields({
                        name: channelInfo?.name || ch.channel_type,
                        value: `<#${ch.discord_channel_id}>\n${channelInfo?.description || ''}`,
                        inline: true
                    });
                });
            }
            
            await interaction.reply({ embeds: [embed], ephemeral: true });
        } catch (error) {
            await interaction.reply({ 
                content: '❌ Error fetching channels: ' + (error.response?.data?.detail || error.message), 
                ephemeral: true 
            });
        }
    }
}

// Tournament handler
async function handleTournament(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'create') {
        await interaction.deferReply();
        
        // Parse date
        let startDate;
        try {
            startDate = new Date(options.getString('date')).toISOString();
        } catch (e) {
            startDate = new Date().toISOString();
        }
        
        const tournamentData = {
            name: options.getString('name'),
            game: options.getString('game'),
            description: options.getString('description') || '',
            max_teams: options.getInteger('teams') || 16,
            start_date: startDate,
            discord_server_id: interaction.guildId,
            created_by: interaction.user.id,
            bracket_type: 'single_elimination'
        };
        
        try {
            const response = await axios.post(`${API_URL}/api/bot/tournaments`, tournamentData, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.data.success) {
                const tournament = response.data.tournament;
                
                // Create embed
                const embed = new EmbedBuilder()
                    .setTitle(`🎮 ${tournament.name}`)
                    .setDescription(`New ${tournament.game} tournament created!`)
                    .addFields(
                        { name: 'ID', value: `\`${tournament.id}\``, inline: true },
                        { name: 'Max Teams', value: `${tournament.max_teams}`, inline: true },
                        { name: 'Status', value: '🟢 REGISTRATION OPEN', inline: true },
                        { name: 'Starts', value: new Date(tournament.start_date).toLocaleString(), inline: true },
                        { name: 'Host', value: `<@${interaction.user.id}>`, inline: true }
                    )
                    .setColor('#5865F2')
                    .setTimestamp();
                
                // Try to send to announcements channel
                try {
                    const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
                    const channels = channelsRes.data;
                    const announceChannel = channels.find(c => c.channel_type === 'announcements');
                    
                    if (announceChannel) {
                        const announceChannelObj = await interaction.guild.channels.fetch(announceChannel.discord_channel_id);
                        await announceChannelObj.send({ 
                            content: '🎉 **New Tournament Created!**',
                            embeds: [embed]
                        });
                    }
                    
                    await interaction.editReply({ 
                        content: `✅ Tournament created successfully! Check the announcements channel.` 
                    });
                    
                } catch (channelError) {
                    await interaction.editReply({ 
                        content: '✅ Tournament created! (Set up channels with `/channels set` for announcements)', 
                        embeds: [embed]
                    });
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
        
        await interaction.deferReply();
        
        try {
            const response = await axios.get(`${API_URL}/api/bot/tournaments/${tournamentId}/bracket`);
            
            if (response.data) {
                const bracketData = response.data;
                const tournament = bracketData.tournament;
                
                const embed = new EmbedBuilder()
                    .setTitle(`📋 ${tournament.name} Bracket`)
                    .setDescription(`**${tournament.game}** - ${tournament.description || 'No description'}`)
                    .addFields(
                        { name: 'Status', value: tournament.status.toUpperCase(), inline: true },
                        { name: 'Teams', value: `${tournament.current_teams}/${tournament.max_teams}`, inline: true },
                        { name: 'Type', value: tournament.bracket_type.replace('_', ' ').toUpperCase(), inline: true }
                    )
                    .setColor('#F1C40F');
                
                const rounds = bracketData.rounds || {};
                if (Object.keys(rounds).length > 0) {
                    let bracketText = '';
                    for (const roundNum in rounds) {
                        bracketText += `\n**Round ${roundNum}:**\n`;
                        rounds[roundNum].forEach(match => {
                            bracketText += `Match ${match.match_number}: ${match.team1_id ? 'Team' : 'TBD'} vs ${match.team2_id ? 'Team' : 'TBD'}\n`;
                        });
                    }
                    
                    embed.addFields({
                        name: 'Bracket Structure',
                        value: bracketText.substring(0, 1020) + (bracketText.length > 1020 ? '...' : '')
                    });
                } else {
                    embed.addFields({
                        name: 'Bracket Status',
                        value: 'No bracket generated yet. Teams need to register first.'
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
}

// Team handler
async function handleTeam(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'register') {
        const tournamentId = options.getString('tournament_id');
        const teamName = options.getString('name');
        
        await interaction.deferReply({ ephemeral: true });
        
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
                const team = response.data.team;
                
                const embed = new EmbedBuilder()
                    .setTitle('✅ Team Registered!')
                    .setDescription(`**${team.name}** has been registered`)
                    .addFields(
                        { name: 'Tournament ID', value: `\`${tournamentId}\``, inline: true },
                        { name: 'Captain', value: `<@${interaction.user.id}>`, inline: true }
                    )
                    .setColor('#57F287');
                
                // Try to send to registrations channel
                try {
                    const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
                    const channels = channelsRes.data;
                    const regChannel = channels.find(c => c.channel_type === 'registrations');
                    
                    if (regChannel) {
                        const regChannelObj = await interaction.guild.channels.fetch(regChannel.discord_channel_id);
                        await regChannelObj.send({ 
                            content: '👥 **New Team Registration!**',
                            embeds: [embed] 
                        });
                    }
                } catch (channelError) {
                    // Continue
                }
                
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

// Setup handler
async function handleSetup(interaction) {
    if (!interaction.member.permissions.has('ADMINISTRATOR')) {
        await interaction.reply({ content: '❌ Need admin permissions!', ephemeral: true });
        return;
    }
    
    await interaction.deferReply();
    
    try {
        // Create category
        const category = await interaction.guild.channels.create({
            name: '🎮 XTOURNEY',
            type: ChannelType.GuildCategory,
            permissionOverwrites: [
                {
                    id: interaction.guild.id,
                    allow: ['ViewChannel'],
                    deny: ['SendMessages']
                },
                {
                    id: interaction.client.user.id,
                    allow: ['ViewChannel', 'SendMessages', 'ManageMessages']
                }
            ]
        });
        
        const createdChannels = [];
        
        // Create channels
        for (const channelType of CHANNEL_TYPES) {
            const channel = await interaction.guild.channels.create({
                name: channelType.value,
                type: ChannelType.GuildText,
                parent: category.id,
                topic: channelType.description
            });
            
            // Save to database
            try {
                await axios.post(`${API_URL}/channels/set`, {
                    discord_server_id: interaction.guildId,
                    channel_type: channelType.value,
                    discord_channel_id: channel.id,
                    channel_name: channel.name
                });
                
                createdChannels.push(channel);
            } catch (dbError) {
                console.log('DB error:', dbError.message);
            }
        }
        
        // Create roles
        const hostRole = await interaction.guild.roles.create({
            name: 'Tournament Host',
            color: 'Blue',
            mentionable: true
        });
        
        // Assign host role to command user
        try {
            await interaction.member.roles.add(hostRole);
        } catch (roleError) {
            console.log('Could not assign host role:', roleError.message);
        }
        
        const embed = new EmbedBuilder()
            .setTitle('✅ XTourney Setup Complete!')
            .setDescription('Tournament system has been set up successfully!')
            .addFields(
                { name: 'Category', value: `${category}`, inline: true },
                { name: 'Channels Created', value: createdChannels.length.toString(), inline: true },
                { name: 'Host Role', value: `${hostRole}`, inline: true }
            )
            .addFields({
                name: '📋 Channel Guide',
                value: createdChannels.map(c => `<#${c.id}>`).join('\n')
            })
            .setColor('#57F287');
        
        await interaction.editReply({ embeds: [embed] });
        
    } catch (error) {
        console.error('Setup error:', error);
        await interaction.editReply({ 
            content: '❌ Setup failed: ' + error.message 
        });
    }
}

// Start bot
client.login(process.env.DISCORD_TOKEN).catch(error => {
    console.error('❌ Failed to login:', error);
});
