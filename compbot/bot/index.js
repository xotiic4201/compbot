const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes, ActionRowBuilder, ButtonBuilder, ButtonStyle, ChannelType } = require('discord.js');
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

const API_URL = process.env.API_URL || "https://your-render-backend.onrender.com"; // Your Render URL

// ========== CHANNEL TYPES ==========
const CHANNEL_TYPES = [
    { name: '📢 Announcements', value: 'announcements', description: 'Tournament announcements' },
    { name: '📝 Registrations', value: 'registrations', description: 'Team registration' },
    { name: '🏆 Brackets', value: 'brackets', description: 'Live brackets & results' },
    { name: '👥 LFG', value: 'lfg', description: 'Looking for players' },
    { name: '🎮 Clips', value: 'clips', description: 'Game highlights' },
    { name: '✅ Verifications', value: 'verifications', description: 'Match proof review' },
    { name: '📊 Logs', value: 'logs', description: 'Activity logs' }
];

// ========== SLASH COMMANDS ==========
const commands = [
    // CHANNELS COMMAND
    new SlashCommandBuilder()
        .setName('channels')
        .setDescription('Configure where tournament info goes')
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
            .setDescription('See current channel setup'))
        .addSubcommand(sub => sub
            .setName('setup-help')
            .setDescription('Get setup instructions')),
    
    // TOURNAMENT COMMANDS
    new SlashCommandBuilder()
        .setName('tournament')
        .setDescription('Tournament management')
        .addSubcommand(sub => sub
            .setName('create')
            .setDescription('Create new tournament')
            .addStringOption(opt => opt.setName('name').setDescription('Tournament name').setRequired(true))
            .addStringOption(opt => opt.setName('game').setDescription('Game name').setRequired(true))
            .addStringOption(opt => opt.setName('date').setDescription('Start date (YYYY-MM-DD HH:MM)').setRequired(true))
            .addIntegerOption(opt => opt.setName('teams').setDescription('Max teams').setRequired(false)))
        .addSubcommand(sub => sub
            .setName('list')
            .setDescription('List your tournaments'))
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
        .setDescription('Quick server setup')
];

// ========== REGISTER COMMANDS ==========
const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

client.once('ready', async () => {
    console.log(`✅ ${client.user.tag} is ready!`);
    client.user.setActivity('/setup | XTourney');
    
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

// ========== COMMAND HANDLER ==========
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

// ========== CHANNELS HANDLER ==========
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
            const response = await axios.post(`${API_URL}/channels/set`, {
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
                .setColor('#57F287')
                .setFooter({ text: 'Use /channels view to see all configured channels' });
            
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
                .setDescription('Here are all the channels set for tournaments:')
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
    
    else if (subcommand === 'setup-help') {
        const embed = new EmbedBuilder()
            .setTitle('🛠️ Channel Setup Guide')
            .setDescription('Configure these channels for full functionality:')
            .setColor('#F1C40F');
        
        CHANNEL_TYPES.forEach((ct, i) => {
            embed.addFields({
                name: `${ct.name}`,
                value: `${ct.description}\n\`/channels set type:${ct.value}\``,
                inline: i < CHANNEL_TYPES.length / 2
            });
        });
        
        embed.addFields({
            name: '📌 Quick Setup',
            value: 'Use `/setup` to auto-create all channels'
        });
        
        await interaction.reply({ embeds: [embed], ephemeral: true });
    }
}

// ========== TOURNAMENT HANDLER ==========
async function handleTournament(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'create') {
        await interaction.deferReply();
        
        // Parse date string to ISO format
        let startDate;
        try {
            startDate = new Date(options.getString('date')).toISOString();
        } catch (e) {
            startDate = new Date().toISOString(); // Default to now if parsing fails
        }
        
        const tournamentData = {
            name: options.getString('name'),
            game: options.getString('game'),
            max_teams: options.getInteger('teams') || 16,
            start_date: startDate,
            discord_server_id: interaction.guildId,
            created_by: interaction.user.id,
            bracket_type: 'single_elimination'
        };
        
        try {
            const response = await axios.post(`${API_URL}/api/tournaments`, tournamentData, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.data.success) {
                const tournament = response.data.tournament;
                
                const embed = new EmbedBuilder()
                    .setTitle(`🎮 ${tournament.name}`)
                    .setDescription(`New ${tournament.game} tournament created!`)
                    .addFields(
                        { name: 'ID', value: `\`${tournament.id}\``, inline: true },
                        { name: 'Max Teams', value: `${tournament.max_teams}`, inline: true },
                        { name: 'Status', value: '🟢 REGISTRATION OPEN', inline: true },
                        { name: 'Starts', value: new Date(tournament.start_date).toLocaleString(), inline: true },
                        { name: 'Host', value: `<@${interaction.user.id}>`, inline: true },
                        { name: 'Game', value: tournament.game, inline: true }
                    )
                    .setColor('#5865F2')
                    .setTimestamp();
                
                // Add registration button
                const row = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setCustomId(`register_${tournament.id}`)
                            .setLabel('Register Team')
                            .setStyle(ButtonStyle.Primary),
                        new ButtonBuilder()
                            .setLabel('View on Website')
                            .setURL(`${process.env.WEBSITE_URL || 'https://xtourney.vercel.app'}`)
                            .setStyle(ButtonStyle.Link)
                    );
                
                // Try to send to announcements channel
                try {
                    const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
                    const channels = channelsRes.data;
                    const announceChannel = channels.find(c => c.channel_type === 'announcements');
                    
                    if (announceChannel) {
                        const announceChannelObj = await interaction.guild.channels.fetch(announceChannel.discord_channel_id);
                        await announceChannelObj.send({ 
                            content: '🎉 **New Tournament Created!**',
                            embeds: [embed],
                            components: [row]
                        });
                        await interaction.editReply({ 
                            content: `✅ Tournament created and announced in <#${announceChannel.discord_channel_id}>!` 
                        });
                    } else {
                        await interaction.editReply({ 
                            content: '✅ Tournament created! (No announcements channel set)', 
                            embeds: [embed],
                            components: [row]
                        });
                    }
                } catch (channelError) {
                    await interaction.editReply({ 
                        content: '✅ Tournament created!', 
                        embeds: [embed],
                        components: [row]
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
    
    else if (subcommand === 'list') {
        await interaction.deferReply({ ephemeral: true });
        
        try {
            // In production, you'd need to pass auth token
            // For now, we'll just show a message
            const embed = new EmbedBuilder()
                .setTitle('📋 Your Tournaments')
                .setDescription('View and manage your tournaments on the XTourney website:')
                .addFields({
                    name: 'Website',
                    value: `[XTourney Dashboard](${process.env.WEBSITE_URL || 'https://xtourney.vercel.app'})`
                })
                .setColor('#5865F2');
            
            await interaction.editReply({ embeds: [embed] });
            
        } catch (error) {
            await interaction.editReply({ 
                content: '❌ Error: ' + (error.response?.data?.detail || error.message) 
            });
        }
    }
    
    else if (subcommand === 'bracket') {
        const tournamentId = options.getString('id');
        
        await interaction.deferReply();
        
        try {
            const response = await axios.get(`${API_URL}/api/tournaments/${tournamentId}/bracket`);
            
            if (response.data) {
                const bracketData = response.data;
                const tournament = bracketData.tournament;
                
                const embed = new EmbedBuilder()
                    .setTitle(`📋 ${tournament.name} Bracket`)
                    .setDescription(`Current bracket status for ${tournament.game}`)
                    .addFields(
                        { name: 'Status', value: tournament.status.toUpperCase(), inline: true },
                        { name: 'Teams', value: `${tournament.current_teams}/${tournament.max_teams}`, inline: true },
                        { name: 'Type', value: tournament.bracket_type.replace('_', ' ').toUpperCase(), inline: true }
                    )
                    .setColor('#F1C40F');
                
                // Show rounds info
                const rounds = bracketData.rounds;
                if (rounds && Object.keys(rounds).length > 0) {
                    const roundCount = Object.keys(rounds).length;
                    const matchesCount = Object.values(rounds).flat().length;
                    
                    embed.addFields(
                        { name: 'Rounds', value: `${roundCount}`, inline: true },
                        { name: 'Total Matches', value: `${matchesCount}`, inline: true }
                    );
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

// ========== TEAM HANDLER ==========
async function handleTeam(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'register') {
        const tournamentId = options.getString('tournament_id');
        const teamName = options.getString('name');
        
        await interaction.deferReply({ ephemeral: true });
        
        try {
            const response = await axios.post(`${API_URL}/api/teams`, {
                tournament_id: tournamentId,
                name: teamName
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
                        { name: 'Captain', value: `<@${interaction.user.id}>`, inline: true },
                        { name: 'Team ID', value: `\`${team.id}\``, inline: false }
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

// ========== SETUP HANDLER ==========
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
                    allow: ['ViewChannel', 'SendMessages', 'ManageMessages', 'ManageChannels']
                }
            ],
            reason: 'XTourney tournament management system'
        });
        
        const createdChannels = [];
        
        // Create all channel types
        for (const channelType of CHANNEL_TYPES) {
            const channel = await interaction.guild.channels.create({
                name: channelType.value,
                type: ChannelType.GuildText,
                parent: category.id,
                topic: channelType.description,
                permissionOverwrites: [
                    {
                        id: interaction.guild.id,
                        allow: ['ViewChannel', 'SendMessages'],
                        deny: []
                    }
                ],
                reason: `XTourney ${channelType.description} channel`
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
                // Continue even if DB fails
            }
        }
        
        // Create roles
        const organizerRole = await interaction.guild.roles.create({
            name: 'Tournament Host',
            color: 'Blue',
            mentionable: true,
            reason: 'XTourney tournament hosts'
        });
        
        const playerRole = await interaction.guild.roles.create({
            name: 'Tournament Player',
            color: 'Green',
            reason: 'XTourney tournament participants'
        });
        
        const adminRole = await interaction.guild.roles.create({
            name: 'Tournament Admin',
            color: 'Red',
            mentionable: true,
            reason: 'XTourney tournament administrators'
        });
        
        // Assign admin role to command user
        try {
            const member = await interaction.guild.members.fetch(interaction.user.id);
            await member.roles.add(adminRole);
        } catch (roleError) {
            console.log('Could not assign admin role:', roleError.message);
        }
        
        const embed = new EmbedBuilder()
            .setTitle('✅ XTourney Setup Complete!')
            .setDescription('Tournament system has been set up successfully!')
            .addFields(
                { name: 'Category', value: `${category}`, inline: true },
                { name: 'Channels Created', value: createdChannels.length.toString(), inline: true },
                { name: 'Host Role', value: `${organizerRole}`, inline: true },
                { name: 'Player Role', value: `${playerRole}`, inline: true },
                { name: 'Admin Role', value: `${adminRole}`, inline: true }
            )
            .addFields({
                name: '📋 Channel Guide',
                value: createdChannels.map(c => `<#${c.id}>`).join('\n'),
                inline: false
            })
            .setColor('#57F287')
            .setFooter({ text: 'Use /tournament create to start your first tournament!' });
        
        await interaction.editReply({ embeds: [embed] });
        
    } catch (error) {
        console.error('Setup error:', error);
        await interaction.editReply({ 
            content: '❌ Setup failed: ' + error.message 
        });
    }
}

// ========== BUTTON INTERACTIONS ==========
client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;
    
    const customId = interaction.customId;
    
    if (customId.startsWith('register_')) {
        const tournamentId = customId.replace('register_', '');
        
        await interaction.reply({
            content: `To register a team for tournament \`${tournamentId}\`, use:\n\`/team register tournament_id:${tournamentId} name:YourTeamName\``,
            ephemeral: true
        });
    }
});

// ========== START BOT ==========
client.login(process.env.DISCORD_TOKEN).catch(error => {
    console.error('❌ Failed to login:', error);
});
