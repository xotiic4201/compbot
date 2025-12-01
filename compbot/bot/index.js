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

const API_URL = process.env.API_URL || "http://localhost:8000";

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
            .addStringOption(opt => opt.setName('date').setDescription('Start date (MM/DD HH:MM)').setRequired(true))
            .addIntegerOption(opt => opt.setName('teams').setDescription('Max teams').setRequired(false)))
        .addSubcommand(sub => sub
            .setName('announce')
            .setDescription('Announce tournament in configured channel')
            .addStringOption(opt => opt.setName('id').setDescription('Tournament ID').setRequired(true))),
    
    // MATCH VERIFICATION
    new SlashCommandBuilder()
        .setName('match')
        .setDescription('Match results')
        .addSubcommand(sub => sub
            .setName('report')
            .setDescription('Report match result with proof')
            .addStringOption(opt => opt.setName('match_id').setDescription('Match ID').setRequired(true))
            .addStringOption(opt => opt.setName('score').setDescription('Score (e.g., 2-1)').setRequired(true))
            .addAttachmentOption(opt => opt.setName('proof').setDescription('Screenshot proof').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('verify')
            .setDescription('Verify match result (hosts only)')
            .addStringOption(opt => opt.setName('verification_id').setDescription('Verification ID').setRequired(true))
            .addStringOption(opt => opt.setName('decision').setDescription('Accept or reject').setRequired(true)
                .addChoices({ name: 'Accept', value: 'accept' }, { name: 'Reject', value: 'reject' }))),
    
    // QUICK SETUP
    new SlashCommandBuilder()
        .setName('setup')
        .setDescription('Quick server setup')
];

// ========== REGISTER COMMANDS ==========
const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
(async () => {
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
            { body: commands }
        );
        console.log('Commands registered!');
    } catch (error) {
        console.error('Error:', error);
    }
})();

// ========== BOT READY ==========
client.once('ready', () => {
    console.log(`✅ ${client.user.tag} is ready!`);
    client.user.setActivity('/setup | Tournaments');
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
            case 'match':
                await handleMatch(interaction, options);
                break;
            case 'setup':
                await handleSetup(interaction);
                break;
        }
    } catch (error) {
        console.error(error);
        await interaction.reply({ content: '❌ Error: ' + error.message, ephemeral: true });
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
            await interaction.editReply({ content: '❌ Failed to set channel: ' + error.message });
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
            
            if (channels.length === 0) {
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
            await interaction.reply({ content: '❌ Error fetching channels', ephemeral: true });
        }
    }
    
    else if (subcommand === 'setup-help') {
        const embed = new EmbedBuilder()
            .setTitle('🛠️ Channel Setup Guide')
            .setDescription('You need to configure these channels for full functionality:')
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
        
        const tournamentData = {
            name: options.getString('name'),
            game: options.getString('game'),
            max_teams: options.getInteger('teams') || 16,
            start_date: options.getString('date'),
            discord_server_id: interaction.guildId,
            created_by: interaction.user.id
        };
        
        try {
            const response = await axios.post(`${API_URL}/tournaments/create`, tournamentData);
            const tournament = response.data.tournament;
            
            // Create embed
            const embed = new EmbedBuilder()
                .setTitle(`🎮 ${tournament.name}`)
                .setDescription(`New ${tournament.game} tournament created!`)
                .addFields(
                    { name: 'ID', value: `\`${tournament.id}\``, inline: true },
                    { name: 'Teams', value: `${tournament.max_teams} max`, inline: true },
                    { name: 'Status', value: '🟢 REGISTRATION OPEN', inline: true },
                    { name: 'Starts', value: tournament.start_date, inline: true },
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
                    await announceChannelObj.send({ embeds: [embed] });
                    await interaction.editReply({ 
                        content: `✅ Tournament created and announced in <#${announceChannel.discord_channel_id}>!` 
                    });
                } else {
                    await interaction.editReply({ 
                        content: '✅ Tournament created! (No announcements channel set)', 
                        embeds: [embed] 
                    });
                }
            } catch (channelError) {
                await interaction.editReply({ 
                    content: '✅ Tournament created!', 
                    embeds: [embed] 
                });
            }
            
        } catch (error) {
            await interaction.editReply({ content: '❌ Failed to create tournament: ' + error.message });
        }
    }
    
    else if (subcommand === 'announce') {
        const tournamentId = options.getString('id');
        
        try {
            const response = await axios.get(`${API_URL}/tournaments/${tournamentId}`);
            const tournament = response.data;
            
            const embed = new EmbedBuilder()
                .setTitle(`📢 ${tournament.name} - REGISTER NOW!`)
                .setDescription(`Join our ${tournament.game} tournament!`)
                .addFields(
                    { name: 'Game', value: tournament.game, inline: true },
                    { name: 'Teams', value: `${tournament.current_teams}/${tournament.max_teams}`, inline: true },
                    { name: 'Start', value: new Date(tournament.start_date).toLocaleString(), inline: true }
                )
                .setColor('#F1C40F')
                .setFooter({ text: `Tournament ID: ${tournament.id}` });
            
            // Get announcements channel
            const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
            const channels = channelsRes.data;
            const announceChannel = channels.find(c => c.channel_type === 'announcements');
            
            if (announceChannel) {
                const channel = await interaction.guild.channels.fetch(announceChannel.discord_channel_id);
                await channel.send({ embeds: [embed] });
                await interaction.reply({ 
                    content: `✅ Announcement sent to <#${announceChannel.discord_channel_id}>!`, 
                    ephemeral: true 
                });
            } else {
                await interaction.reply({ 
                    content: '❌ No announcements channel set! Use `/channels set` first.', 
                    ephemeral: true 
                });
            }
            
        } catch (error) {
            await interaction.reply({ content: '❌ Error: ' + error.message, ephemeral: true });
        }
    }
}

// ========== MATCH HANDLER ==========
async function handleMatch(interaction, options) {
    const subcommand = options.getSubcommand();
    
    if (subcommand === 'report') {
        const matchId = options.getString('match_id');
        const score = options.getString('score');
        const proof = options.getAttachment('proof');
        
        // Validate proof
        if (!proof.contentType.startsWith('image/')) {
            await interaction.reply({ content: '❌ Proof must be an image!', ephemeral: true });
            return;
        }
        
        await interaction.deferReply({ ephemeral: true });
        
        try {
            const response = await axios.post(`${API_URL}/matches/report`, {
                match_id: matchId,
                team_id: 'temp-team-id', // You'd get this from database
                proof_image_url: proof.url,
                score: score,
                submitted_by: interaction.user.id
            });
            
            const verification = response.data.verification;
            
            // Send to verifications channel if configured
            try {
                const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
                const channels = channelsRes.data;
                const verifyChannel = channels.find(c => c.channel_type === 'verifications');
                
                if (verifyChannel) {
                    const verifyEmbed = new EmbedBuilder()
                        .setTitle('📋 Match Result Submitted')
                        .setDescription(`Verification needed for match \`${matchId}\``)
                        .addFields(
                            { name: 'Submitted by', value: `<@${interaction.user.id}>`, inline: true },
                            { name: 'Score', value: score, inline: true },
                            { name: 'Verification ID', value: `\`${verification.id}\``, inline: false }
                        )
                        .setImage(proof.url)
                        .setColor('#F1C40F')
                        .setTimestamp();
                    
                    const verifyChannelObj = await interaction.guild.channels.fetch(verifyChannel.discord_channel_id);
                    await verifyChannelObj.send({ 
                        content: '**Match verification needed!**',
                        embeds: [verifyEmbed] 
                    });
                }
            } catch (channelError) {
                // Channel not configured, continue
            }
            
            await interaction.editReply({ 
                content: `✅ Match result submitted! Verification ID: \`${verification.id}\`` 
            });
            
        } catch (error) {
            await interaction.editReply({ content: '❌ Failed to submit: ' + error.message });
        }
    }
    
    else if (subcommand === 'verify') {
        const verificationId = options.getString('verification_id');
        const decision = options.getString('decision');
        
        await interaction.deferReply();
        
        try {
            const response = await axios.post(`${API_URL}/matches/verify/${verificationId}`, null, {
                params: { decision, reviewed_by: interaction.user.id }
            });
            
            const verification = response.data.verification;
            
            // Send result to brackets channel
            try {
                const channelsRes = await axios.get(`${API_URL}/channels/${interaction.guildId}`);
                const channels = channelsRes.data;
                const bracketsChannel = channels.find(c => c.channel_type === 'brackets');
                
                if (bracketsChannel) {
                    const resultEmbed = new EmbedBuilder()
                        .setTitle(decision === 'accept' ? '✅ Match Result Accepted' : '❌ Match Result Rejected')
                        .setDescription(`Match verification \`${verificationId}\``)
                        .addFields(
                            { name: 'Decision', value: decision.toUpperCase(), inline: true },
                            { name: 'Reviewed by', value: `<@${interaction.user.id}>`, inline: true },
                            { name: 'Score', value: verification.score || 'N/A', inline: true }
                        )
                        .setColor(decision === 'accept' ? '#57F287' : '#ED4245')
                        .setTimestamp();
                    
                    const bracketsChannelObj = await interaction.guild.channels.fetch(bracketsChannel.discord_channel_id);
                    await bracketsChannelObj.send({ embeds: [resultEmbed] });
                }
            } catch (channelError) {
                // Continue
            }
            
            await interaction.editReply({ 
                content: `✅ Match ${decision}ed successfully!` 
            });
            
        } catch (error) {
            await interaction.editReply({ content: '❌ Verification failed: ' + error.message });
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
            name: '🎮 TOURNAMENTS',
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
        
        // Create all channel types
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
        const organizerRole = await interaction.guild.roles.create({
            name: 'Tournament Organizer',
            color: 'Blue',
            mentionable: true
        });
        
        const playerRole = await interaction.guild.roles.create({
            name: 'Tournament Player',
            color: 'Green'
        });
        
        const embed = new EmbedBuilder()
            .setTitle('✅ Setup Complete!')
            .setDescription('Tournament system has been set up successfully!')
            .addFields(
                { name: 'Category', value: `${category}`, inline: true },
                { name: 'Channels Created', value: createdChannels.length.toString(), inline: true },
                { name: 'Organizer Role', value: `${organizerRole}`, inline: true },
                { name: 'Player Role', value: `${playerRole}`, inline: true }
            )
            .addFields({
                name: '📋 Channel Guide',
                value: createdChannels.map(c => `<#${c.id}>`).join(' • '),
                inline: false
            })
            .setColor('#57F287')
            .setFooter({ text: 'Use /tournament create to start your first tournament!' });
        
        await interaction.editReply({ embeds: [embed] });
        
    } catch (error) {
        await interaction.editReply({ content: '❌ Setup failed: ' + error.message });
    }
}

// ========== START BOT ==========
client.login(process.env.DISCORD_TOKEN);