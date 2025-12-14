# bot.py - FIXED FOR NEW SCHEMA
import string
import discord
from discord import app_commands, Interaction, Embed, Color, ButtonStyle, ui
from discord.ext import commands, tasks
import aiohttp
import os
from datetime import datetime, timedelta
import json
from typing import Optional, Dict, List
import asyncio
import uuid
import random
import re

# ========== CONFIGURATION ==========
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")  # NO DEFAULT VALUE - USE ENV VARIABLE
API_URL = os.getenv("API_URL", "https://compbot-lhuy.onrender.com")
WEBSITE_URL = os.getenv("WEBSITE_URL", "https://www.xotiicsplaza.us")

# ========== BOT SETUP ==========
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True

class TournamentBot(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )
        self.session = None
        self.server_stats_cache = {}
        
    async def setup_hook(self):
        self.session = aiohttp.ClientSession()
        print("✅ Tournament Bot is starting up...")
        
        # Start background tasks
        self.stats_update_task.start()
        
    async def close(self):
        if self.session:
            await self.session.close()
        await super().close()
    
    @tasks.loop(minutes=5)
    async def stats_update_task(self):
        """Update server statistics to backend"""
        for guild in self.guilds:
            try:
                async with self.session.post(f"{API_URL}/api/bot/server-stats", json={
                    "server_id": str(guild.id),
                    "server_name": guild.name,
                    "member_count": guild.member_count,
                    "icon_url": str(guild.icon.url) if guild.icon else None
                }) as response:
                    if response.status == 200:
                        print(f"✅ Updated stats for {guild.name}")
                    else:
                        print(f"❌ Failed to update stats for {guild.name}: {response.status}")
                        
                self.server_stats_cache[str(guild.id)] = {
                    "name": guild.name,
                    "members": guild.member_count,
                    "icon": str(guild.icon.url) if guild.icon else None
                }
            except Exception as e:
                print(f"Error updating server {guild.name}: {e}")

bot = TournamentBot()

# ========== API HELPER FUNCTIONS ==========
async def api_request(endpoint, method="GET", data=None, token=None):
    """Make API request to backend"""
    url = f"{API_URL}{endpoint}"
    headers = {
        'Content-Type': 'application/json',
    }
    
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    try:
        async with bot.session.request(method, url, json=data, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                error_text = await response.text()
                try:
                    error_json = json.loads(error_text)
                    error_detail = error_json.get('detail', error_text)
                    raise Exception(f"API Error {response.status}: {error_detail}")
                except:
                    raise Exception(f"API Error {response.status}: {error_text}")
    except Exception as e:
        raise Exception(f"Connection error: {str(e)}")

# ========== MODALS ==========
class TournamentCreateModal(ui.Modal, title="Create Tournament"):
    name = ui.TextInput(
        label="Tournament Name",
        placeholder="Summer Championship 2024",
        required=True,
        max_length=100
    )
    
    game = ui.TextInput(
        label="Game",
        placeholder="Valorant, CS2, League of Legends, etc.",
        required=True,
        max_length=50
    )
    
    max_teams = ui.TextInput(
        label="Max Teams (8, 16, 32, 64)",
        placeholder="16",
        required=True,
        default="16",
        max_length=2
    )
    
    max_players = ui.TextInput(
        label="Players Per Team (1-10)",
        placeholder="5",
        required=True,
        default="5",
        max_length=2
    )
    
    description = ui.TextInput(
        label="Description (Optional)",
        placeholder="Tournament rules, schedule, prize pool info, etc.",
        style=discord.TextStyle.paragraph,
        required=False,
        max_length=500
    )
    
    async def on_submit(self, interaction: Interaction):
        await interaction.response.defer(ephemeral=True)
        
        try:
            max_teams = int(self.max_teams.value)
            max_players = int(self.max_players.value)
            
            if max_teams not in [8, 16, 32, 64]:
                await interaction.followup.send("❌ Max teams must be 8, 16, 32, or 64", ephemeral=True)
                return
            
            if max_players < 1 or max_players > 10:
                await interaction.followup.send("❌ Players per team must be between 1 and 10", ephemeral=True)
                return
            
            tournament_pass = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            
            tournament_data = {
                "name": self.name.value,
                "game": self.game.value,
                "max_teams": max_teams,
                "max_players_per_team": max_players,
                "description": self.description.value if self.description.value else "",
                "tournament_pass": tournament_pass,
                "host_id": str(interaction.user.id),
                "created_by": interaction.user.name,
                "discord_server_id": str(interaction.guild.id) if interaction.guild else None
            }
            
            # Send to backend
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{API_URL}/api/tournaments/discord", 
                    json=tournament_data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('success'):
                            tournament_id = data.get('tournament_id', '')
                            final_pass = data.get('tournament_pass', tournament_pass)
                            
                            # FIXED: Use tournament_id from response
                            if not tournament_id:
                                tournament_id = str(uuid.uuid4())
                            
                            # 1. Send confirmation to channel
                            embed = discord.Embed(
                                title="✅ Tournament Created!",
                                description=f"**{self.name.value}** has been created!",
                                color=discord.Color.green(),
                                timestamp=interaction.created_at
                            )
                            
                            embed.add_field(name="Game", value=self.game.value, inline=True)
                            embed.add_field(name="Max Teams", value=str(max_teams), inline=True)
                            embed.add_field(name="Players/Team", value=str(max_players), inline=True)
                            
                            if self.description.value:
                                desc_preview = self.description.value[:150]
                                if len(self.description.value) > 150:
                                    desc_preview += "..."
                                embed.add_field(name="Description", value=desc_preview, inline=False)
                            
                            embed.add_field(
                                name="🌐 Manage on Website", 
                                value=f"[Click here]({WEBSITE_URL})\nCheck your DMs for the tournament pass!",
                                inline=False
                            )
                            
                            embed.set_footer(text="Tournament pass has been sent to your DMs")
                            
                            # Buttons for server
                            view = ui.View()
                            view.add_item(ui.Button(
                                label="🌐 Open Website",
                                style=ButtonStyle.link,
                                url=WEBSITE_URL
                            ))
                            
                            # FIXED: Always show register button with actual tournament_id
                            view.add_item(ui.Button(
                                label="👥 Register Team",
                                style=ButtonStyle.primary,
                                custom_id=f"register_{tournament_id}"
                            ))
                            
                            await interaction.followup.send(embed=embed, view=view)
                            
                            # 2. Send pass in DM ONLY
                            try:
                                dm_embed = discord.Embed(
                                    title="🔐 Your Tournament Pass",
                                    description=f"**⚠️ KEEP THIS CODE SECRET! ⚠️**\n\nThis pass is required to manage **{self.name.value}** on the website.",
                                    color=discord.Color.blue(),
                                    timestamp=interaction.created_at
                                )
                                
                                dm_embed.add_field(name="Tournament", value=self.name.value, inline=False)
                                dm_embed.add_field(name="Game", value=self.game.value, inline=True)
                                dm_embed.add_field(name="Format", value=f"{max_players}v{max_players}", inline=True)
                                dm_embed.add_field(name="Tournament ID", value=f"`{tournament_id}`", inline=False)
                                
                                # Pass code in DM only
                                dm_embed.add_field(
                                    name="🔑 Tournament Pass Code", 
                                    value=f"```{final_pass}```\n*Keep this secret - it gives full control*",
                                    inline=False
                                )
                                
                                # How to use instructions
                                dm_embed.add_field(
                                    name="📋 How to Use on Website",
                                    value=(
                                        f"1. Go to [XTourney Website]({WEBSITE_URL})\n"
                                        f"2. Login or create an account\n"
                                        f"3. Click **'Use Tournament Pass'** in the menu\n"
                                        f"4. Enter the pass code above\n"
                                        f"5. You'll get full management access!"
                                    ),
                                    inline=False
                                )
                                
                                # Security warning
                                dm_embed.add_field(
                                    name="⚠️ Security Notice",
                                    value="Do NOT share this pass with anyone you don't trust. Anyone with this code can manage your tournament.",
                                    inline=False
                                )
                                
                                dm_embed.set_footer(text=f"Created at | Keep this message safe!")
                                
                                # DM buttons for copying pass
                                dm_view = ui.View()
                                dm_view.add_item(ui.Button(
                                    label="📋 Copy Pass Code",
                                    style=ButtonStyle.primary,
                                    custom_id=f"copy_pass_{final_pass}"
                                ))
                                dm_view.add_item(ui.Button(
                                    label="🌐 Open Website",
                                    style=ButtonStyle.link,
                                    url=WEBSITE_URL
                                ))
                                
                                await interaction.user.send(embed=dm_embed, view=dm_view)
                                
                                # Send a separate follow-up message for backup
                                backup_msg = await interaction.user.send(
                                    f"**Tournament Pass Backup:**\n"
                                    f"```{final_pass}```\n"
                                    f"Tournament: {self.name.value}\n"
                                    f"Tournament ID: {tournament_id}\n"
                                    f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                                )
                                
                            except discord.Forbidden:
                                # User has DMs disabled
                                dm_error_embed = discord.Embed(
                                    title="⚠️ DMs Disabled - Pass Not Sent",
                                    description=f"Your tournament **{self.name.value}** was created, but I couldn't send you the pass via DMs.",
                                    color=discord.Color.orange()
                                )
                                
                                dm_error_embed.add_field(
                                    name="How to Get Your Pass",
                                    value=(
                                        f"1. Enable DMs from server members\n"
                                        f"2. Run the command: `/tournament_pass {tournament_id}`\n"
                                        f"3. Or contact an admin to retrieve your pass"
                                    ),
                                    inline=False
                                )
                                
                                dm_error_embed.add_field(
                                    name="Tournament ID",
                                    value=f"```{tournament_id}```",
                                    inline=False
                                )
                                
                                await interaction.followup.send(embed=dm_error_embed, ephemeral=True)
                            
                            # 3. Auto-announce in announcements channel
                            try:
                                announcement_channel = None
                                for channel in interaction.guild.text_channels:
                                    if "announcement" in channel.name.lower() or "tournament" in channel.name.lower():
                                        announcement_channel = channel
                                        break
                                
                                if not announcement_channel:
                                    for channel in interaction.guild.text_channels:
                                        if "general" in channel.name.lower() or "main" in channel.name.lower():
                                            announcement_channel = channel
                                            break
                                
                                if not announcement_channel:
                                    announcement_channel = interaction.channel
                                
                                # Create announcement WITH ACTUAL TOURNAMENT ID
                                announce_embed = discord.Embed(
                                    title="🏆 **NEW TOURNAMENT ANNOUNCEMENT!** 🏆",
                                    description=f"**{self.name.value}** is now open for registrations!",
                                    color=discord.Color.gold(),
                                    timestamp=interaction.created_at
                                )
                                
                                announce_embed.add_field(name="🎮 Game", value=self.game.value, inline=True)
                                announce_embed.add_field(name="👥 Format", value=f"{max_players}v{max_players}", inline=True)
                                announce_embed.add_field(name="📊 Max Teams", value=str(max_teams), inline=True)
                                
                                # FIXED: Use actual tournament_id
                                announce_embed.add_field(
                                    name="📝 HOW TO REGISTER", 
                                    value=f"**Command:** `/team_register {tournament_id}`\n"
                                          f"**Or click** the button below!\n"
                                          f"Make sure to @mention all team members!",
                                    inline=False
                                )
                                
                                if self.description.value:
                                    desc_text = self.description.value[:250]
                                    if len(self.description.value) > 250:
                                        desc_text += "..."
                                    announce_embed.add_field(name="📋 Description", value=desc_text, inline=False)
                                
                                announce_embed.set_footer(text=f"Hosted by {interaction.user.name}")
                                
                                announce_view = ui.View()
                                # FIXED: Use actual tournament_id for button
                                announce_view.add_item(ui.Button(
                                    label="👥 Register Team",
                                    style=ButtonStyle.primary,
                                    custom_id=f"register_{tournament_id}"
                                ))
                                
                                announce_view.add_item(ui.Button(
                                    label="🌐 View on Website",
                                    style=ButtonStyle.link,
                                    url=WEBSITE_URL
                                ))
                                
                                await announcement_channel.send(embed=announce_embed, view=announce_view)
                                
                            except Exception as e:
                                print(f"Announcement failed: {e}")
                                # Don't show error to user
                                
                        else:
                            await interaction.followup.send(
                                f"❌ Error: {data.get('detail', 'Unknown error')}",
                                ephemeral=True
                            )
                    else:
                        error_text = await response.text()
                        await interaction.followup.send(
                            f"❌ Backend Error ({response.status}): {error_text[:100]}",
                            ephemeral=True
                        )
                        
        except ValueError:
            await interaction.followup.send("❌ Please enter valid numbers for teams and players", ephemeral=True)
        except aiohttp.ClientError as e:
            await interaction.followup.send(f"❌ Connection error: {str(e)}", ephemeral=True)
        except Exception as e:
            print(f"Error creating tournament: {e}")
            await interaction.followup.send(f"❌ An error occurred: {str(e)}", ephemeral=True)

class TeamRegistrationModal(ui.Modal, title="Register Team"):
    def __init__(self, tournament_id: str, tournament_name: str):
        super().__init__()
        self.tournament_id = tournament_id
        self.tournament_name = tournament_name
        self.title = f"Register for: {tournament_name}"
    
    team_name = ui.TextInput(
        label="Team Name",
        placeholder="Enter your team name",
        required=True,
        max_length=50
    )
    
    team_tag = ui.TextInput(
        label="Team Tag (Optional)",
        placeholder="e.g., TSM, C9, TL",
        required=False,
        max_length=10
    )
    
    region = ui.TextInput(
        label="Region (NA, EU, ASIA, OCE, SA, GLOBAL)",
        placeholder="GLOBAL",
        required=True,
        max_length=20,
        default="GLOBAL"
    )
    
    members = ui.TextInput(
        label="Team Members (@mention them!)",
        placeholder="@player1 @player2 @player3 ...",
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=1000
    )
    
    async def on_submit(self, interaction: Interaction):
        await interaction.response.defer(ephemeral=True)
        
        # Extract mentions from the input
        member_mentions = []
        user_ids = []
        
        # Parse mentions from the input
        for mention in re.findall(r'<@!?(\d+)>', self.members.value):
            try:
                user = await interaction.guild.fetch_member(int(mention))
                member_mentions.append(user.mention)
                user_ids.append(str(user.id))
            except:
                member_mentions.append(f"<@{mention}>")
                user_ids.append(mention)
        
        # Also accept plain text names
        plain_names = [name.strip() for name in re.sub(r'<@!?\d+>', '', self.members.value).split(',') if name.strip()]
        member_mentions.extend(plain_names)
        
        if not member_mentions:
            await interaction.followup.send(
                "❌ Please @mention your players or provide their names.",
                ephemeral=True
            )
            return
        
        try:
            # Prepare team data for backend
            team_data = {
                "team_name": self.team_name.value,
                "tournament_id": self.tournament_id,
                "captain_id": str(interaction.user.id),
                "captain_name": interaction.user.name,
                "members": member_mentions,
                "region": self.region.value.upper(),
                "tag": self.team_tag.value if self.team_tag.value else None,
                "player_ids": user_ids
            }
            
            # Call backend API
            async with bot.session.post(f"{API_URL}/api/teams/register", json=team_data) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('success'):
                        team = data.get('team', {})
                        
                        embed = discord.Embed(
                            title="✅ Team Registered Successfully!",
                            description=f"**{self.team_name.value}** has been registered for **{self.tournament_name}**",
                            color=discord.Color.green()
                        )
                        
                        embed.add_field(name="Region", value=self.region.value.upper(), inline=True)
                        embed.add_field(name="Team Size", value=f"{len(member_mentions)} players", inline=True)
                        embed.add_field(name="Team ID", value=f"`{team.get('id', 'N/A')}`", inline=True)
                        
                        # Show tagged players
                        players_list = "\n".join([f"• {player}" for player in member_mentions[:5]])
                        if len(member_mentions) > 5:
                            players_list += f"\n... and {len(member_mentions) - 5} more"
                        
                        embed.add_field(name="Players", value=players_list, inline=False)
                        
                        # Add website link
                        embed.add_field(
                            name="🌐 View on Website", 
                            value=f"[Click here]({WEBSITE_URL})", 
                            inline=False
                        )
                        
                        await interaction.followup.send(embed=embed, ephemeral=True)
                        
                        # Announce in channel
                        public_embed = discord.Embed(
                            title="👥 New Team Registration",
                            description=f"**{self.team_name.value}** has registered for **{self.tournament_name}**!",
                            color=discord.Color.blue()
                        )
                        public_embed.add_field(name="Captain", value=interaction.user.mention, inline=True)
                        public_embed.add_field(name="Region", value=self.region.value.upper(), inline=True)
                        public_embed.add_field(name="Team Size", value=f"{len(member_mentions)} players", inline=True)
                        
                        await interaction.channel.send(embed=public_embed)
                        
                    else:
                        await interaction.followup.send(
                            f"❌ {data.get('detail', 'Registration failed')}",
                            ephemeral=True
                        )
                else:
                    error_text = await response.text()
                    await interaction.followup.send(
                        f"❌ Backend Error ({response.status}): {error_text[:100]}",
                        ephemeral=True
                    )
                
        except Exception as e:
            print(f"Error registering team: {e}")
            await interaction.followup.send(
                f"❌ Error: {str(e)}",
                ephemeral=True
            )

# ========== COMMANDS ==========
@bot.tree.command(name="setup", description="Setup tournament channels (Admin only)")
@app_commands.default_permissions(administrator=True)
async def setup(interaction: Interaction):
    """Setup tournament channels"""
    embed = Embed(
        title="✅ Setup Complete!",
        description="Tournament bot is ready to use!\n\n**Important:** Tournament creation requires the backend API to be running.",
        color=Color.green()
    )
    
    embed.add_field(
        name="📋 AVAILABLE COMMANDS",
        value="• `/tournament_create` - Create new tournament\n"
              "• `/tournament_list` - List tournaments\n"
              "• `/tournament_info <id>` - Tournament details\n"
              "• `/team_register <id>` - Register team\n"
              "• `/tournament_pass <id>` - Get management pass\n"
              "• `/host_panel <id>` - Host control panel\n"
              "• `/bot_stats` - Bot statistics",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="tournament_create", description="Create a new tournament")
async def tournament_create(interaction: Interaction):
    """Create a tournament"""
    modal = TournamentCreateModal()
    await interaction.response.send_modal(modal)

@bot.tree.command(name="tournament_list", description="List tournaments")
@app_commands.describe(status="Filter by status")
async def tournament_list(interaction: Interaction, status: str = None):
    """List tournaments"""
    await interaction.response.defer()
    
    try:
        response = await api_request('/api/tournaments')
        
        if not response.get('success') or not response.get('tournaments'):
            embed = Embed(
                title="📋 Tournaments",
                description="No tournaments found.",
                color=Color.blue()
            )
            await interaction.followup.send(embed=embed)
            return
        
        tournaments = response['tournaments']
        
        # Filter by status if provided
        if status:
            tournaments = [t for t in tournaments if t['status'] == status]
        
        if not tournaments:
            embed = Embed(
                title="📋 Tournaments",
                description=f"No tournaments found with status: {status}",
                color=Color.blue()
            )
            await interaction.followup.send(embed=embed)
            return
        
        embed = Embed(
            title=f"📋 Tournaments ({len(tournaments)})",
            description=f"Status: {status if status else 'All'}",
            color=Color.blue()
        )
        
        for tournament in tournaments[:5]:
            status_emoji = "🟢" if tournament['status'] == 'registration' else "🟡" if tournament['status'] == 'ongoing' else "🔴"
            embed.add_field(
                name=f"{status_emoji} {tournament['name']}",
                value=f"**Game:** {tournament['game']}\n"
                      f"**Teams:** {tournament.get('team_count', 0)}/{tournament['max_teams']}\n"
                      f"**Status:** {tournament['status'].upper()}\n"
                      f"**ID:** `{tournament['id']}`",
                inline=False
            )
        
        if len(tournaments) > 5:
            embed.set_footer(text=f"Showing 5 of {len(tournaments)} tournaments")
        
        view = ui.View()
        view.add_item(ui.Button(
            label="🌐 View All on Website",
            style=ButtonStyle.link,
            url=WEBSITE_URL
        ))
        
        await interaction.followup.send(embed=embed, view=view)
        
    except Exception as e:
        print(f"Error listing tournaments: {e}")
        embed = Embed(
            title="❌ Error",
            description="Failed to load tournaments. Please check if the backend API is running.",
            color=Color.red()
        )
        await interaction.followup.send(embed=embed)

@bot.tree.command(name="tournament_info", description="Get tournament details")
@app_commands.describe(tournament_id="Tournament ID")
async def tournament_info(interaction: Interaction, tournament_id: str):
    """Get tournament info"""
    await interaction.response.defer()
    
    try:
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Tournament not found')}"
            )
            return
        
        tournament = response['tournament']
        
        embed = Embed(
            title=f"🏆 {tournament['name']}",
            description=tournament.get('description', ''),
            color=Color.blue(),
            timestamp=datetime.fromisoformat(tournament['created_at'].replace('Z', '+00:00'))
        )
        
        embed.add_field(name="Game", value=tournament['game'], inline=True)
        embed.add_field(name="Status", value=tournament['status'].upper(), inline=True)
        embed.add_field(name="Teams", value=f"{tournament.get('team_count', 0)}/{tournament['max_teams']}", inline=True)
        embed.add_field(name="Format", value=f"{tournament.get('max_players_per_team', 5)}v{tournament.get('max_players_per_team', 5)}", inline=True)
        
        if tournament.get('created_by'):
            embed.add_field(name="Host", value=tournament['created_by'], inline=True)
        
        embed.add_field(name="Tournament ID", value=f"`{tournament['id']}`", inline=False)
        
        # Add teams if available
        if tournament.get('teams'):
            teams_text = ""
            for team in tournament['teams'][:5]:
                members = team.get('members', [])
                if isinstance(members, str):
                    try:
                        members = json.loads(members)
                    except:
                        members = []
                
                teams_text += f"• **{team['name']}** ({len(members)} players)\n"
            
            if len(tournament['teams']) > 5:
                teams_text += f"\n... and {len(tournament['teams']) - 5} more teams"
            
            embed.add_field(name="Registered Teams", value=teams_text or "No teams", inline=False)
        
        # Add website link
        embed.add_field(
            name="🌐 Website", 
            value=f"[View on Website]({WEBSITE_URL})", 
            inline=False
        )
        
        view = ui.View()
        view.add_item(ui.Button(
            label="👥 Register Team",
            style=ButtonStyle.primary,
            custom_id=f"register_{tournament_id}"
        ))
        view.add_item(ui.Button(
            label="🌐 View on Website",
            style=ButtonStyle.link,
            url=WEBSITE_URL
        ))
        
        await interaction.followup.send(embed=embed, view=view)
        
    except Exception as e:
        print(f"Error getting tournament info: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}"
        )

@bot.tree.command(name="team_register", description="Register a team for tournament")
@app_commands.describe(tournament_id="Tournament ID")
async def team_register(interaction: Interaction, tournament_id: str):
    """Register a team"""
    try:
        # Get tournament info first
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.response.send_message(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        
        # Check if tournament is accepting registrations
        if tournament['status'] != 'registration':
            await interaction.response.send_message(
                f"❌ Tournament is not accepting registrations (status: {tournament['status']})",
                ephemeral=True
            )
            return
        
        modal = TeamRegistrationModal(tournament_id, tournament['name'])
        await interaction.response.send_modal(modal)
        
    except Exception as e:
        print(f"Error in team register: {e}")
        await interaction.response.send_message(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

@bot.tree.command(name="tournament_pass", description="Get tournament pass for website management")
@app_commands.describe(tournament_id="Tournament ID")
async def tournament_pass(interaction: Interaction, tournament_id: str):
    """Get tournament pass for website management"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get tournament from backend
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        
        # Check if tournament has a pass
        if not tournament.get('tournament_pass'):
            await interaction.followup.send(
                "❌ This tournament doesn't have a pass code.",
                ephemeral=True
            )
            return
        
        embed = Embed(
            title="🔑 Tournament Management Pass",
            description=f"Use this pass to manage **{tournament['name']}** on the website",
            color=Color.gold()
        )
        
        embed.add_field(name="Tournament", value=tournament['name'], inline=False)
        embed.add_field(name="Game", value=tournament['game'], inline=True)
        embed.add_field(name="Status", value=tournament['status'].upper(), inline=True)
        
        embed.add_field(
            name="🔐 Tournament Pass",
            value=f"```{tournament['tournament_pass']}```",
            inline=False
        )
        
        embed.add_field(
            name="📋 How to Use on Website",
            value="1. Go to the website and login/create account\n"
                  "2. Click 'Tournament Pass' in the menu\n"
                  "3. Enter the pass code above\n"
                  "4. You'll get full management access to this tournament\n"
                  "5. You can generate brackets, update matches, and more!",
            inline=False
        )
        
        embed.add_field(
            name="🌐 Website Link",
            value=f"[Click here to go to website]({WEBSITE_URL})",
            inline=False
        )
        
        view = ui.View()
        view.add_item(ui.Button(
            label="📋 Copy Pass Code",
            style=ButtonStyle.primary,
            custom_id=f"copy_pass_{tournament['tournament_pass']}"
        ))
        view.add_item(ui.Button(
            label="🌐 Open Website",
            style=ButtonStyle.link,
            url=WEBSITE_URL
        ))
        
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        print(f"Error getting tournament pass: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

@bot.tree.command(name="host_panel", description="Host control panel for tournament management")
@app_commands.describe(tournament_id="Tournament ID")
async def host_panel(interaction: Interaction, tournament_id: str):
    """Host control panel with website integration"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get tournament from backend
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        
        embed = Embed(
            title=f"🎮 Host Control Panel - {tournament['name']}",
            description=f"Manage your tournament from Discord or Website",
            color=Color.blue()
        )
        
        embed.add_field(name="Game", value=tournament['game'], inline=True)
        embed.add_field(name="Status", value=tournament['status'].upper(), inline=True)
        embed.add_field(name="Teams", value=f"{tournament.get('team_count', 0)}/{tournament['max_teams']}", inline=True)
        
        if tournament.get('tournament_pass'):
            embed.add_field(
                name="🔐 Website Access",
                value=f"Pass: `{tournament['tournament_pass']}`\nUse this on the website for full control",
                inline=False
            )
        
        # Add action buttons
        view = ui.View(timeout=300)
        
        # Get tournament pass button
        view.add_item(ui.Button(
            label="🔑 Get Tournament Pass",
            style=ButtonStyle.primary,
            custom_id=f"get_pass_{tournament_id}"
        ))
        
        # View teams button
        view.add_item(ui.Button(
            label="👥 View Teams",
            style=ButtonStyle.secondary,
            custom_id=f"view_teams_{tournament_id}"
        ))
        
        # Generate bracket button
        if tournament['status'] == 'registration' and tournament.get('team_count', 0) >= 2:
            view.add_item(ui.Button(
                label="🚀 Generate Bracket",
                style=ButtonStyle.success,
                custom_id=f"generate_bracket_{tournament_id}"
            ))
        
        # Website button
        view.add_item(ui.Button(
            label="🌐 Manage on Website",
            style=ButtonStyle.link,
            url=f"{WEBSITE_URL}"
        ))
        
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        print(f"Error in host panel: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

@bot.tree.command(name="bot_stats", description="Show bot and server statistics")
async def bot_stats(interaction: Interaction):
    """Show bot stats"""
    await interaction.response.defer()
    
    try:
        # Get website stats
        response = await api_request('/api/stats')
        
        if not response.get('success'):
            stats = {
                'active_tournaments': 0,
                'total_teams': 0,
                'connected_servers': len(bot.guilds),
                'live_matches': 0
            }
        else:
            stats = response['stats']
        
        # Get server stats
        total_members = sum(guild.member_count for guild in bot.guilds)
        
        embed = Embed(
            title="🌐 XTourney Global Statistics",
            color=Color.purple(),
            timestamp=datetime.utcnow()
        )
        
        embed.add_field(name="🏢 Servers", value=len(bot.guilds), inline=True)
        embed.add_field(name="👥 Total Members", value=f"{total_members:,}", inline=True)
        embed.add_field(name="🏆 Active Tournaments", value=stats['active_tournaments'], inline=True)
        embed.add_field(name="👥 Total Teams", value=stats['total_teams'], inline=True)
        embed.add_field(name="🎮 Live Matches", value=stats['live_matches'], inline=True)
        embed.add_field(name="🔗 Connected Servers", value=stats['connected_servers'], inline=True)
        
        # Add top servers
        top_servers = sorted(bot.guilds, key=lambda g: g.member_count, reverse=True)[:3]
        servers_text = "\n".join([f"• {g.name} ({g.member_count} members)" for g in top_servers])
        embed.add_field(name="🏆 Top Servers", value=servers_text, inline=False)
        
        view = ui.View()
        view.add_item(ui.Button(
            label="🌐 Visit Website",
            style=ButtonStyle.link,
            url=WEBSITE_URL
        ))
        
        await interaction.followup.send(embed=embed, view=view)
        
    except Exception as e:
        print(f"Error getting bot stats: {e}")
        embed = Embed(
            title="📊 Bot Statistics",
            description=f"Connected to {len(bot.guilds)} servers with {sum(g.member_count for g in bot.guilds):,} total members",
            color=Color.blue()
        )
        await interaction.followup.send(embed=embed)

@bot.tree.command(name="help", description="Show all available commands")
async def help_command(interaction: Interaction):
    """Show help"""
    embed = Embed(
        title="🎮 XTourney Bot Commands",
        description="Complete tournament management system with website integration",
        color=Color.blue()
    )
    
    embed.add_field(
        name="🏆 Tournament Commands",
        value="• `/tournament_create` - Create new tournament\n"
              "• `/tournament_list [status]` - List tournaments\n"
              "• `/tournament_info <id>` - Tournament details\n"
              "• `/team_register <id>` - Register team\n"
              "• `/tournament_pass <id>` - Get management pass\n"
              "• `/host_panel <id>` - Host control panel",
        inline=False
    )
    
    embed.add_field(
        name="📊 Statistics & Info",
        value="• `/bot_stats` - Global bot statistics\n"
              "• `/help` - This help menu",
        inline=False
    )
    
    embed.add_field(
        name="⚙️ Setup (Admin)",
        value="• `/setup` - Configure bot",
        inline=False
    )
    
    embed.add_field(
        name="🌐 Website Integration",
        value=f"• Use tournament pass to manage on website\n• [Visit Website]({WEBSITE_URL})",
        inline=False
    )
    
    embed.add_field(
        name="📋 How to Get Started",
        value="1. Use `/tournament_create` to make a tournament\n"
              "2. Get the tournament pass with `/tournament_pass`\n"
              "3. Use the pass on the website for full management\n"
              "4. Teams register with `/team_register`",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed)

# ========== BUTTON HANDLERS ==========
@bot.event
async def on_interaction(interaction: Interaction):
    if interaction.type != discord.InteractionType.component:
        return
    
    custom_id = interaction.data.get('custom_id', '')
    
    if custom_id.startswith('get_pass_'):
        tournament_id = custom_id.replace('get_pass_', '')
        await handle_get_pass(interaction, tournament_id)
    
    elif custom_id.startswith('copy_pass_'):
        pass_code = custom_id.replace('copy_pass_', '')
        await handle_copy_pass(interaction, pass_code)
    
    elif custom_id.startswith('register_'):
        tournament_id = custom_id.replace('register_', '')
        await handle_button_register(interaction, tournament_id)
    
    elif custom_id.startswith('announce_'):
        tournament_id = custom_id.replace('announce_', '')
        await handle_announce_tournament(interaction, tournament_id)
    
    elif custom_id.startswith('view_teams_'):
        tournament_id = custom_id.replace('view_teams_', '')
        await handle_view_teams(interaction, tournament_id)
    
    elif custom_id.startswith('generate_bracket_'):
        tournament_id = custom_id.replace('generate_bracket_', '')
        await handle_generate_bracket(interaction, tournament_id)
    
    elif custom_id.startswith('start_tournament_'):
        tournament_id = custom_id.replace('start_tournament_', '')
        await handle_start_tournament(interaction, tournament_id)

async def handle_get_pass(interaction: Interaction, tournament_id: str):
    """Handle get tournament pass button"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get tournament from backend
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        
        if not tournament.get('tournament_pass'):
            await interaction.followup.send(
                "❌ This tournament doesn't have a pass code",
                ephemeral=True
            )
            return
        
        embed = Embed(
            title="🔑 Tournament Pass",
            description=f"**Tournament:** {tournament['name']}",
            color=Color.gold()
        )
        
        embed.add_field(
            name="Pass Code",
            value=f"```{tournament['tournament_pass']}```",
            inline=False
        )
        
        embed.add_field(
            name="How to Use on Website",
            value="1. Login to your account on the website\n"
                  "2. Click 'Tournament Pass' in the menu\n"
                  "3. Enter the code above\n"
                  "4. You'll get full management access to this tournament",
            inline=False
        )
        
        embed.add_field(
            name="Website Link",
            value=f"[Click here to go to website]({WEBSITE_URL})",
            inline=False
        )
        
        view = ui.View()
        view.add_item(ui.Button(
            label="📋 Copy Pass Code",
            style=ButtonStyle.primary,
            custom_id=f"copy_pass_{tournament['tournament_pass']}"
        ))
        
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        print(f"Error handling get pass: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

async def handle_copy_pass(interaction: Interaction, pass_code: str):
    """Handle copy pass code button"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await interaction.followup.send(
            f"✅ Pass code `{pass_code}` copied to clipboard!\n\n"
            f"**Now go to the website and:**\n"
            f"1. Login/create account\n"
            f"2. Click 'Tournament Pass'\n"
            f"3. Paste the code\n"
            f"4. Get full tournament management!",
            ephemeral=True
        )
    except Exception as e:
        await interaction.followup.send(
            "❌ Failed to copy pass code",
            ephemeral=True
        )

async def handle_button_register(interaction: Interaction, tournament_id: str):
    """Handle team registration from button"""
    try:
        # Get tournament info first
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.response.send_message(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        
        # Check if tournament is accepting registrations
        if tournament['status'] != 'registration':
            await interaction.response.send_message(
                f"❌ Tournament is not accepting registrations (status: {tournament['status']})",
                ephemeral=True
            )
            return
        
        modal = TeamRegistrationModal(tournament_id, tournament['name'])
        await interaction.response.send_modal(modal)
        
    except Exception as e:
        print(f"Error handling button register: {e}")
        await interaction.response.send_message(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

async def handle_view_teams(interaction: Interaction, tournament_id: str):
    """Handle view teams button"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        response = await api_request(f'/api/tournaments/{tournament_id}')
        
        if not response.get('success'):
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Tournament not found')}",
                ephemeral=True
            )
            return
        
        tournament = response['tournament']
        teams = tournament.get('teams', [])
        
        if not teams:
            embed = Embed(
                title="👥 Teams",
                description="No teams registered yet",
                color=Color.blue()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)
            return
        
        embed = Embed(
            title=f"👥 Teams in {tournament['name']}",
            description=f"Total: {len(teams)} teams",
            color=Color.blue()
        )
        
        for team in teams[:10]:
            members = team.get('members', [])
            if isinstance(members, str):
                try:
                    members = json.loads(members)
                except:
                    members = []
            
            members_text = "\n".join([f"• {member}" for member in members[:3]])
            if len(members) > 3:
                members_text += f"\n... and {len(members) - 3} more"
            
            embed.add_field(
                name=f"{team['name']}",
                value=f"**Captain:** {team.get('captain_name', 'Unknown')}\n"
                      f"**Region:** {team.get('region', 'GLOBAL')}\n"
                      f"**Players:** {len(members)}\n{members_text}",
                inline=False
            )
        
        if len(teams) > 10:
            embed.set_footer(text=f"Showing 10 of {len(teams)} teams")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        print(f"Error showing teams: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

async def handle_generate_bracket(interaction: Interaction, tournament_id: str):
    """Handle generate bracket button"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Call backend to generate bracket
        response = await api_request(f'/api/tournament-pass/{tournament_id}/generate-bracket', 'POST')
        
        if response.get('success'):
            embed = Embed(
                title="✅ Bracket Generated!",
                description=f"The tournament bracket has been generated successfully",
                color=Color.green()
            )
            
            embed.add_field(
                name="Next Steps",
                value="1. Use the tournament pass to manage brackets on the website\n"
                      "2. Update match results as games are played\n"
                      "3. Advance rounds when ready",
                inline=False
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(
                f"❌ {response.get('detail', 'Failed to generate bracket')}",
                ephemeral=True
            )
            
    except Exception as e:
        print(f"Error generating bracket: {e}")
        await interaction.followup.send(
            f"❌ Error: {str(e)}",
            ephemeral=True
        )

# ========== BOT EVENTS ==========
@bot.event
async def on_ready():
    print(f'✅ Logged in as {bot.user} (ID: {bot.user.id})')
    print(f'🌐 Connected to {len(bot.guilds)} servers')
    
    # Update all servers in database
    for guild in bot.guilds:
        try:
            async with bot.session.post(f"{API_URL}/api/bot/server-stats", json={
                "server_id": str(guild.id),
                "server_name": guild.name,
                "member_count": guild.member_count,
                "icon_url": str(guild.icon.url) if guild.icon else None
            }):
                pass
        except:
            pass
    
    # Sync commands
    try:
        synced = await bot.tree.sync()
        print(f'📝 Synced {len(synced)} commands')
    except Exception as e:
        print(f'❌ Error syncing commands: {e}')
    
    # Print global stats
    total_members = sum(guild.member_count for guild in bot.guilds)
    print(f'📊 Global Stats: {len(bot.guilds)} servers, {total_members:,} total members')

@bot.event
async def on_guild_join(guild: discord.Guild):
    print(f'📥 Joined server: {guild.name} ({guild.id})')
    
    # Send welcome message
    for channel in guild.text_channels:
        if channel.permissions_for(guild.me).send_messages:
            embed = Embed(
                title="🎮 XTourney Tournament Bot",
                description="Thank you for adding XTourney to your server!",
                color=Color.blue()
            )
            
            embed.add_field(
                name="Get Started",
                value="1. Use `/tournament_create` to create tournaments\n"
                      "2. Use `/team_register` for teams to register\n"
                      "3. Use `/tournament_pass` to get website management access\n"
                      "4. Use `/help` for all commands",
                inline=False
            )
            
            embed.add_field(
                name="Website Integration",
                value=f"• Manage tournaments on [the website]({WEBSITE_URL})\n"
                      "• Use tournament pass for full control\n"
                      "• Real-time bracket updates",
                inline=False
            )
            
            await channel.send(embed=embed)
            break

@bot.event
async def on_guild_remove(guild: discord.Guild):
    print(f'📤 Left server: {guild.name} ({guild.id})')

# ========== RUN BOT ==========
if __name__ == "__main__":
    print("🚀 Starting XTourney Bot...")
    print(f"🌐 Website: {WEBSITE_URL}")
    print(f"🔗 API: {API_URL}")
    
    if not DISCORD_TOKEN:
        print("❌ ERROR: DISCORD_TOKEN environment variable is not set!")
        exit(1)
    
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        print(f"❌ ERROR: {e}")

