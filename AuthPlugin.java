package com.adhisiyaulagam.auth;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthPlugin extends JavaPlugin implements Listener {
    private final Set<UUID> authenticated = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<UUID, Location> loginLocations = new ConcurrentHashMap<>();
    private final Map<UUID, Long> joinTimes = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private File usersFile;
    private File premiumFile;
    private File namesFile;
    private YamlConfiguration users, premium, names;

    @Override public void onEnable() {
        saveDefaultConfig();
        usersFile = new File(getDataFolder(), "users.yml");
        premiumFile = new File(getDataFolder(), "premium.yml");
        namesFile = new File(getDataFolder(), "names.yml");
        users = YamlConfiguration.loadConfiguration(usersFile);
        premium = YamlConfiguration.loadConfiguration(premiumFile);
        names = YamlConfiguration.loadConfiguration(namesFile);
        Bukkit.getPluginManager().registerEvents(this, this);
        Objects.requireNonNull(getCommand("register")).setExecutor(this);
        Objects.requireNonNull(getCommand("login")).setExecutor(this);
        Objects.requireNonNull(getCommand("changepassword")).setExecutor(this);
        Objects.requireNonNull(getCommand("authadmin")).setExecutor(this);

        long timeout = Math.max(10, getConfig().getLong("settings.login-timeout-seconds", 60));
        Bukkit.getScheduler().runTaskTimer(this, () -> {
            long now = System.currentTimeMillis();
            for (Player p : Bukkit.getOnlinePlayers()) {
                if (!isAuthenticated(p) && !p.hasPermission("adhisiyaauth.bypass")) {
                    long joined = joinTimes.getOrDefault(p.getUniqueId(), now);
                    if (now - joined > timeout * 1000L) {
                        p.kickPlayer(color("&cAuthentication timed out. Please reconnect and log in."));
                    }
                }
            }
        }, 20L, 20L);
        getLogger().info("AdhisiyaUlagamMCAuth enabled.");
    }

    @Override public void onDisable() {
        save(users, usersFile); save(premium, premiumFile); save(names, namesFile);
    }

    private boolean isAuthenticated(Player p) {
        return authenticated.contains(p.getUniqueId()) || p.hasPermission("adhisiyaauth.bypass");
    }

    private String path(UUID id) { return id.toString(); }
    private String msg(String key) { return color(getConfig().getString("messages.prefix", "") + getConfig().getString("messages." + key, "&cMissing message: " + key)); }
    private String color(String s) { return ChatColor.translateAlternateColorCodes('&', s == null ? "" : s); }
    private void save(YamlConfiguration y, File f) {
        try { y.save(f); } catch (IOException e) { getLogger().severe("Could not save " + f.getName() + ": " + e.getMessage()); }
    }
    private void persistUsers() { save(users, usersFile); }
    private void persistPremium() { save(premium, premiumFile); }
    private void persistNames() { save(names, namesFile); }

    private String hashPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 210_000, 256);
        try {
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(key);
        } finally { spec.clearPassword(); }
    }
    private byte[] newSalt() { byte[] salt = new byte[16]; random.nextBytes(salt); return salt; }
    private boolean passwordMatches(UUID id, String password) {
        String saltText = users.getString(path(id) + ".salt");
        String hashText = users.getString(path(id) + ".hash");
        if (saltText == null || hashText == null) return false;
        try {
            byte[] salt = Base64.getDecoder().decode(saltText);
            byte[] expected = Base64.getDecoder().decode(hashText);
            byte[] actual = Base64.getDecoder().decode(hashPassword(password, salt));
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) { getLogger().warning("Password verification failed for UUID " + id); return false; }
    }
    private boolean registered(UUID id) { return users.contains(path(id) + ".hash"); }
    private int minLength() { return Math.max(8, getConfig().getInt("settings.password-min-length", 8)); }
    private int maxLength() { return Math.min(128, Math.max(minLength(), getConfig().getInt("settings.password-max-length", 64))); }
    private void finishLogin(Player p) {
        authenticated.add(p.getUniqueId());
        attempts.remove(p.getUniqueId());
        p.setDisplayName(displayName(p));
        p.sendMessage(msg(registered(p.getUniqueId()) ? "login-success" : "register-success"));
    }
    private String displayName(Player p) {
        String custom = names.getString(path(p.getUniqueId()) + ".display");
        String prefix = premium.getBoolean(path(p.getUniqueId())) ? color(getConfig().getString("messages.premium-label", "&6[PREMIUM] ")) : "";
        return prefix + (custom == null || custom.isBlank() ? p.getName() : color(custom));
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        authenticated.remove(p.getUniqueId());
        attempts.remove(p.getUniqueId());
        loginLocations.put(p.getUniqueId(), p.getLocation().clone());
        joinTimes.put(p.getUniqueId(), System.currentTimeMillis());
        p.setDisplayName(displayName(p));
        Bukkit.getScheduler().runTaskLater(this, () -> {
            if (!p.isOnline() || isAuthenticated(p)) return;
            p.sendMessage(msg(registered(p.getUniqueId()) ? "login-required" : "register-required"));
        }, 10L);
    }

    @EventHandler public void onQuit(PlayerQuitEvent e) {
        UUID id = e.getPlayer().getUniqueId();
        authenticated.remove(id); attempts.remove(id); loginLocations.remove(id); joinTimes.remove(id);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (isAuthenticated(e.getPlayer())) return;
        if (e.getFrom().getX() != e.getTo().getX() || e.getFrom().getY() != e.getTo().getY() || e.getFrom().getZ() != e.getTo().getZ()) {
            e.setTo(e.getFrom());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent e) {
        if (isAuthenticated(e.getPlayer())) return;
        String root = e.getMessage().split(" ")[0].replaceFirst("^/", "").toLowerCase(Locale.ROOT);
        List<String> allowed = getConfig().getStringList("settings.allow-unauthenticated-commands");
        if (!allowed.contains(root) && !root.equals("register") && !root.equals("reg") && !root.equals("login") && !root.equals("l")) {
            e.setCancelled(true);
            e.getPlayer().sendMessage(msg(registered(e.getPlayer().getUniqueId()) ? "login-required" : "register-required"));
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onChat(AsyncPlayerChatEvent e) {
        if (!isAuthenticated(e.getPlayer())) {
            e.setCancelled(true);
            e.getPlayer().sendMessage(msg(registered(e.getPlayer().getUniqueId()) ? "login-required" : "register-required"));
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPickup(PlayerAttemptPickupItemEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDamage(EntityDamageByEntityEvent e) {
        if (e.getDamager() instanceof Player p && !isAuthenticated(p)) e.setCancelled(true);
        if (e.getEntity() instanceof Player p && !isAuthenticated(p)) e.setCancelled(true);
    }

    @Override public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String cmd = command.getName().toLowerCase(Locale.ROOT);
        if (cmd.equals("register")) {
            if (!(sender instanceof Player p)) { sender.sendMessage("Players only."); return true; }
            UUID id = p.getUniqueId();
            if (registered(id)) { p.sendMessage(msg("already-registered")); return true; }
            if (args.length != 2) { p.sendMessage(color("&eUsage: /register <password> <confirmPassword>")); return true; }
            if (args[0].length() < minLength()) { p.sendMessage(msg("password-too-short").replace("%min%", String.valueOf(minLength()))); return true; }
            if (args[0].length() > maxLength()) { p.sendMessage(msg("password-too-long").replace("%max%", String.valueOf(maxLength()))); return true; }
            if (!args[0].equals(args[1])) { p.sendMessage(msg("password-mismatch")); return true; }
            try {
                byte[] salt = newSalt();
                users.set(path(id) + ".salt", Base64.getEncoder().encodeToString(salt));
                users.set(path(id) + ".hash", hashPassword(args[0], salt));
                users.set(path(id) + ".last-name", p.getName());
                persistUsers(); finishLogin(p);
            } catch (Exception ex) { p.sendMessage(color("&cCould not create account. Contact an administrator.")); getLogger().severe("Password hashing error: " + ex.getMessage()); }
            return true;
        }
        if (cmd.equals("login")) {
            if (!(sender instanceof Player p)) { sender.sendMessage("Players only."); return true; }
            if (isAuthenticated(p)) { p.sendMessage(msg("already-logged-in")); return true; }
            if (!registered(p.getUniqueId())) { p.sendMessage(msg("not-registered")); return true; }
            if (args.length != 1) { p.sendMessage(color("&eUsage: /login <password>")); return true; }
            if (!passwordMatches(p.getUniqueId(), args[0])) {
                int count = attempts.merge(p.getUniqueId(), 1, Integer::sum);
                int limit = Math.max(3, getConfig().getInt("settings.max-login-attempts", 5));
                if (count >= limit) { p.kickPlayer(msg("too-many-attempts")); }
                else p.sendMessage(msg("wrong-password") + color(" &7(" + count + "/" + limit + ")"));
                return true;
            }
            finishLogin(p); return true;
        }
        if (cmd.equals("changepassword")) {
            if (!(sender instanceof Player p)) { sender.sendMessage("Players only."); return true; }
            if (!isAuthenticated(p)) { p.sendMessage(msg("login-required")); return true; }
            if (args.length != 2) { p.sendMessage(color("&eUsage: /changepassword <oldPassword> <newPassword>")); return true; }
            if (!passwordMatches(p.getUniqueId(), args[0])) { p.sendMessage(msg("old-password-wrong")); return true; }
            if (args[1].length() < minLength() || args[1].length() > maxLength()) { p.sendMessage(color("&cNew password length must be " + minLength() + "-" + maxLength() + " characters.")); return true; }
            try {
                byte[] salt = newSalt();
                users.set(path(p.getUniqueId()) + ".salt", Base64.getEncoder().encodeToString(salt));
                users.set(path(p.getUniqueId()) + ".hash", hashPassword(args[1], salt));
                persistUsers(); p.sendMessage(msg("password-changed"));
            } catch (Exception ex) { p.sendMessage(color("&cCould not change password.")); }
            return true;
        }
        if (cmd.equals("authadmin")) {
            if (!sender.hasPermission("adhisiyaauth.admin")) { sender.sendMessage(msg("no-permission")); return true; }
            if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
                reloadConfig(); sender.sendMessage(color("&aConfig reloaded.")); return true;
            }
            if (args.length >= 3 && args[0].equalsIgnoreCase("premium")) {
                String name = args[2]; OfflinePlayer target = Bukkit.getOfflinePlayer(name); String key = target.getUniqueId().toString();
                if (args[1].equalsIgnoreCase("add")) { premium.set(key, true); persistPremium(); sender.sendMessage(msg("premium-added").replace("%player%", name)); }
                else if (args[1].equalsIgnoreCase("remove")) { premium.set(key, null); persistPremium(); sender.sendMessage(msg("premium-removed").replace("%player%", name)); }
                else sender.sendMessage(color("&e/authadmin premium <add|remove> <player>"));
                return true;
            }
            if (args.length >= 4 && args[0].equalsIgnoreCase("name") && args[1].equalsIgnoreCase("set")) {
                OfflinePlayer target = Bukkit.getOfflinePlayer(args[2]);
                String custom = String.join(" ", Arrays.copyOfRange(args, 3, args.length));
                if (custom.length() > 32) { sender.sendMessage(color("&cDisplay names are limited to 32 characters.")); return true; }
                names.set(target.getUniqueId() + ".display", custom); persistNames();
                Player online = target.getPlayer(); if (online != null) online.setDisplayName(displayName(online));
                sender.sendMessage(msg("display-name-set").replace("%player%", args[2])); return true;
            }
            if (args.length == 3 && args[0].equalsIgnoreCase("name") && args[1].equalsIgnoreCase("reset")) {
                OfflinePlayer target = Bukkit.getOfflinePlayer(args[2]); names.set(target.getUniqueId() + ".display", null); persistNames();
                Player online = target.getPlayer(); if (online != null) online.setDisplayName(displayName(online));
                sender.sendMessage(msg("display-name-reset").replace("%player%", args[2])); return true;
            }
            sender.sendMessage(color("&6AdhisiyaUlagam Auth admin commands:"));
            sender.sendMessage(color("&e/authadmin premium <add|remove> <player> &7- mark premium; no login bypass"));
            sender.sendMessage(color("&e/authadmin name set <player> <display name>"));
            sender.sendMessage(color("&e/authadmin name reset <player>"));
            sender.sendMessage(color("&e/authadmin reload"));
            return true;
        }
        return false;
    }
}
