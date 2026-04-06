using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ParentalControl
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--service")
            {
                ServiceBase.Run(new ParentalControlService());
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ManagerForm());
        }
    }

    // ============================================
    // AUDIT LOGGER - Layer 7: Windows Event Log
    // ============================================
    public static class AuditLogger
    {
        private const string SourceName = "ParentalControl";
        private const string LogName    = "Application";

        static AuditLogger()
        {
            try
            {
                if (!EventLog.SourceExists(SourceName))
                    EventLog.CreateEventSource(SourceName, LogName);
            }
            catch { /* Requires admin; silently skip if already exists */ }
        }

        public static void Log(string message, EventLogEntryType type = EventLogEntryType.Information)
        {
            try
            {
                EventLog.WriteEntry(SourceName, message, type, 1001);
            }
            catch { /* Never crash because of logging */ }
        }

        public static void LogBlock(string domain, string reason)
            => Log($"BLOCKED: {domain} | Reason: {reason}", EventLogEntryType.Warning);

        public static void LogBypassAttempt(string detail)
            => Log($"BYPASS ATTEMPT: {detail}", EventLogEntryType.Error);
    }

    // ============================================
    // DNS ENFORCER - Layer 1 upgrade
    // Locks DNS to Cloudflare for Families (1.1.1.3)
    // ============================================
    public static class DnsEnforcer
    {
        // Cloudflare for Families — blocks malware + adult content
        private static readonly string[] SafeDnsServers = { "1.1.1.3", "1.0.0.3" };

        public static void EnforceDns()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    SetDnsViaRegistry(nic.Id);
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"DNS enforcement error: {ex.Message}", EventLogEntryType.Error);
            }
        }

        private static void SetDnsViaRegistry(string nicId)
        {
            // IPv4
            var keyPath = $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{nicId}";
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
            if (key == null) return;

            var current = key.GetValue("NameServer") as string ?? "";
            var desired = string.Join(",", SafeDnsServers);

            if (current != desired)
            {
                key.SetValue("NameServer", desired);
                AuditLogger.Log($"DNS locked to Cloudflare for Families on adapter {nicId}");
            }
        }

        public static bool IsDnsEnforced()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var props = nic.GetIPProperties();
                    foreach (var dns in props.DnsAddresses)
                    {
                        if (SafeDnsServers.Contains(dns.ToString())) return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }

    // ============================================
    // VPN / BYPASS PROCESS BLOCKER - Layer 5
    // ============================================
    public static class ProcessBlocker
    {
        private static readonly HashSet<string> BlockedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Browsers that bypass filters
            "brave", "brave browser",
            "tor", "torbrowser", "firefox-esr",

            // VPN clients
            "protonvpn", "nordvpn", "expressvpn", "surfshark",
            "windscribe", "mullvadvpn", "privatevpn", "ipvanish",
            "cyberghost", "purevpn", "hotspotshield", "tunnelbear",
            "openvpn", "openvpn-gui",

            // Proxy tools
            "psiphon", "psiphon3",
            "ultrasurf", "freegate",
            "lantern",
            "i2p", "i2pdesktop",

            // Tor-based
            "vidalia", "obfs4proxy",

            // Generic bypass tools
            "shadowsocks", "v2ray", "clash", "xray"
        };

        public static void KillBlockedProcesses()
        {
            foreach (var name in BlockedProcesses)
            {
                try
                {
                    foreach (var proc in Process.GetProcessesByName(name))
                    {
                        proc.Kill();
                        AuditLogger.LogBypassAttempt($"Killed process: {name} (PID {proc.Id})");
                    }
                }
                catch { }
            }
        }

        public static IEnumerable<string> GetRunningBlockedProcesses()
        {
            var running = new List<string>();
            foreach (var name in BlockedProcesses)
            {
                if (Process.GetProcessesByName(name).Any())
                    running.Add(name);
            }
            return running;
        }
    }

    // ============================================
    // CLOUDFLARE DOMAIN CATEGORIZER - Layer 3
    // Checks unknown domains against Cloudflare Radar
    // ============================================
    public static class CloudflareCategorizer
    {
        private static readonly HttpClient Http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        // Categories Cloudflare assigns to adult/explicit content
        private static readonly HashSet<string> BlockedCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Adult Themes", "Nudity", "Pornography", "Sexuality",
            "Dating", "Gambling", "Violence", "Weapons",
            "Proxy/Anonymizer", "Malware", "Phishing"
        };

        // Simple in-memory cache so we don't re-query the same domain
        private static readonly Dictionary<string, bool> Cache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static readonly object CacheLock = new object();

        public static async Task<bool> IsDomainBlockedAsync(string domain)
        {
            lock (CacheLock)
            {
                if (Cache.TryGetValue(domain, out var cached)) return cached;
            }

            try
            {
                // Cloudflare Radar public domain categorization (no API key required)
                var url = $"https://radar.cloudflare.com/api/v0/domains/categorization/{Uri.EscapeDataString(domain)}";
                var response = await Http.GetStringAsync(url);

                using var doc = JsonDocument.Parse(response);
                var root = doc.RootElement;

                if (root.TryGetProperty("result", out var result) &&
                    result.TryGetProperty("categories", out var cats))
                {
                    foreach (var cat in cats.EnumerateArray())
                    {
                        var catName = cat.GetProperty("name").GetString() ?? "";
                        if (BlockedCategories.Contains(catName))
                        {
                            lock (CacheLock) Cache[domain] = true;
                            AuditLogger.LogBlock(domain, $"Cloudflare category: {catName}");
                            return true;
                        }
                    }
                }

                lock (CacheLock) Cache[domain] = false;
                return false;
            }
            catch
            {
                // If API is unreachable, fail safe (don't block on timeout)
                return false;
            }
        }
    }

    // ============================================
    // BLOCKING ENGINE - Core Logic (upgraded)
    // ============================================
    public static class BlockingEngine
    {
        public static readonly HashSet<string> HardcodedBlocks = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Major adult sites
            "pornhub.com", "www.pornhub.com",
            "xvideos.com", "www.xvideos.com",
            "xnxx.com", "www.xnxx.com",
            "redtube.com", "www.redtube.com",
            "youporn.com", "www.youporn.com",
            "tube8.com", "www.tube8.com",
            "spankbang.com", "www.spankbang.com",
            "xhamster.com", "www.xhamster.com",
            "beeg.com", "www.beeg.com",
            "txxx.com", "www.txxx.com",
            "hqporner.com", "www.hqporner.com",
            "porntrex.com", "www.porntrex.com",

            // Live cam sites
            "chaturbate.com", "www.chaturbate.com",
            "livejasmin.com", "www.livejasmin.com",
            "stripchat.com", "www.stripchat.com",
            "cam4.com", "www.cam4.com",
            "bongacams.com", "www.bongacams.com",
            "myfreecams.com", "www.myfreecams.com",
            "streamate.com", "www.streamate.com",
            "camsoda.com", "www.camsoda.com",

            // Subscription sites
            "onlyfans.com", "www.onlyfans.com",
            "fansly.com", "www.fansly.com",

            // Image/forum sites
            "4chan.org", "www.4chan.org", "boards.4chan.org",
            "8chan.moe", "www.8chan.moe",
            "rule34.xxx", "www.rule34.xxx",
            "gelbooru.com", "www.gelbooru.com",
            "danbooru.donmai.us",
            "e621.net", "www.e621.net",

            // Gambling sites
            "bet365.com", "www.bet365.com",
            "888casino.com", "www.888casino.com",
            "pokerstars.com", "www.pokerstars.com",
            "draftkings.com", "www.draftkings.com",
            "fanduel.com", "www.fanduel.com",

            // Gore/shock sites
            "bestgore.com", "www.bestgore.com",
            "liveleak.com", "www.liveleak.com",
            "kaotic.com", "www.kaotic.com",

            // Proxy/VPN bypass sites
            "hidemyass.com", "www.hidemyass.com",
            "kproxy.com", "www.kproxy.com",
            "hide.me", "www.hide.me",
            "proxysite.com", "www.proxysite.com",
            "vpnbook.com", "www.vpnbook.com",
            "filterbypass.me", "www.filterbypass.me",

            // DoH endpoints used by Brave/Chrome to bypass DNS filtering
            "dns.cloudflare.com",
            "dns.google",
            "chrome.cloudflare-dns.com",
            "doh.opendns.com",
            "mozilla.cloudflare-dns.com",
            "dns.quad9.net"
        };

        private static readonly HashSet<string> BlockedKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "porn", "xxx", "sex", "nude", "adult", "cam", "hentai", "nsfw",
            "livecam", "webcam", "erotic", "playboy", "hustler", "penthouse",
            "brazzers", "bangbros", "naughty", "milf", "escort",
            "hookup", "casino", "poker", "slots", "betting",
            "gore", "shock", "proxy", "vpn", "unblock", "bypass", "torrent"
        };

        private static HashSet<string> CustomBlocks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ParentalControl");

        private static readonly string CustomBlocksFile;
        private static readonly string PasswordFile;

        private static string AdminPasswordHash;

        static BlockingEngine()
        {
            CustomBlocksFile = Path.Combine(DataDir, "custom_blocks.txt");
            PasswordFile     = Path.Combine(DataDir, "admin.pwd");
            AdminPasswordHash = HashPassword("ParentAdmin123");

            LoadCustomBlocks();
            LoadAdminPassword();
        }

        public static bool IsBlocked(string domain)
        {
            domain = domain.ToLower().Trim();

            if (HardcodedBlocks.Contains(domain)) return true;
            if (CustomBlocks.Contains(domain)) return true;

            foreach (var keyword in BlockedKeywords)
                if (domain.Contains(keyword)) return true;

            return false;
        }

        public static IEnumerable<string> GetAllBlocks()
            => HardcodedBlocks.Concat(CustomBlocks).OrderBy(x => x);

        public static bool AddCustomBlock(string domain, string password)
        {
            if (!VerifyPassword(password)) return false;
            domain = domain.ToLower().Trim();
            if (CustomBlocks.Add(domain)) { SaveCustomBlocks(); return true; }
            return false;
        }

        public static bool RemoveCustomBlock(string domain, string password)
        {
            if (!VerifyPassword(password)) return false;
            if (HardcodedBlocks.Contains(domain)) return false;
            domain = domain.ToLower().Trim();
            if (CustomBlocks.Remove(domain)) { SaveCustomBlocks(); return true; }
            return false;
        }

        public static bool ChangePassword(string oldPassword, string newPassword)
        {
            if (!VerifyPassword(oldPassword)) return false;
            AdminPasswordHash = HashPassword(newPassword);
            SaveAdminPassword();
            return true;
        }

        public static bool VerifyPassword(string password)
            => HashPassword(password) == AdminPasswordHash;

        private static string HashPassword(string password)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "ParentalControlSalt"));
            return Convert.ToBase64String(bytes);
        }

        private static void LoadCustomBlocks()
        {
            try
            {
                if (File.Exists(CustomBlocksFile))
                    foreach (var line in File.ReadAllLines(CustomBlocksFile))
                    {
                        var d = line.Trim();
                        if (!string.IsNullOrEmpty(d)) CustomBlocks.Add(d);
                    }
            }
            catch { }
        }

        private static void SaveCustomBlocks()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                File.WriteAllLines(CustomBlocksFile, CustomBlocks);
            }
            catch { }
        }

        private static void LoadAdminPassword()
        {
            try
            {
                if (File.Exists(PasswordFile))
                    AdminPasswordHash = File.ReadAllText(PasswordFile).Trim();
            }
            catch { }
        }

        private static void SaveAdminPassword()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                File.WriteAllText(PasswordFile, AdminPasswordHash);
            }
            catch { }
        }

        public static void UpdateHostsFile()
        {
            try
            {
                var hostsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    @"drivers\etc\hosts");

                var lines = new List<string>();
                if (File.Exists(hostsPath))
                    foreach (var line in File.ReadAllLines(hostsPath))
                        if (!line.Contains("# PARENTAL-CONTROL"))
                            lines.Add(line);

                lines.Add("");
                lines.Add("# PARENTAL-CONTROL: DO NOT EDIT BELOW THIS LINE");
                foreach (var domain in GetAllBlocks())
                    lines.Add($"127.0.0.1 {domain} # PARENTAL-CONTROL");

                File.WriteAllLines(hostsPath, lines);
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Hosts file update error: {ex.Message}", EventLogEntryType.Error);
            }
        }
    }

    // ============================================
    // WINDOWS SERVICE (upgraded)
    // ============================================
    public class ParentalControlService : ServiceBase
    {
        private System.Threading.Timer _mainTimer;
        private System.Threading.Timer _processTimer;

        public ParentalControlService()
        {
            ServiceName = "ParentalControlService";
        }

        protected override void OnStart(string[] args)
        {
            AuditLogger.Log("Parental Control Service started.");

            // Immediate actions
            BlockingEngine.UpdateHostsFile();
            DnsEnforcer.EnforceDns();
            ProcessBlocker.KillBlockedProcesses();

            // Hosts file + DNS re-enforcement every 30 seconds
            _mainTimer = new System.Threading.Timer(_ =>
            {
                BlockingEngine.UpdateHostsFile();
                DnsEnforcer.EnforceDns();
            }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

            // Process killer every 10 seconds (more responsive)
            _processTimer = new System.Threading.Timer(_ =>
            {
                ProcessBlocker.KillBlockedProcesses();
            }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        }

        protected override void OnStop()
        {
            _mainTimer?.Dispose();
            _processTimer?.Dispose();
            AuditLogger.Log("Parental Control Service stopped.", EventLogEntryType.Warning);
        }
    }

    // ============================================
    // MANAGER GUI (upgraded)
    // ============================================
    public class ManagerForm : Form
    {
        private TabControl tabs;
        private ListBox blockedList;
        private TextBox addDomainBox;
        private Button addButton, removeButton;
        private Label statusLabel;
        private TextBox oldPasswordBox, newPasswordBox, confirmPasswordBox;
        private Button changePasswordButton;
        private RichTextBox logBox;

        public ManagerForm()
        {
            Text = "Parental Control Manager";
            Size = new Size(750, 560);
            StartPosition = FormStartPosition.CenterScreen;

            tabs = new TabControl { Dock = DockStyle.Fill };
            tabs.TabPages.Add(CreateBlocksTab());
            tabs.TabPages.Add(CreateStatusTab());
            tabs.TabPages.Add(CreateSettingsTab());
            Controls.Add(tabs);

            UpdateStatus();
        }

        // ---- Blocks Tab ----
        private TabPage CreateBlocksTab()
        {
            var tab = new TabPage("Active Blocks");

            var label = new Label
            {
                Text = "🔒 Currently Blocked Domains (Hardcoded sites cannot be removed)",
                Location = new Point(20, 30),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold)
            };
            tab.Controls.Add(label);

            blockedList = new ListBox
            {
                Location = new Point(20, 60),
                Size = new Size(690, 280),
                Font = new Font("Consolas", 9)
            };
            tab.Controls.Add(blockedList);

            addDomainBox = new TextBox
            {
                Location = new Point(20, 355),
                Size = new Size(300, 25),
                PlaceholderText = "example.com"
            };
            tab.Controls.Add(addDomainBox);

            addButton = new Button
            {
                Text = "Add Domain",
                Location = new Point(330, 353),
                Size = new Size(100, 28)
            };
            addButton.Click += AddDomain_Click;
            tab.Controls.Add(addButton);

            removeButton = new Button
            {
                Text = "Remove Selected",
                Location = new Point(440, 353),
                Size = new Size(130, 28)
            };
            removeButton.Click += RemoveDomain_Click;
            tab.Controls.Add(removeButton);

            statusLabel = new Label
            {
                Location = new Point(20, 395),
                Size = new Size(690, 50),
                ForeColor = Color.Green,
                Font = new Font("Segoe UI", 9)
            };
            tab.Controls.Add(statusLabel);

            RefreshBlockList();
            return tab;
        }

        // ---- Status Tab ----
        private TabPage CreateStatusTab()
        {
            var tab = new TabPage("Status & Logs");

            var title = new Label
            {
                Text = "Live Protection Status",
                Location = new Point(20, 20),
                AutoSize = true,
                Font = new Font("Segoe UI", 11, FontStyle.Bold)
            };
            tab.Controls.Add(title);

            // DNS status
            var dnsLabel = new Label
            {
                Location = new Point(20, 55),
                Size = new Size(680, 22),
                Font = new Font("Segoe UI", 9)
            };
            bool dnsOk = DnsEnforcer.IsDnsEnforced();
            dnsLabel.Text = dnsOk
                ? "✅ DNS: Locked to Cloudflare for Families (1.1.1.3)"
                : "⚠️ DNS: Not enforced — click 'Force Re-Enforce' below";
            dnsLabel.ForeColor = dnsOk ? Color.Green : Color.OrangeRed;
            tab.Controls.Add(dnsLabel);

            // Running bypass processes
            var procTitle = new Label
            {
                Text = "Detected bypass processes (should be empty):",
                Location = new Point(20, 85),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            tab.Controls.Add(procTitle);

            var procList = new ListBox
            {
                Location = new Point(20, 110),
                Size = new Size(690, 80),
                Font = new Font("Consolas", 9),
                ForeColor = Color.Red
            };
            foreach (var p in ProcessBlocker.GetRunningBlockedProcesses())
                procList.Items.Add(p);
            if (procList.Items.Count == 0)
                procList.Items.Add("(none detected — ✅ clean)");
            tab.Controls.Add(procList);

            // Re-enforce button
            var enforceBtn = new Button
            {
                Text = "Force Re-Enforce All Protections Now",
                Location = new Point(20, 200),
                Size = new Size(280, 32),
                BackColor = Color.DarkGreen,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            enforceBtn.Click += (s, e) =>
            {
                BlockingEngine.UpdateHostsFile();
                DnsEnforcer.EnforceDns();
                ProcessBlocker.KillBlockedProcesses();
                MessageBox.Show("All protections re-enforced.", "Done",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            tab.Controls.Add(enforceBtn);

            // Event log viewer
            var logTitle = new Label
            {
                Text = "Recent audit log entries (Windows Event Log):",
                Location = new Point(20, 250),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            tab.Controls.Add(logTitle);

            logBox = new RichTextBox
            {
                Location = new Point(20, 272),
                Size = new Size(690, 160),
                Font = new Font("Consolas", 8),
                ReadOnly = true,
                BackColor = Color.Black,
                ForeColor = Color.LimeGreen
            };
            LoadRecentLogs();
            tab.Controls.Add(logBox);

            return tab;
        }

        private void LoadRecentLogs()
        {
            try
            {
                var log = new EventLog("Application");
                var entries = log.Entries.Cast<EventLogEntry>()
                    .Where(e => e.Source == "ParentalControl")
                    .OrderByDescending(e => e.TimeGenerated)
                    .Take(30)
                    .ToList();

                if (entries.Count == 0)
                {
                    logBox.Text = "(No log entries yet — service may not have run)";
                    return;
                }

                var sb = new StringBuilder();
                foreach (var entry in entries)
                    sb.AppendLine($"[{entry.TimeGenerated:HH:mm:ss}] {entry.EntryType}: {entry.Message}");

                logBox.Text = sb.ToString();
            }
            catch (Exception ex)
            {
                logBox.Text = $"Could not read event log: {ex.Message}";
            }
        }

        // ---- Settings Tab ----
        private TabPage CreateSettingsTab()
        {
            var tab = new TabPage("Settings");

            var titleLabel = new Label
            {
                Text = "Change Admin Password",
                Location = new Point(20, 30),
                AutoSize = true,
                Font = new Font("Segoe UI", 12, FontStyle.Bold)
            };
            tab.Controls.Add(titleLabel);

            var oldLabel = new Label { Text = "Current Password:", Location = new Point(20, 80), AutoSize = true };
            tab.Controls.Add(oldLabel);
            oldPasswordBox = new TextBox { Location = new Point(20, 100), Size = new Size(300, 25), UseSystemPasswordChar = true };
            tab.Controls.Add(oldPasswordBox);

            var newLabel = new Label { Text = "New Password:", Location = new Point(20, 140), AutoSize = true };
            tab.Controls.Add(newLabel);
            newPasswordBox = new TextBox { Location = new Point(20, 160), Size = new Size(300, 25), UseSystemPasswordChar = true };
            tab.Controls.Add(newPasswordBox);

            var confirmLabel = new Label { Text = "Confirm New Password:", Location = new Point(20, 200), AutoSize = true };
            tab.Controls.Add(confirmLabel);
            confirmPasswordBox = new TextBox { Location = new Point(20, 220), Size = new Size(300, 25), UseSystemPasswordChar = true };
            tab.Controls.Add(confirmPasswordBox);

            changePasswordButton = new Button
            {
                Text = "Change Password",
                Location = new Point(20, 265),
                Size = new Size(150, 32)
            };
            changePasswordButton.Click += ChangePassword_Click;
            tab.Controls.Add(changePasswordButton);

            var warningLabel = new Label
            {
                Text = "⚠️ Default password is: ParentAdmin123\nChange this immediately!",
                Location = new Point(20, 315),
                Size = new Size(500, 50),
                ForeColor = Color.OrangeRed,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            tab.Controls.Add(warningLabel);

            return tab;
        }

        // ---- Event handlers ----
        private void RefreshBlockList()
        {
            blockedList.Items.Clear();
            foreach (var domain in BlockingEngine.GetAllBlocks())
            {
                var prefix = BlockingEngine.HardcodedBlocks.Contains(domain) ? "[LOCKED] " : "[Custom] ";
                blockedList.Items.Add(prefix + domain);
            }
        }

        private void AddDomain_Click(object sender, EventArgs e)
        {
            var domain = addDomainBox.Text.Trim();
            if (string.IsNullOrEmpty(domain))
            {
                MessageBox.Show("Please enter a domain.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var password = PromptPassword("Enter admin password to add domain:");
            if (password == null) return;

            if (BlockingEngine.AddCustomBlock(domain, password))
            {
                RefreshBlockList();
                addDomainBox.Clear();
                UpdateStatus();
                MessageBox.Show($"Added: {domain}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Incorrect password or domain already blocked.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RemoveDomain_Click(object sender, EventArgs e)
        {
            if (blockedList.SelectedItem == null)
            {
                MessageBox.Show("Please select a domain to remove.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var selected = blockedList.SelectedItem.ToString();
            var domain = selected.Replace("[LOCKED] ", "").Replace("[Custom] ", "");

            if (selected.StartsWith("[LOCKED]"))
            {
                MessageBox.Show("Hardcoded domains cannot be removed.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var password = PromptPassword("Enter admin password to remove domain:");
            if (password == null) return;

            if (BlockingEngine.RemoveCustomBlock(domain, password))
            {
                RefreshBlockList();
                UpdateStatus();
                MessageBox.Show($"Removed: {domain}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Incorrect password.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ChangePassword_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(oldPasswordBox.Text) || string.IsNullOrEmpty(newPasswordBox.Text))
            {
                MessageBox.Show("Please fill in all fields.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (newPasswordBox.Text != confirmPasswordBox.Text)
            {
                MessageBox.Show("New passwords do not match.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (BlockingEngine.ChangePassword(oldPasswordBox.Text, newPasswordBox.Text))
            {
                oldPasswordBox.Clear(); newPasswordBox.Clear(); confirmPasswordBox.Clear();
                MessageBox.Show("Password changed successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Current password is incorrect.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string PromptPassword(string message)
        {
            using var form = new Form
            {
                Text = "Authentication Required",
                Size = new Size(400, 180),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var label  = new Label  { Text = message, Location = new Point(20, 20), AutoSize = true };
            var textBox = new TextBox { Location = new Point(20, 50), Size = new Size(340, 25), UseSystemPasswordChar = true };
            var ok      = new Button  { Text = "OK",     DialogResult = DialogResult.OK,     Location = new Point(200, 90), Size = new Size(75, 30) };
            var cancel  = new Button  { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(285, 90), Size = new Size(75, 30) };

            form.Controls.AddRange(new Control[] { label, textBox, ok, cancel });
            form.AcceptButton = ok;
            form.CancelButton = cancel;

            return form.ShowDialog() == DialogResult.OK ? textBox.Text : null;
        }

        private void UpdateStatus()
        {
            var service = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == "ParentalControlService");
            var serviceStatus = service?.Status.ToString() ?? "Not Installed";
            var color = service?.Status == ServiceControllerStatus.Running ? Color.Green : Color.Red;
            var dnsOk = DnsEnforcer.IsDnsEnforced();

            statusLabel.Text = $"Service: {serviceStatus}  |  DNS Filter: {(dnsOk ? "✅ Active" : "⚠️ Not enforced")}  |  Blocking {BlockingEngine.GetAllBlocks().Count()} domains";
            statusLabel.ForeColor = color;
        }
    }
}
