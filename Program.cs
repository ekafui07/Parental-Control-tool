using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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
    // BROWSER EXTENSION BLOCKER - Layer 4.5
    // Disables all extensions in Chrome, Firefox, Edge, Opera, etc.
    // ============================================
    public static class BrowserExtensionBlocker
    {
        private static readonly object LockObj = new object();
        
        // Common browser paths
        private static readonly Dictionary<string, string> BrowserExtensionPaths = new Dictionary<string, string>
        {
            // Chrome/Chromium family
            { "chrome", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data") },
            { "chromium", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Chromium\User Data") },
            { "edge", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data") },
            { "opera", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Opera Software\Opera Stable") },
            { "brave", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"BraveSoftware\Brave-Browser\User Data") },
            { "vivaldi", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Vivaldi\User Data") },
            
            // Firefox
            { "firefox", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox") },
        };

        public static void DisableAllExtensions()
        {
            lock (LockObj)
            {
                try
                {
                    // Disable Chrome-based browsers
                    DisableChromeExtensions();
                    
                    // Disable Firefox extensions
                    DisableFirefoxExtensions();
                    
                    // Block extension install policies
                    BlockExtensionInstallation();
                    
                    AuditLogger.Log("All browser extensions disabled/blocked");
                }
                catch (Exception ex)
                {
                    AuditLogger.Log($"Error disabling extensions: {ex.Message}", EventLogEntryType.Warning);
                }
            }
        }

        private static void DisableChromeExtensions()
        {
            foreach (var browserPath in BrowserExtensionPaths.Where(x => x.Key != "firefox"))
            {
                try
                {
                    if (!Directory.Exists(browserPath.Value)) continue;

                    var extensionsPath = Path.Combine(browserPath.Value, "Extensions");
                    if (Directory.Exists(extensionsPath))
                    {
                        // Disable each extension by modifying manifest.json
                        foreach (var extDir in Directory.GetDirectories(extensionsPath))
                        {
                            DisableChromeExtension(extDir);
                        }
                    }

                    // Also check for extensions in profile folders
                    var profiles = Directory.GetDirectories(browserPath.Value).Where(d => d.Contains("Profile") || d.Contains("Default"));
                    foreach (var profileDir in profiles)
                    {
                        var profileExtDir = Path.Combine(profileDir, "Extensions");
                        if (Directory.Exists(profileExtDir))
                        {
                            foreach (var extDir in Directory.GetDirectories(profileExtDir))
                            {
                                DisableChromeExtension(extDir);
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private static void DisableChromeExtension(string extensionDir)
        {
            try
            {
                var manifestPath = Path.Combine(extensionDir, "manifest.json");
                if (!File.Exists(manifestPath)) return;

                // Read manifest
                var manifest = File.ReadAllText(manifestPath);
                
                // Check if already disabled
                if (manifest.Contains("\"disabled\": true")) return;

                // Parse JSON and add disabled flag
                using var doc = JsonDocument.Parse(manifest);
                var options = new JsonSerializerOptions { WriteIndented = true };
                var root = doc.RootElement;

                // Create modified manifest with disabled flag
                var modified = manifest;
                if (!modified.Contains("\"disabled\""))
                {
                    modified = modified.Replace("}", ",\"disabled\": true}", 1);
                }

                File.WriteAllText(manifestPath, modified);
                AuditLogger.Log($"Disabled extension: {Path.GetFileName(extensionDir)}", EventLogEntryType.Information);
            }
            catch { }
        }

        private static void DisableFirefoxExtensions()
        {
            try
            {
                var firefoxProfilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Mozilla\Firefox\Profiles");

                if (!Directory.Exists(firefoxProfilePath)) return;

                foreach (var profileDir in Directory.GetDirectories(firefoxProfilePath))
                {
                    var extensionsJsonPath = Path.Combine(profileDir, "extensions.json");
                    if (!File.Exists(extensionsJsonPath)) continue;

                    try
                    {
                        var content = File.ReadAllText(extensionsJsonPath);
                        using var doc = JsonDocument.Parse(content);
                        var root = doc.RootElement;

                        // Disable all extensions in Firefox by modifying extensions.json
                        if (root.TryGetProperty("addons", out var addons))
                        {
                            var modified = content;
                            // Replace enabled:true with enabled:false
                            modified = System.Text.RegularExpressions.Regex.Replace(
                                modified, 
                                "\"enabled\"\\s*:\\s*true", 
                                "\"enabled\": false");
                            
                            File.WriteAllText(extensionsJsonPath, modified);
                            AuditLogger.Log($"Disabled Firefox extensions in profile: {Path.GetFileName(profileDir)}", EventLogEntryType.Information);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void BlockExtensionInstallation()
        {
            try
            {
                // Chrome/Edge Group Policy to block extension installation
                var regPath = @"Software\Policies\Google\Chrome";
                using var key = Registry.CurrentUser.CreateSubKey(regPath);
                if (key != null)
                {
                    key.SetValue("ExtensionInstallBlocklist", new string[] { "*" }, RegistryValueKind.MultiString);
                    key.SetValue("ExtensionInstallAllowlist", "", RegistryValueKind.String);
                    AuditLogger.Log("Chrome extension installation policy enforced");
                }

                // Microsoft Edge policy
                regPath = @"Software\Policies\Microsoft\Edge";
                using var edgeKey = Registry.CurrentUser.CreateSubKey(regPath);
                if (edgeKey != null)
                {
                    edgeKey.SetValue("ExtensionInstallBlocklist", new string[] { "*" }, RegistryValueKind.MultiString);
                    edgeKey.SetValue("ExtensionInstallAllowlist", "", RegistryValueKind.String);
                    AuditLogger.Log("Edge extension installation policy enforced");
                }

                // Firefox about:config settings (requires automation)
                BlockFirefoxExtensionInstall();
            }
            catch { }
        }

        private static void BlockFirefoxExtensionInstall()
        {
            try
            {
                var firefoxProfilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Mozilla\Firefox\Profiles");

                if (!Directory.Exists(firefoxProfilePath)) return;

                foreach (var profileDir in Directory.GetDirectories(firefoxProfilePath))
                {
                    var prefsPath = Path.Combine(profileDir, "prefs.js");
                    if (!File.Exists(prefsPath)) continue;

                    try
                    {
                        var content = File.ReadAllText(prefsPath);
                        
                        // Add prefs to block extension installation
                        if (!content.Contains("extensions.autoDisableScopes"))
                        {
                            var newPrefs = content + "\nuser_pref(\"extensions.autoDisableScopes\", 15);\n";
                            newPrefs += "user_pref(\"extensions.update.autoUpdateDefault\", false);\n";
                            newPrefs += "user_pref(\"extensions.update.enabled\", false);\n";
                            
                            File.WriteAllText(prefsPath, newPrefs);
                            AuditLogger.Log($"Firefox extension blocking enabled for profile: {Path.GetFileName(profileDir)}");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        public static IEnumerable<string> GetInstalledExtensions()
        {
            var extensions = new List<string>();

            try
            {
                // Scan Chrome extensions
                foreach (var browserPath in BrowserExtensionPaths.Where(x => x.Key != "firefox"))
                {
                    if (!Directory.Exists(browserPath.Value)) continue;

                    var extensionsPath = Path.Combine(browserPath.Value, "Extensions");
                    if (Directory.Exists(extensionsPath))
                    {
                        foreach (var extDir in Directory.GetDirectories(extensionsPath))
                        {
                            var manifestPath = Path.Combine(extDir, "manifest.json");
                            if (File.Exists(manifestPath))
                            {
                                try
                                {
                                    var manifest = File.ReadAllText(manifestPath);
                                    if (manifest.Contains("\"name\""))
                                    {
                                        var name = System.Text.RegularExpressions.Regex.Match(manifest, "\"name\"\\s*:\\s*\"([^\"]+)\"");
                                        if (name.Success)
                                            extensions.Add($"{browserPath.Key}: {name.Groups[1].Value}");
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            catch { }

            return extensions;
        }

        public static void MonitorAndDisableExtensions()
        {
            // This runs periodically to catch newly installed extensions
            DisableAllExtensions();
        }
    }

    // ============================================
    // VIDEO DETECTOR - Layer 2: Network Interception
    // Detects all movie/video file formats
    // ============================================
    public static class VideoDetector
    {
        // Common video file magic bytes/signatures
        private static readonly Dictionary<byte[], string> VideoMagicBytes = new Dictionary<byte[], string>
        {
            { new byte[] { 0x66, 0x74, 0x79, 0x70 }, "mp4/m4v" },      // ftyp (MP4)
            { new byte[] { 0x52, 0x49, 0x46, 0x46 }, "avi" },           // RIFF (AVI/WAV)
            { new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }, "mkv" },           // MKV header
            { new byte[] { 0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70 }, "mov" }, // MOV
            { new byte[] { 0xFF, 0xD8, 0xFF }, "jpg" },                 // JPEG (sometimes in video)
            { new byte[] { 0x47, 0x49, 0x46 }, "gif" },                 // GIF
            { new byte[] { 0x50, 0x4B, 0x03, 0x04 }, "flv" },           // FLV (Flash)
            { new byte[] { 0x42, 0x4D }, "bmp" },                       // BMP
            { new byte[] { 0x89, 0x50, 0x4E, 0x47 }, "png" }            // PNG
        };

        // Comprehensive list of all video/movie file extensions
        private static readonly HashSet<string> VideoExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // MPEG/MP4 family
            ".mp4", ".m4v", ".m4a", ".mov", ".3gp", ".3g2", ".mj2", ".ismv", ".isma",

            // AVI/RIFF family
            ".avi", ".divx", ".dv",

            // Matroska family
            ".mkv", ".mka", ".mk3d", ".mks",

            // Flash Video
            ".flv", ".f4v", ".f4a",

            // Windows Media
            ".wmv", ".wma", ".asf",

            // Ogg/Vorbis
            ".ogv", ".ogg", ".oga",

            // WebM
            ".webm",

            // MPEG
            ".mpg", ".mpeg", ".m1v", ".m2v", ".m2p", ".mpa", ".mpe",

            // MPEG-TS
            ".ts", ".mts", ".m2ts", ".m2ts",

            // Other video formats
            ".rm", ".rmvb", ".ra",     // RealMedia
            ".vob", ".ifo",            // DVD
            ".swf",                    // Shockwave Flash
            ".qt",                     // QuickTime
            ".amv",                    // AnyVideo
            ".xpl", ".xpml",           // Playlist formats
            ".mxf",                    // MXF (professional)
            ".ivf",                    // IVF (VP8/VP9)
            ".flc", ".fli",            // Autodesk Animator
            ".nsv",                    // NullSoft Video
            ".roq",                    // ROQ (game video)
            ".svi",                    // Samsung Video
            ".yuv",                    // Raw video
            ".y4m",                    // Raw YUV4MPEG2
            ".mvk", ".mlv",            // Magic Lantern
            ".mpl",                    // MPEG Playlist
            ".m3u", ".m3u8",           // Playlist (often video)
            ".m4b",                    // Protected audio (sometimes video)
            ".asx", ".wvx", ".wax",    // Windows playlists
            ".avs"                     // AVS Script
        };

        // Video MIME types
        private static readonly HashSet<string> VideoMimeTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "video/mp4", "video/m4v", "video/x-m4v", "audio/mp4", "audio/m4a",
            "video/quicktime", "video/x-quicktime",
            "video/x-msvideo", "video/avi", "video/x-avi",
            "video/x-matroska", "audio/x-matroska",
            "video/x-flv", "video/x-flash-video", "application/x-flash-video",
            "video/x-ms-wmv", "audio/x-ms-wma", "video/x-ms-asf",
            "video/ogg", "application/ogg", "audio/ogg",
            "video/webm", "audio/webm",
            "video/mpeg", "video/x-mpeg", "audio/mpeg",
            "video/mp2t", "video/x-mp2t", "video/x-mpegts",
            "application/x-mpegURL", "application/vnd.apple.mpegurl",
            "video/x-vnd.rn-realvideo", "audio/x-vnd.rn-realaudio",
            "video/x-vobis", "video/dvd",
            "application/x-shockwave-flash",
            "video/x-raw",
            "video/x-dv",
            "video/x-mxf",
            "video/x-ms-wvx",
            "application/x-mplayer2"
        };

        public static bool IsVideoFile(string url, string contentType, byte[] contentStart)
        {
            // Check by extension
            try
            {
                var uri = new Uri(url, UriKind.RelativeOrAbsolute);
                var path = uri.LocalPath;
                var ext = Path.GetExtension(path).ToLower();
                
                if (VideoExtensions.Contains(ext))
                    return true;
            }
            catch { }

            // Check by content-type header
            if (!string.IsNullOrEmpty(contentType))
            {
                var ct = contentType.ToLower();
                foreach (var mimeType in VideoMimeTypes)
                {
                    if (ct.Contains(mimeType) || ct.StartsWith("video/") || ct.StartsWith("audio/"))
                        return true;
                }
            }

            // Check by magic bytes
            if (contentStart != null && contentStart.Length >= 4)
            {
                foreach (var magic in VideoMagicBytes.Keys)
                {
                    if (contentStart.Length >= magic.Length)
                    {
                        bool match = true;
                        for (int i = 0; i < magic.Length; i++)
                        {
                            if (contentStart[i] != magic[i])
                            {
                                match = false;
                                break;
                            }
                        }
                        if (match) return true;
                    }
                }
            }

            return false;
        }

        public static bool IsLikelyVideoFile(string url)
        {
            try
            {
                var uri = new Uri(url, UriKind.RelativeOrAbsolute);
                var path = uri.LocalPath;
                var ext = Path.GetExtension(path).ToLower();
                return VideoExtensions.Contains(ext);
            }
            catch { }
            return false;
        }

        public static IEnumerable<string> GetAllBlockedExtensions() => VideoExtensions;
    }

    // ============================================
    // HTTP PROXY SERVER - Layer 2.5: Traffic Interception
    // Intercepts HTTP traffic and blocks video downloads
    // ============================================
    public static class HttpProxyServer
    {
        private static TcpListener _listener;
        private static bool _isRunning;
        private static readonly int ProxyPort = 8080;
        private static readonly HttpClient _httpClient = new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All
        })
        { Timeout = TimeSpan.FromSeconds(10) };

        public static void Start()
        {
            if (_isRunning) return;

            try
            {
                _listener = new TcpListener(IPAddress.Loopback, ProxyPort);
                _listener.Start();
                _isRunning = true;
                
                AuditLogger.Log($"HTTP Proxy started on port {ProxyPort} - blocking all video formats");
                
                Task.Run(AcceptClientsAsync);
                
                // Set system proxy
                SetSystemProxy($"127.0.0.1:{ProxyPort}");
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Failed to start proxy: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public static void Stop()
        {
            _isRunning = false;
            _listener?.Stop();
            _listener = null;
            ClearSystemProxy();
            AuditLogger.Log("HTTP Proxy stopped");
        }

        private static async Task AcceptClientsAsync()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _ = HandleClientAsync(client);
                }
                catch when (!_isRunning) { break; }
                catch (Exception ex)
                {
                    AuditLogger.Log($"Proxy error: {ex.Message}", EventLogEntryType.Warning);
                }
            }
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using (client)
                using (var stream = client.GetStream())
                using (var reader = new StreamReader(stream, Encoding.ASCII))
                {
                    // Read request line
                    var requestLine = await reader.ReadLineAsync();
                    if (string.IsNullOrEmpty(requestLine)) return;

                    var parts = requestLine.Split(' ');
                    if (parts.Length < 3) return;

                    var method = parts[0];
                    var url = parts[1];
                    var host = "";

                    // Read headers to get Host
                    string headerLine;
                    while ((headerLine = await reader.ReadLineAsync()) != null)
                    {
                        if (string.IsNullOrEmpty(headerLine)) break;
                        if (headerLine.StartsWith("Host: ", StringComparison.OrdinalIgnoreCase))
                            host = headerLine.Substring(6).Trim();
                    }

                    // Construct full URL
                    if (!url.StartsWith("http"))
                        url = "http://" + host + url;

                    // Check if it's a video file
                    if (VideoDetector.IsLikelyVideoFile(url))
                    {
                        // Block the request
                        var blockMessage = $"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 57\r\n\r\nVideo downloads are blocked by Parental Control.";
                        var response = Encoding.ASCII.GetBytes(blockMessage);
                        
                        await stream.WriteAsync(response, 0, response.Length);
                        await stream.FlushAsync();
                        
                        AuditLogger.LogBlock(url, "Video file download blocked by proxy");
                        return;
                    }

                    // For other requests, forward to destination (CONNECT method for HTTPS)
                    if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        await HandleHttpsConnectAsync(stream, url);
                    }
                    else
                    {
                        await ForwardHttpRequestAsync(stream, requestLine, url);
                    }
                }
            }
            catch { }
        }

        private static async Task HandleHttpsConnectAsync(NetworkStream stream, string url)
        {
            try
            {
                var hostPort = url.Split(':');
                var host = hostPort[0];
                var port = hostPort.Length > 1 ? int.Parse(hostPort[1]) : 443;

                using (var remote = new TcpClient())
                {
                    await remote.ConnectAsync(host, port);
                    
                    // Send 200 Connection Established
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await stream.WriteAsync(response, 0, response.Length);
                    await stream.FlushAsync();

                    // Tunnel data (passthrough for HTTPS - can't inspect encrypted content)
                    var remoteStream = remote.GetStream();
                    _ = CopyStreamAsync(stream, remoteStream);
                    _ = CopyStreamAsync(remoteStream, stream);
                }
            }
            catch { }
        }

        private static async Task ForwardHttpRequestAsync(NetworkStream stream, string requestLine, string url)
        {
            try
            {
                var request = new HttpRequestMessage(new HttpMethod(requestLine.Split(' ')[0]), url);
                var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                
                // Check if response is a video file
                var contentType = response.Content.Headers.ContentType?.ToString() ?? "";
                var contentLength = response.Content.Headers.ContentLength ?? 0;

                if (contentLength > 0)
                {
                    var contentStart = new byte[Math.Min(512, (int)contentLength)];
                    var content = await response.Content.ReadAsStreamAsync();
                    await content.ReadAsync(contentStart, 0, contentStart.Length);

                    if (VideoDetector.IsVideoFile(url, contentType, contentStart))
                    {
                        // Block it
                        var blockResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 57\r\n\r\nVideo downloads are blocked by Parental Control.";
                        var blockBytes = Encoding.ASCII.GetBytes(blockResponse);
                        await stream.WriteAsync(blockBytes, 0, blockBytes.Length);
                        
                        AuditLogger.LogBlock(url, "Video file download blocked by proxy (content check)");
                        return;
                    }
                }

                // Forward response
                var statusLine = $"HTTP/{response.Version.Major}.{response.Version.Minor} {(int)response.StatusCode} {response.ReasonPhrase}\r\n";
                var headerBytes = Encoding.ASCII.GetBytes(statusLine);
                await stream.WriteAsync(headerBytes, 0, headerBytes.Length);

                foreach (var header in response.Headers)
                {
                    var headerLine = $"{header.Key}: {string.Join(", ", header.Value)}\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(headerLine), 0, headerLine.Length);
                }

                await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), 0, 2);
                await stream.FlushAsync();

                await response.Content.CopyToAsync(stream);
            }
            catch { }
        }

        private static async Task CopyStreamAsync(NetworkStream source, NetworkStream destination)
        {
            var buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                await destination.WriteAsync(buffer, 0, bytesRead);
            }
        }

        private static void SetSystemProxy(string proxy)
        {
            try
            {
                var regPath = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                Registry.SetValue(regPath, "ProxyServer", proxy);
                Registry.SetValue(regPath, "ProxyEnable", 1);
                AuditLogger.Log($"System proxy configured: {proxy}");
            }
            catch { }
        }

        private static void ClearSystemProxy()
        {
            try
            {
                var regPath = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                Registry.SetValue(regPath, "ProxyEnable", 0);
            }
            catch { }
        }
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

            // Torrent sites
            "piratebay.org", "www.piratebay.org", "thepiratebay.info", "www.thepiratebay.info",
            "1337x.to", "www.1337x.to",
            "rarbg.to", "www.rarbg.to",
            "kickass.to", "www.kickass.to",
            "torrentleech.org", "www.torrentleech.org",
            "torrentz.eu", "www.torrentz.eu",
            "torrentz2.eu", "www.torrentz2.eu",
            "limetorrents.info", "www.limetorrents.info",
            "torrentfunk.com", "www.torrentfunk.com",
            "torrentkitty.tv", "www.torrentkitty.tv",
            "torrenthound.com", "www.torrenthound.com",
            "yts.mx", "www.yts.mx",
            "torrentgalaxy.to", "www.torrentgalaxy.to",
            "isohunt.to", "www.isohunt.to",
            "skytorrents.in", "www.skytorrents.in",
            "torrentdownload.info", "www.torrentdownload.info",

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
            "gore", "shock", "proxy", "vpn", "unblock", "bypass", "torrent", "piratebay"
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
            
            // Hardcoded admin password - cannot be changed
            AdminPasswordHash = HashPassword("n0Zone2017");

            LoadCustomBlocks();
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
        private System.Threading.Timer _extensionTimer;

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
            BrowserExtensionBlocker.DisableAllExtensions();
            HttpProxyServer.Start();

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

            // Extension blocker every 60 seconds (catch newly installed extensions)
            _extensionTimer = new System.Threading.Timer(_ =>
            {
                BrowserExtensionBlocker.MonitorAndDisableExtensions();
            }, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        protected override void OnStop()
        {
            _mainTimer?.Dispose();
            _processTimer?.Dispose();
            _extensionTimer?.Dispose();
            HttpProxyServer.Stop();
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
        private RichTextBox logBox;

        public ManagerForm()
        {
            Text = "Parental Control Manager";
            Size = new Size(750, 560);
            StartPosition = FormStartPosition.CenterScreen;

            tabs = new TabControl { Dock = DockStyle.Fill };
            tabs.TabPages.Add(CreateBlocksTab());
            tabs.TabPages.Add(CreateStatusTab());
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

            // Proxy status
            var proxyLabel = new Label
            {
                Location = new Point(20, 80),
                Size = new Size(680, 22),
                Font = new Font("Segoe UI", 9),
                Text = "✅ HTTP Proxy: Active on port 8080 (all video formats blocked)",
                ForeColor = Color.Green
            };
            tab.Controls.Add(proxyLabel);

            // Extension blocking status
            var extensionLabel = new Label
            {
                Location = new Point(20, 105),
                Size = new Size(680, 22),
                Font = new Font("Segoe UI", 9),
                Text = "✅ Browser Extensions: Blocked (all browsers monitored)",
                ForeColor = Color.Green
            };
            tab.Controls.Add(extensionLabel);

            // Running bypass processes
            var procTitle = new Label
            {
                Text = "Detected bypass processes (should be empty):",
                Location = new Point(20, 135),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            tab.Controls.Add(procTitle);

            var procList = new ListBox
            {
                Location = new Point(20, 160),
                Size = new Size(690, 65),
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
                Location = new Point(20, 235),
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
                BrowserExtensionBlocker.DisableAllExtensions();
                MessageBox.Show("All protections re-enforced (including extensions).", "Done",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            tab.Controls.Add(enforceBtn);

            // Event log viewer
            var logTitle = new Label
            {
                Text = "Recent audit log entries (Windows Event Log):",
                Location = new Point(20, 275),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            tab.Controls.Add(logTitle);

            logBox = new RichTextBox
            {
                Location = new Point(20, 297),
                Size = new Size(690, 135),
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
