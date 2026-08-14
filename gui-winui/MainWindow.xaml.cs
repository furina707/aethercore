using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.UI;

namespace OmniProxyGui;

// ===== 行模型 =====
public class OutboundRow
{
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Target { get; set; } = "";
    public string HealthText { get; set; } = "";
    public SolidColorBrush Dot { get; set; } = new SolidColorBrush(Color.FromArgb(255, 0x2F, 0xB8, 0x7F));
    public string Connections { get; set; } = "0";
    public string Active { get; set; } = "0";
    public string Errors { get; set; } = "0";
    public string Up { get; set; } = "0 B";
    public string Down { get; set; } = "0 B";
}

public class ListenerRow { public string Protocol { get; set; } = ""; public string Bind { get; set; } = ""; }
public class RouteRow { public string Name { get; set; } = ""; public string Match { get; set; } = ""; public string Mode { get; set; } = ""; public string Outbound { get; set; } = ""; }
public class NodeRow { public string Tag { get; set; } = ""; public string Type { get; set; } = ""; public string Server { get; set; } = ""; public string Port { get; set; } = ""; }

public sealed partial class MainWindow : Window
{
    private static readonly SolidColorBrush Green = new(Color.FromArgb(255, 0x2F, 0xB8, 0x7F));
    private static readonly SolidColorBrush Red = new(Color.FromArgb(255, 0xEF, 0x5F, 0x6B));
    private static readonly SolidColorBrush Purple = new(Color.FromArgb(255, 0xA7, 0x8B, 0xFA));

    private readonly ObservableCollection<OutboundRow> _ob = new();
    private readonly ObservableCollection<ListenerRow> _ls = new();
    private readonly ObservableCollection<RouteRow> _rt = new();
    private readonly ObservableCollection<NodeRow> _nodes = new();
    private readonly DispatcherTimer _pollTimer;
    private readonly DispatcherTimer _logTimer;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private Process? _omniProc;
    private Process? _sbProc;
    private readonly string _root;

    public MainWindow()
    {
        InitializeComponent();
        ObList.ItemsSource = _ob;
        LsList.ItemsSource = _ls;
        RtList.ItemsSource = _rt;
        NodeList.ItemsSource = _nodes;

        _root = FindRoot();
        RefreshNodes();
        LoadSubSources();
        TailLog();
        ApplyCorePreference();

        _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _pollTimer.Tick += async (_, _) => await PollAsync();
        _pollTimer.Start();

        _logTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        _logTimer.Tick += (_, _) => TailLog();
        _logTimer.Start();
    }

    private string CorePrefFile => Path.Combine(_root, ".gui-core");

    private void ApplyCorePreference()
    {
        // 记忆上次选择的核（omni / singbox）
        string core = "omni";
        try { core = File.ReadAllText(CorePrefFile).Trim(); } catch { }
        if (core != "singbox") core = "omni";
        if (core == "singbox") CoreSb.IsChecked = true; else CoreOmni.IsChecked = true;
        ApplyCoreVisibility(core == "singbox");
    }

    private void Core_Checked(object sender, RoutedEventArgs e)
    {
        // XAML 中 IsChecked="True" 会在 InitializeComponent 期间触发 Checked，
        // 此时控件字段尚未赋值，需跳过
        if (OmniSection == null || SbSection == null) return;
        if (sender is not RadioButton rb) return;
        bool singbox = rb.Tag?.ToString() == "singbox";
        ApplyCoreVisibility(singbox);
        try { File.WriteAllText(CorePrefFile, singbox ? "singbox" : "omni"); } catch { }
    }

    private void ApplyCoreVisibility(bool singbox)
    {
        OmniSection.Visibility = singbox ? Visibility.Collapsed : Visibility.Visible;
        SbSection.Visibility = singbox ? Visibility.Visible : Visibility.Collapsed;
    }

    // ===== 订阅源选择 =====
    private void LoadSubSources()
    {
        var sub = Path.Combine(_root, "sub");
        if (!File.Exists(sub)) return;
        foreach (var line in File.ReadAllLines(sub))
        {
            var s = line.Trim();
            if (s.StartsWith("http")) SubSource.Items.Add(s);
        }
        if (SubSource.Items.Count > 0) SubSource.SelectedIndex = 0;
    }

    private async void SubUpdate_Click(object sender, RoutedEventArgs e)
    {
        BtnSub.IsEnabled = false;
        BtnSub.Content = "更新中…";
        // 选中了某个订阅源 → 仅更新该源；否则全部
        var url = SubSource.SelectedItem as string;
        if (!string.IsNullOrEmpty(url))
            await RunPyAsync("update_subscription.py", "--url", url);
        else
            await RunPyAsync("update_subscription.py");
        BtnSub.IsEnabled = true;
        BtnSub.Content = "更新该订阅";
        RefreshNodes();
    }

    private async void SubUpdateAll_Click(object sender, RoutedEventArgs e) => await RunPyAsync("update_subscription.py");

    // ===== 节点选择 / 设为默认 =====
    private void NodeList_SelectionChanged(object sender, Microsoft.UI.Xaml.Controls.SelectionChangedEventArgs e)
    {
        BtnSetDefault.IsEnabled = NodeList.SelectedItem != null;
    }

    private void SetDefaultNode_Click(object sender, RoutedEventArgs e)
    {
        if (NodeList.SelectedItem is not NodeRow node) return;
        var cfg = Path.Combine(_root, "singbox-config.json");
        if (!File.Exists(cfg)) { SbOutput.Text = "未找到 singbox-config.json"; return; }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(cfg));
            var outbounds = doc.RootElement.GetProperty("outbounds");
            // 找到 "🚀节点选择" selector，把选中节点 tag 置顶（作为默认出口）
            var nodeTag = node.Tag;
            var list = new System.Collections.Generic.List<object>();
            bool done = false;
            foreach (var ob in outbounds.EnumerateArray())
            {
                var tag = ob.TryGetProperty("tag", out var t) ? t.GetString() : "";
                var type = ob.TryGetProperty("type", out var ty) ? ty.GetString() : "";
                if (type == "selector" && tag == "🚀节点选择")
                {
                    var outs = new System.Collections.Generic.List<string>();
                    foreach (var o in ob.GetProperty("outbounds").EnumerateArray())
                        outs.Add(o.GetString()!);
                    outs.Remove(nodeTag);
                    outs.Insert(0, nodeTag);   // 默认取第一个
                    list.Add(new
                    {
                        type = "selector",
                        tag = "🚀节点选择",
                        interrupt_exist_connections = ob.TryGetProperty("interrupt_exist_connections", out var ie) && ie.GetBoolean(),
                        outbounds = outs,
                    });
                    done = true;
                    continue;
                }
                list.Add(JsonElementToObject(ob));
            }
            if (!done) { SbOutput.Text = "未找到 🚀节点选择 selector"; return; }

            // 组装回原结构并写文件（备份后写）
            using var root = JsonDocument.Parse(File.ReadAllText(cfg));
            var props = new System.Collections.Generic.Dictionary<string, object>();
            foreach (var pr in root.RootElement.EnumerateObject())
                props[pr.Name] = pr.Value.ValueKind == JsonValueKind.Array
                    ? (object)System.Linq.Enumerable.ToList(JsonElementToObjectList(pr.Value))
                    : JsonElementToObject(pr.Value);
            props["outbounds"] = list;

            var bak = cfg + $".bak-{DateTime.Now:yyyyMMdd-HHmmss}";
            File.Copy(cfg, bak, true);
            File.WriteAllText(cfg, JsonSerializer.Serialize(props, new JsonSerializerOptions { WriteIndented = true }));
            SbOutput.Text = $"已设为默认节点：{nodeTag}\n（原配置已备份为 {Path.GetFileName(bak)}）";
        }
        catch (Exception ex) { SbOutput.Text = $"设置默认节点失败：{ex.Message}"; }
    }

    private static object JsonElementToObject(JsonElement el) => el.Clone();

    private static System.Collections.Generic.IEnumerable<object> JsonElementToObjectList(JsonElement arr)
    {
        foreach (var x in arr.EnumerateArray()) yield return x.Clone();
    }


    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir != null; i++)
        {
            if (File.Exists(Path.Combine(dir.FullName, "sub"))) return dir.FullName;
            dir = dir.Parent;
        }
        return AppContext.BaseDirectory;
    }

    // ===== 轮询 /api/status（失败 fallback 演示数据） =====
    private async Task PollAsync()
    {
        JsonElement d;
        bool demo = false;
        try
        {
            using var resp = await _http.GetAsync("http://127.0.0.1:9090/api/status");
            resp.EnsureSuccessStatusCode();
            d = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        }
        catch
        {
            d = DemoStatus();
            demo = true;
        }
        Render(d, demo);
        RefreshProxyStates();
    }

    private void Render(JsonElement d, bool demo)
    {
        OmniDot.Fill = demo ? Purple : Green;
        OmniStatus.Text = demo
            ? $"演示数据模式（omni-proxy 未运行）· v{d.GetProperty("version").GetString()} · 启动后自动切换为实时数据"
            : $"已连接 · v{d.GetProperty("version").GetString()} · 热重载 {Cfg(d, "hot_reload_secs")}s · 健康检查 {Cfg(d, "health_check_enabled")}";

        var st = d.GetProperty("stats");
        KpiTotal.Text = st.GetProperty("total_connections").ToString();
        KpiActive.Text = st.GetProperty("active_connections").ToString();
        KpiUp.Text = st.GetProperty("bytes_in_human").GetString();
        KpiDown.Text = st.GetProperty("bytes_out_human").GetString();
        KpiErrors.Text = st.GetProperty("errors").ToString();
        KpiUptime.Text = FmtUptime(st.GetProperty("uptime_secs").GetInt64());

        _ob.Clear();
        foreach (var o in d.GetProperty("outbounds").EnumerateArray())
        {
            bool alive = o.GetProperty("alive").GetBoolean();
            _ob.Add(new OutboundRow
            {
                Name = o.GetProperty("name").GetString()!,
                Protocol = o.GetProperty("protocol").GetString()!,
                Target = o.GetProperty("target").GetString()!,
                HealthText = alive ? "正常" : $"失效×{o.GetProperty("failures")}",
                Dot = alive ? Green : Red,
                Connections = o.GetProperty("connections").ToString(),
                Active = o.GetProperty("active").ToString(),
                Errors = o.GetProperty("errors").ToString(),
                Up = FmtBytes(o.GetProperty("bytes_up").GetInt64()),
                Down = FmtBytes(o.GetProperty("bytes_down").GetInt64()),
            });
        }
        _ls.Clear();
        foreach (var l in d.GetProperty("listeners").EnumerateArray())
            _ls.Add(new ListenerRow { Protocol = l.GetProperty("protocol").GetString()!, Bind = l.GetProperty("bind").GetString()! });

        _rt.Clear();
        foreach (var r in d.GetProperty("routes").EnumerateArray())
        {
            var parts = new System.Collections.Generic.List<string>();
            if (r.TryGetProperty("domain_suffix", out var ds) && ds.ValueKind == JsonValueKind.Array)
                parts.Add("域名: " + string.Join(", ", EnumerateStrings(ds)));
            if (r.TryGetProperty("ip_cidr", out var ip) && ip.ValueKind == JsonValueKind.Array)
                parts.Add("CIDR: " + string.Join(", ", EnumerateStrings(ip)));
            if (r.TryGetProperty("port", out var pt) && pt.ValueKind == JsonValueKind.Array)
                parts.Add("端口: " + string.Join(",", EnumerateNumbers(pt)));
            _rt.Add(new RouteRow
            {
                Name = r.TryGetProperty("name", out var nm) ? nm.GetString()! : "未命名",
                Match = parts.Count > 0 ? string.Join(" / ", parts) : "全量",
                Mode = r.GetProperty("match_mode").GetString()!,
                Outbound = r.GetProperty("outbound").GetString()!,
            });
        }
    }

    private static string Cfg(JsonElement d, string key) =>
        d.TryGetProperty("config", out var c) && c.TryGetProperty(key, out var v) ? v.ToString() : "—";

    private static System.Collections.Generic.IEnumerable<string> EnumerateStrings(JsonElement arr)
    { foreach (var x in arr.EnumerateArray()) yield return x.GetString()!; }
    private static System.Collections.Generic.IEnumerable<string> EnumerateNumbers(JsonElement arr)
    { foreach (var x in arr.EnumerateArray()) yield return x.ToString(); }

    private static string FmtBytes(long b)
    {
        double v = b;
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return (i == 0 ? $"{v:0}" : $"{v:0.00}") + " " + u[i];
    }
    private static string FmtUptime(long s)
    { long h = s / 3600, m = s % 3600 / 60, x = s % 60; return $"{h:00}:{m:00}:{x:00}"; }

    // ===== 演示数据（与 proxy_gui.py DEMO_STATUS 一致） =====
    private static JsonElement DemoStatus() =>
        JsonDocument.Parse(
            """{"version":"0.1.0","stats":{"total_connections":1284,"active_connections":7,"bytes_in":523000000,"bytes_out":1204000000,"bytes_in_human":"498.78 MB","bytes_out_human":"1.12 GB","errors":3,"uptime_secs":90042},"outbounds":[{"name":"direct","protocol":"direct","target":"0.0.0.0:0","alive":true,"failures":0,"connections":820,"active":2,"errors":0,"bytes_up":210000000,"bytes_down":640000000},{"name":"via-socks5","protocol":"socks5","target":"127.0.0.1:1088","alive":true,"failures":0,"connections":410,"active":5,"errors":1,"bytes_up":300000000,"bytes_down":550000000},{"name":"dns","protocol":"direct","target":"8.8.8.8:53","alive":false,"failures":3,"connections":54,"active":0,"errors":2,"bytes_up":13000000,"bytes_down":14000000}],"listeners":[{"protocol":"http","bind":"0.0.0.0:8080"},{"protocol":"https","bind":"0.0.0.0:8443"},{"protocol":"socks","bind":"0.0.0.0:1080"},{"protocol":"dns","bind":"0.0.0.0:53"}],"routes":[{"name":"内网直连","domain_suffix":["internal.example.com","corp.local"],"ip_cidr":[],"port":[],"match_mode":"any","outbound":"direct"},{"name":"SSH/RDP 走 SOCKS5","domain_suffix":[],"ip_cidr":[],"port":[22,3389],"match_mode":"any","outbound":"via-socks5"},{"name":"内网网段","domain_suffix":[],"ip_cidr":["192.168.0.0/16","10.0.0.0/8"],"port":[],"match_mode":"any","outbound":"direct"}],"config":{"hot_reload_secs":5,"health_check_enabled":true,"log_level":"info","stats_interval_secs":10,"idle_timeout_secs":300}}"""
        ).RootElement;

    // ===== 进程启停 =====
    private Process? StartProc(string exe, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe) { WorkingDirectory = _root, CreateNoWindow = true, UseShellExecute = false };
            foreach (var a in args) psi.ArgumentList.Add(a);
            return Process.Start(psi);
        }
        catch { return null; }
    }

    private void OmniStart_Click(object sender, RoutedEventArgs e)
    {
        var exe = FindBinary("proxy-core", "omni-proxy");
        if (exe == null) { SbOutput.Text += "\n[omni] 未找到编译产物，请先 cargo build --release\n"; return; }
        _omniProc = StartProc(exe, Path.Combine(_root, "proxy-config.json"));
        BtnOmniStart.IsEnabled = false;
        BtnOmniStop.IsEnabled = true;
        OmniStatus.Text = "启动中…（等待 Web 控制台就绪）";
    }

    private void OmniStop_Click(object sender, RoutedEventArgs e)
    {
        try { _omniProc?.Kill(); } catch { }
        _omniProc = null;
        BtnOmniStart.IsEnabled = true;
        BtnOmniStop.IsEnabled = false;
    }

    private void OmniRefresh_Click(object sender, RoutedEventArgs e) => _ = PollAsync();

    private void SbStart_Click(object sender, RoutedEventArgs e)
    {
        var exe = Path.Combine(_root, "core", "singbox-core", "sing-box.exe");
        if (!File.Exists(exe)) { SbOutput.Text += "\n[sing-box] 未找到可执行文件\n"; return; }
        _sbProc = StartProc(exe, "run", "-c", Path.Combine(_root, "singbox-config.json"));
        if (_sbProc != null)
        {
            BtnSbStart.IsEnabled = false;
            BtnSbStop.IsEnabled = true;
            SbDot.Fill = Green;
            SbStatus.Text = $"运行中（PID {_sbProc.Id}）";
        }
    }

    private void SbStop_Click(object sender, RoutedEventArgs e)
    {
        try { _sbProc?.Kill(); } catch { }
        _sbProc = null;
        BtnSbStart.IsEnabled = true;
        BtnSbStop.IsEnabled = false;
        SbDot.Fill = new SolidColorBrush(Color.FromArgb(255, 0x4A, 0x55, 0x68));
        SbStatus.Text = "未运行";
    }


    private async void SbVersion_Click(object sender, RoutedEventArgs e) => await RunPyAsync("update_singbox.py", "--check");

    private async Task RunPyAsync(string script, params string[] args)
    {
        var py = "python";
        if (File.Exists(Path.Combine(_root, "core", "singbox-core", "python.exe"))) py = Path.Combine(_root, "core", "singbox-core", "python.exe");
        var psi = new ProcessStartInfo(py)
        {
            WorkingDirectory = _root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(Path.Combine(_root, script));
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            var p = Process.Start(psi);
            if (p == null) return;
            var outp = await p.StandardOutput.ReadToEndAsync();
            var errp = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            SbOutput.Text = $"$ python {script} {string.Join(' ', args)}\n{outp}{errp}";
        }
        catch (Exception ex) { SbOutput.Text = $"运行失败：{ex.Message}"; }
    }

    // ===== 节点解析 =====
    private void RefreshNodes()
    {
        _nodes.Clear();
        var cfg = Path.Combine(_root, "singbox-config.json");
        if (!File.Exists(cfg)) { SbStatus.Text = "未找到 singbox-config.json"; return; }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(cfg));
            foreach (var ob in doc.RootElement.GetProperty("outbounds").EnumerateArray())
            {
                var tag = ob.TryGetProperty("tag", out var t) ? t.GetString() : "";
                if (string.IsNullOrEmpty(tag)) continue;
                _nodes.Add(new NodeRow
                {
                    Tag = tag!,
                    Type = ob.TryGetProperty("type", out var ty) ? ty.GetString()! : "",
                    Server = ob.TryGetProperty("server", out var sv) ? sv.GetString()! : "",
                    Port = ob.TryGetProperty("server_port", out var pt) ? pt.ToString() : "",
                });
            }
            if (_nodes.Count == 0) SbStatus.Text = "节点清单为空";
        }
        catch { SbStatus.Text = "singbox-config.json 解析失败"; }
    }

    // ===== 日志尾随 =====
    private void TailLog()
    {
        var dir = Path.Combine(_root, "log");
        if (!Directory.Exists(dir)) return;
        var latest = new DirectoryInfo(dir).GetFiles("omni-proxy-*.log");
        if (latest.Length == 0) return;
        var f = latest[^1];
        try
        {
            var lines = File.ReadAllLines(f.FullName);
            var tail = lines.Length > 300 ? lines[^300..] : lines;
            LogBox.Text = string.Join("\n", tail);
            if (ChkFollow.IsChecked == true) { LogBox.SelectionStart = LogBox.Text.Length; LogBox.SelectionLength = 0; }
        }
        catch { }
    }

    // ===== 入口 =====
    private void OpenDocs_Click(object sender, RoutedEventArgs e) => LaunchFile("singbox-docs.html");
    private void OpenReport_Click(object sender, RoutedEventArgs e) => LaunchFile("dev-progress-report.html");
    private void OpenLogDir_Click(object sender, RoutedEventArgs e)
    {
        var dir = Path.Combine(_root, "log");
        Directory.CreateDirectory(dir);
        LaunchFile(dir);
    }
    private void OpenOfficial_Click(object sender, RoutedEventArgs e) => _ = LaunchUri("https://sing-box.sagernet.org/configuration/");

    private void LaunchFile(string path) => _ = LaunchUri(Path.GetFullPath(Path.Combine(_root, path)));

    private static async Task LaunchUri(string uri)
    {
        try { await Windows.System.Launcher.LaunchUriAsync(new Uri(uri)); } catch { }
    }

    // ===== 系统代理（Windows 注册表 + 通知系统刷新） =====
    private const string ProxyKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    [DllImport("shell32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsUserAnAdmin();

    private static string SysProxyGet()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(ProxyKey);
            var en = (int?)(k?.GetValue("ProxyEnable")) ?? 0;
            var srv = (string?)(k?.GetValue("ProxyServer")) ?? "";
            return en == 1 ? srv : "";
        }
        catch { return ""; }
    }

    private static void SysProxySet(bool enable, string server = "")
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(ProxyKey);
            k.SetValue("ProxyEnable", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
            if (enable) k.SetValue("ProxyServer", server);
            // 通知系统立即刷新代理设置
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // SETTINGS_CHANGED
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // REFRESH
        }
        catch { }
    }

    private void RefreshProxyStates()
    {
        var s = SysProxyGet();
        var t = s == "" ? "未开启" : $"已开启 → {s}";
        OmniSysProxyState.Text = t;
        SbSysProxyState.Text = t;
    }

    /// <summary>omni-proxy 的 HTTP 监听端口（从 proxy-config.json 读取，默认 8080）。</summary>
    private int OmniHttpPort()
    {
        var cfg = Path.Combine(_root, "proxy-config.json");
        if (File.Exists(cfg))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(cfg));
                foreach (var l in doc.RootElement.GetProperty("server").GetProperty("listeners").EnumerateArray())
                {
                    if (l.TryGetProperty("protocol", out var p) && p.GetString() == "http"
                        && l.TryGetProperty("bind", out var b) && b.ValueKind == JsonValueKind.String)
                    {
                        var s = b.GetString()!;
                        var idx = s.LastIndexOf(':');
                        if (idx >= 0 && int.TryParse(s[(idx + 1)..], out var port)) return port;
                    }
                }
            }
            catch { }
        }
        return 8080;
    }

    private void OmniSysProxyOn_Click(object sender, RoutedEventArgs e)
    {
        SysProxySet(true, $"127.0.0.1:{OmniHttpPort()}");
        RefreshProxyStates();
    }

    private void OmniSysProxyOff_Click(object sender, RoutedEventArgs e)
    {
        SysProxySet(false);
        RefreshProxyStates();
    }

    private void SbSysProxyOn_Click(object sender, RoutedEventArgs e)
    {
        SysProxySet(true, "127.0.0.1:9090"); // sing-box mixed 监听
        RefreshProxyStates();
    }

    private void SbSysProxyOff_Click(object sender, RoutedEventArgs e)
    {
        SysProxySet(false);
        RefreshProxyStates();
    }

    private void OmniTun_Click(object sender, RoutedEventArgs e)
    {
        if (!IsUserAnAdmin())
        {
            // TUN 需要管理员：经 omni-elevater 提权启动 omni-proxy（配置启用 wintun 时自动生效）
            var elev = FindBinary("proxy-core", "omni-elevater");
            var omni = FindBinary("proxy-core", "omni-proxy");
            if (elev == null || omni == null)
            {
                SbOutput.Text = "未找到 omni-elevater / omni-proxy。TUN 模式需要：管理员权限 + wintun.dll + 配置启用 transparent.wintun。";
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo(elev)
                {
                    UseShellExecute = true,
                    Arguments = $"\"{omni}\" \"{Path.Combine(_root, "proxy-config.json")}\"",
                });
                SbOutput.Text = "已请求 UAC 提权启动 omni-proxy（TUN 模式）。确认 wintun.dll 存在且配置启用 transparent.wintun。";
            }
            catch (Exception ex) { SbOutput.Text = $"TUN 提权失败：{ex.Message}"; }
        }
        else
        {
            SbOutput.Text = "当前已是管理员。TUN 模式需 wintun.dll（core/singbox-core/ 或系统目录）且配置启用 transparent.wintun；请确认后点击「启动核心」。";
        }
    }

    private string? FindBinary(string subdir, string name)
    {
        var baseDir = Path.Combine(_root, "core", subdir, "target");
        foreach (var profile in new[] { "release", "debug" })
        {
            var cand = Path.Combine(baseDir, profile, name + ".exe");
            if (File.Exists(cand)) return cand;
        }
        return null;
    }
}
