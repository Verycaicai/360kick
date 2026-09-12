// ============================================================
//  360Kick —— 360 全系软件强制清除工具
//
//  检测并强制清除一切 360 / Qihoo / 奇虎 系软件及其残留:
//  进程、服务、内核驱动、计划任务、注册表项、安装目录、数据文件、防火墙规则
//
//  用法:
//    360Kick.exe scan              仅扫描检测, 不做任何修改(分步打印过程)
//    360Kick.exe remove            强制清除(带确认), 有被拦截项时提供自动处理选项
//    360Kick.exe --safemode        设置: 重启进安全模式自动清理(对抗自我保护内核驱动)
//    双击运行                      先扫描, 再交互菜单选择
//    (以下由工具自动注册, 一般无需手动运行:)
//    360Kick.exe --cleanup-at-boot   开机自动清理(RunOnce 触发, 重启后自动继续)
//    360Kick.exe --safemode-cleanup  安全模式内自动清理(自动恢复正常启动并重启收尾)
//
//  编译(使用 Windows 自带的 .NET Framework 4.x 编译器, 无需安装任何环境):
//    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /codepage:65001 ^
//      /target:exe /platform:anycpu /optimize+ /win32manifest:app.manifest ^
//      /out:360Kick.exe 360Kick.cs
//
//  说明:
//    - exe 带 requireAdministrator 清单, 启动自动请求管理员权限。
//    - 360 的「自我保护」是内核驱动, 管理员也无法绕过; 请先关闭自我保护再运行,
//      否则被拦截的项会被列出, 需要重启进安全模式后重跑。
// ============================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

internal static class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existing, string newName, int flags);
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    private static readonly HashSet<string> Pending = new HashSet<string>();  // 已登记重启后删除
    private static readonly List<string> Blocked = new List<string>();        // 被拦截(自我保护)
    private static readonly List<string> Done = new List<string>();           // 已删除的主要项
    private static readonly HashSet<string> Parents = new HashSet<string>();  // 待清空的父目录
    private static int FileCount;   // 已删文件数
    private static int FindCount;   // 扫描发现的项数
    private static bool ScanMode;
    private static StreamWriter Log;

    private static int Main(string[] args)
    {
        Log = new StreamWriter(Path.Combine(Path.GetTempPath(), "360Kick.log"), true, Encoding.UTF8) { AutoFlush = true };
        try
        {
            int cp = Console.OutputEncoding.CodePage;
            if (cp != 936 && cp != 54936 && cp != 950 && cp != 65001)
                Console.OutputEncoding = Encoding.UTF8;
        }
        catch { }

        Say("==================================================");
        Say("  360Kick —— 360 全系软件强制清除工具");
        Say("==================================================");

        string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "";
        if (mode == "remove")
        {
            if (ConfirmRemove()) { DoRemove(); PrintSummary(); OfferAutoCleanup(); }
        }
        else if (mode == "scan")
        {
            ScanAll(true);
        }
        else if (mode == "--cleanup-at-boot")
        {
            // 重启后自动继续: 由 RunOnce 触发, 不再确认
            ClearRunOnce();
            Say("=== 开机自动清理(重启后自动继续) ===");
            DoRemove();
            PrintSummary();
            if (Blocked.Count > 0)
            {
                // 补刀后仍被拦截说明保护驱动仍加载了(登记可能被拦), 兜底到安全模式
                Say("");
                Say("仍有 " + Blocked.Count + " 项被拦截, 是否自动设置安全模式清理(最彻底)? (y/n)");
                string c = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
                if (c == "y" || c == "yes") SetupSafeMode();
            }
            Say("按任意键退出...");
            try { Console.ReadKey(true); } catch { }
        }
        else if (mode == "--safemode")
        {
            // 设置: 重启进安全模式自动清理
            SetupSafeMode();
        }
        else if (mode == "--safemode-cleanup")
        {
            // 在安全模式中运行: 先恢复正常启动 → 清理 → 注册开机收尾 → 自动重启
            ClearRunOnce();
            Run("bcdedit.exe", "/deletevalue {current} safeboot", 15);
            Say("=== 安全模式自动清理 ===");
            DoRemove();
            PrintSummary();
            SetRunOnce("360Kick", "--cleanup-at-boot");
            Say("10 秒后自动重启, 进入正常模式完成收尾...");
            Run("shutdown.exe", "/r /t 10", 10);
            Say("按任意键退出...");
            try { Console.ReadKey(true); } catch { }
        }
        else
        {
            while (true)
            {
                ScanAll(true);
                Say("");
                Say("[1] 执行清除   [2] 重新扫描   [0] 退出");
                string c = Console.ReadLine() ?? "";
                if (c.Trim() == "0") break;
                if (c.Trim() == "1") { if (ConfirmRemove()) { DoRemove(); PrintSummary(); OfferAutoCleanup(); } break; }
            }
            Say("按任意键退出...");
            try { Console.ReadKey(true); } catch { }
        }
        Log.Close();
        return 0;
    }

    // ================= 基础工具 =================

    private static void Say(string msg)
    {
        Console.WriteLine(msg);
        if (Log != null) Log.WriteLine(msg);
    }

    private static void Find(string msg) { FindCount++; Say("  [找到] " + msg); }

    private static string[] SafeGetDirs(string path)
    {
        try { return Directory.GetDirectories(path); } catch { return new string[0]; }
    }

    private static string[] SafeGetFiles(string path, string pattern = "*")
    {
        try { return Directory.GetFiles(path, pattern); } catch { return new string[0]; }
    }

    private static string Run(string file, string args, int timeoutSec)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                // 后台线程边读边排空管道, 避免输出超过管道缓冲把子进程卡死
                string so = "", se = "";
                var t1 = new System.Threading.Thread(delegate() { try { so = p.StandardOutput.ReadToEnd(); } catch { } });
                var t2 = new System.Threading.Thread(delegate() { try { se = p.StandardError.ReadToEnd(); } catch { } });
                t1.Start();
                t2.Start();
                if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } p.WaitForExit(5000); }
                t1.Join(5000);
                t2.Join(5000);
                return so;
            }
        }
        catch { return ""; }
    }

    // ================= 匹配规则 =================
    // 排除名单: 与360无关但名字带 360 的第三方(Xbox手柄驱动、360Works文件制作插件、360Amigo清理工具)

    // 显示名/厂商/计划任务名/防火墙规则名等文本
    private static bool Is360Text(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        string t = s.ToLowerInvariant();
        if (t.Contains("xbox") || t.Contains("360controller") || t.Contains("360works") || t.Contains("360amigo")) return false;
        return t.Contains("360") || t.Contains("qihoo") || t.Contains("奇虎") || t.Contains("鲁大师") || t.Contains("ludashi");
    }

    // 路径(安装目录/服务ImagePath/自启动值): 任一路径段命中即匹配
    private static bool Is360Path(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (string raw in s.Split('\\', '/'))
        {
            string seg = raw.Trim().Trim('"', ' ').ToLowerInvariant();
            if (seg.Length == 0) continue;
            if (seg == "360controller" || seg.StartsWith("360controller")) continue;
            if (seg == "360works" || seg.StartsWith("360works")) continue;
            if (seg == "360amigo" || seg.StartsWith("360amigo")) continue;
            if (seg.StartsWith("360") || seg.StartsWith("bapidrv") || seg.StartsWith("qutm")
                || seg == "qihoo" || seg == "ludashi" || seg == "鲁大师" || seg == "奇虎") return true;
        }
        return false;
    }

    // 目录名/注册表软件根键名
    private static bool Is360DirName(string s)
    {
        string t = (s ?? "").Trim().ToLowerInvariant();
        if (t.Length == 0) return false;
        if (t == "360controller" || t.StartsWith("360controller")) return false;
        if (t == "360works" || t.StartsWith("360works")) return false;
        if (t == "360amigo" || t.StartsWith("360amigo")) return false;
        return t.StartsWith("360") || t == "qihoo" || t == "ludashi" || t == "鲁大师" || t == "奇虎";
    }

    // 进程名
    private static bool Is360ProcessName(string name)
    {
        string t = (name ?? "").ToLowerInvariant();
        if (t.StartsWith("360") || t.StartsWith("qh")) return true;
        switch (t)
        {
            case "zhuodongfangyu":
            case "softmgr":
            case "seapp":
            case "computerz":
            case "ludashi":
            case "liveupdate":
            case "liveupdate360":
            case "deepscan":
                return true;
        }
        return false;
    }

    // 服务/驱动名
    private static bool Is360ServiceName(string name)
    {
        string t = (name ?? "").ToLowerInvariant();
        return t.StartsWith("360") || t.StartsWith("qh") || t.StartsWith("seapp")
            || t.StartsWith("bapidrv") || t.StartsWith("qutm");
    }

    // 驱动文件名(仅限 drivers 目录下使用)
    private static bool Is360DriverFile(string name)
    {
        string t = name.ToLowerInvariant();
        if (!t.EndsWith(".sys")) return false;
        string n = t.Substring(0, t.Length - 4);
        return n.StartsWith("360") || n.StartsWith("bapidrv") || n.StartsWith("qh") || n.StartsWith("qutm");
    }

    // ================= 扫描 =================

    private static void ScanAll(bool steps)
    {
        FindCount = 0;
        ScanMode = true;
        Say("");
        Say("---------------- 扫描开始 ----------------");
        if (steps) Say("[1/7] 检查 360 进程...");
        KillProcesses();
        if (steps) Say("[2/7] 检查服务与内核驱动...");
        CleanServices();
        if (steps) Say("[3/7] 检查计划任务...");
        CleanTasks();
        if (steps) Say("[4/7] 检查注册表残留...");
        CleanRegistry();
        if (steps) Say("[5/7] 检查目录与文件...");
        CleanFiles();
        if (steps) Say("[6/7] 检查防火墙规则...");
        CleanFirewall();
        ScanMode = false;
        Say("---------------- 扫描完成 ----------------");
        if (FindCount == 0) Say("未检测到任何 360 / Qihoo / 奇虎 系软件。");
        else Say("共检测到 " + FindCount + " 项(见上方 [找到] 行)。");
    }

    // ================= 清除 =================

    private static bool ConfirmRemove()
    {
        Say("");
        Say("【警告】将直接强制清除所有 360 / Qihoo / 奇虎 系软件(不经其自带卸载程序)。");
        Say("  1. 请先确认已在 360 设置中关闭「自我保护」(360安全卫士→设置→安全防护中心→自我保护),");
        Say("     否则其核心进程/文件会被内核驱动拦截, 需重启进安全模式再跑一次本工具。");
        Say("  2. 清除后请重启电脑, 完成被占用文件的最终删除。");
        Say("");
        Say("确认开始清除? (y/n)");
        string c = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
        return c == "y" || c == "yes";
    }

    private static void DoRemove()
    {
        Say(">> [1/8] 结束 360 进程...");
        KillProcesses();
        Say(">> [2/8] 停止并删除服务与驱动...");
        CleanServices();
        Say(">> [3/8] 删除计划任务...");
        CleanTasks();
        Say(">> [4/8] 清理注册表(卸载项/自启动/软件键/驱动残留)...");
        CleanRegistry();
        Say(">> [5/8] 删除安装目录与数据文件...");
        CleanFiles();
        Say(">> [6/8] 删除防火墙规则...");
        CleanFirewall();
        Say(">> [7/8] 清空残留父目录...");
        CleanEmptyParents();
        Say(">> [8/8] 复查...");
        ScanAll(false);
    }

    private static void KillProcesses()
    {
        int self = Process.GetCurrentProcess().Id;
        var reported = new HashSet<string>();
        for (int round = 0; round < 3; round++)
        {
            bool any = false;
            foreach (Process p in Process.GetProcesses())
            {
                if (p.Id == self || !Is360ProcessName(p.ProcessName)) continue;
                if (ScanMode) { Find("进程: " + p.ProcessName + " (PID " + p.Id + ")"); any = true; continue; }
                try
                {
                    p.Kill();
                    p.WaitForExit(3000);
                    Done.Add("进程: " + p.ProcessName + " (PID " + p.Id + ")");
                    Say("  [已杀] 进程: " + p.ProcessName);
                    any = true;
                }
                catch
                {
                    if (reported.Add(p.ProcessName))
                    {
                        Blocked.Add("进程: " + p.ProcessName + " (自我保护拦截)");
                        Say("  [拦截] 进程: " + p.ProcessName);
                    }
                }
            }
            if (!any) break;
            System.Threading.Thread.Sleep(1000);
        }
    }

    private static void CleanServices()
    {
        using (RegistryKey svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
        {
            if (svc == null) return;
            foreach (string name in svc.GetSubKeyNames())
            {
                string img = "";
                using (RegistryKey k = svc.OpenSubKey(name))
                    img = k == null ? "" : (k.GetValue("ImagePath") as string ?? "");
                if (!Is360ServiceName(name) && !Is360Path(img)) continue;
                if (ScanMode) { Find("服务/驱动: " + name + "  ->  " + img); continue; }
                RemoveService(name);
            }
        }
    }

    private static void RemoveService(string name)
    {
        bool isDriver = false;
        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
            isDriver = (int)(k == null ? 0 : (k.GetValue("Type") ?? 0)) == 1;
        string what = isDriver ? "驱动: " : "服务: ";

        Run("sc.exe", "stop \"" + name + "\"", 12);
        if (ServiceRunning(name))
        {
            // 运行中无法停止: sc delete 会将其标记为下次启动自动删除, 等 SCM 清理
            Run("sc.exe", "delete \"" + name + "\"", 12);
        }
        else
        {
            Run("sc.exe", "delete \"" + name + "\"", 12);
            try
            {
                using (RegistryKey svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", true))
                {
                    if (svc != null && svc.OpenSubKey(name) != null)
                        svc.DeleteSubKeyTree(name);
                }
            }
            catch { }
        }

        using (RegistryKey svc2 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
        {
            if (svc2 == null) return;
            using (RegistryKey k2 = svc2.OpenSubKey(name))
            {
                if (k2 == null)
                {
                    Done.Add(what + name);
                    Say("  [已删] " + what + name);
                    return;
                }
                if ((int)(k2.GetValue("DeleteFlag") ?? 0) == 1)
                {
                    Done.Add(what + name + " (已标记, 下次启动自动删除)");
                    Say("  [重启删] " + what + name + " (已标记, 下次启动自动删除)");
                    return;
                }
            }
        }
        // 兜底: 禁用其启动, 防止下次开机再次加载保护驱动
        Run("sc.exe", "config \"" + name + "\" start= disabled", 12);
        Blocked.Add(what + name + " (正在运行且无法停止/删除)");
        Say("  [拦截] " + what + name + " (正在运行且无法停止/删除)");
    }

    private static bool ServiceRunning(string name)
    {
        return Run("sc.exe", "query \"" + name + "\"", 10).ToLowerInvariant().Contains("running");
    }

    private static void CleanTasks()
    {
        var tasks = new List<string>();
        foreach (string line in Run("schtasks.exe", "/query /fo csv /nh", 60).Split('\n'))
        {
            Match m = Regex.Match(line, "^\"([^\"]*)\",\"([^\"]*)\"");
            if (!m.Success) continue;
            string t = m.Groups[2].Value;
            // 按路径段/进程名匹配: 系统任务名可能含 GUID(其中可能恰含 "360" 子串)
            if (Is360Path(t) || Is360ProcessName(Path.GetFileName(t))) tasks.Add(t);
        }
        foreach (string t in tasks)
        {
            if (ScanMode) { Find("计划任务: " + t); continue; }
            Run("schtasks.exe", "/end /tn \"" + t + "\" /f", 15);
            Run("schtasks.exe", "/delete /tn \"" + t + "\" /f", 15);
            Done.Add("计划任务: " + t);
            Say("  [已删] 计划任务: " + t);
        }
    }

    private static void CleanRegistry()
    {
        string[] uninstallRoots =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };
        foreach (string root in uninstallRoots) CleanUninstall(Registry.LocalMachine, root);
        CleanUninstall(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        CleanUninstall(Registry.CurrentUser, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
        CleanRunKeys();
        CleanAppPaths();
        CleanSoftKeys(Registry.LocalMachine, "SOFTWARE");
        CleanSoftKeys(Registry.LocalMachine, @"SOFTWARE\WOW6432Node");
        CleanSoftKeys(Registry.CurrentUser, "SOFTWARE");
        CleanLegacy();
    }

    private static void CleanUninstall(RegistryKey hive, string path)
    {
        using (RegistryKey root = hive.OpenSubKey(path, true))
        {
            if (root == null) return;
            foreach (string sub in root.GetSubKeyNames())
            {
                string dn = null, pub = null, loc = null;
                using (RegistryKey k = root.OpenSubKey(sub))
                {
                    if (k != null)
                    {
                        dn = k.GetValue("DisplayName") as string;
                        pub = k.GetValue("Publisher") as string;
                        loc = k.GetValue("InstallLocation") as string;
                    }
                }
                if (!Is360Text(dn) && !Is360Text(pub) && !Is360Path(loc)) continue;
                if (ScanMode) { Find("已安装软件: " + (dn ?? sub)); continue; }
                try
                {
                    root.DeleteSubKeyTree(sub);
                    Done.Add("卸载项: " + root.Name + "\\" + sub + "  (" + (dn ?? "") + ")");
                    Say("  [已删] 卸载项: " + (dn ?? sub));
                }
                catch
                {
                    Blocked.Add("卸载项: " + (dn ?? sub) + " (注册表被拦截)");
                    Say("  [拦截] 卸载项: " + (dn ?? sub));
                }
            }
        }
    }

    private static void CleanRunKeys()
    {
        CleanRunOne(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true));
        CleanRunOne(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", true));
        CleanRunOne(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true));
    }

    private static void CleanRunOne(RegistryKey k)
    {
        if (k == null) return;
        foreach (string name in k.GetValueNames())
        {
            string data = k.GetValue(name) as string;
            if (!Is360Path(data)) continue;
            if (ScanMode) { Find("自启动项: " + k.Name + "\\" + name); continue; }
            try
            {
                k.DeleteValue(name);
                Done.Add("自启动项: " + k.Name + "\\" + name);
                Say("  [已删] 自启动项: " + name);
            }
            catch
            {
                Blocked.Add("自启动项: " + k.Name + "\\" + name);
            }
        }
    }

    private static void CleanAppPaths()
    {
        string[] roots =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"
        };
        foreach (string root in roots)
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(root, true))
            {
                if (k == null) continue;
                foreach (string sub in k.GetSubKeyNames())
                {
                    string def = null;
                    using (RegistryKey s = k.OpenSubKey(sub))
                        def = s == null ? null : s.GetValue(null) as string;
                    if (!Is360Path(def)) continue;
                    if (ScanMode) { Find("App Paths: " + root + "\\" + sub); continue; }
                    try
                    {
                        k.DeleteSubKeyTree(sub);
                        Done.Add("App Paths: " + root + "\\" + sub);
                        Say("  [已删] App Paths: " + sub);
                    }
                    catch { Blocked.Add("App Paths: " + root + "\\" + sub); }
                }
            }
        }
    }

    private static void CleanSoftKeys(RegistryKey hive, string path)
    {
        using (RegistryKey root = hive.OpenSubKey(path, true))
        {
            if (root == null) return;
            foreach (string sub in root.GetSubKeyNames())
            {
                if (!Is360DirName(sub)) continue;
                if (ScanMode) { Find("注册表键: " + root.Name + "\\" + sub); continue; }
                try
                {
                    root.DeleteSubKeyTree(sub);
                    Done.Add("注册表键: " + root.Name + "\\" + sub);
                    Say("  [已删] 注册表键: " + root.Name + "\\" + sub);
                }
                catch
                {
                    Blocked.Add("注册表键: " + root.Name + "\\" + sub + " (被拦截)");
                    Say("  [拦截] 注册表键: " + root.Name + "\\" + sub);
                }
            }
        }
    }

    private static void CleanLegacy()
    {
        using (RegistryKey en = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\Root", true))
        {
            if (en == null) return;
            foreach (string sub in en.GetSubKeyNames())
            {
                if (!sub.ToLowerInvariant().StartsWith("legacy_")) continue;
                string name = sub.Substring(7);
                if (!Is360ServiceName(name)) continue;
                if (ScanMode) { Find("驱动枚举残留: Enum\\Root\\" + sub); continue; }
                try
                {
                    en.DeleteSubKeyTree(sub);
                    Done.Add("驱动枚举残留: Enum\\Root\\" + sub);
                    Say("  [已删] 驱动枚举残留: " + sub);
                }
                catch { Blocked.Add("驱动枚举残留: Enum\\Root\\" + sub); }
            }
        }
    }

    // ================= 文件删除 =================

    private static void CleanFiles()
    {
        var roots = new List<string>();
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        roots.Add(pd);
        roots.Add(Path.Combine(pd, "Microsoft", "Windows", "Start Menu", "Programs"));
        foreach (string user in SafeGetDirs("C:\\Users"))
        {
            string n = Path.GetFileName(user).ToLowerInvariant();
            if (n == "default" || n == "defaultuser0" || n == "public" || n == "all users") continue;
            roots.Add(Path.Combine(user, "AppData", "Roaming"));
            roots.Add(Path.Combine(user, "AppData", "Local"));
            roots.Add(Path.Combine(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"));
        }
        foreach (string root in roots) CleanRoot(root);
        string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
        CleanDriverFiles(Path.Combine(sys, "drivers"));
        CleanDriverFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "drivers"));
    }

    private static void CleanRoot(string root)
    {
        if (!Directory.Exists(root)) return;
        bool isStartMenu = root.EndsWith("Start Menu\\Programs", StringComparison.OrdinalIgnoreCase);
        foreach (string dir in SafeGetDirs(root))
        {
            if (!Is360DirName(Path.GetFileName(dir))) continue;
            if (ScanMode) { Find("目录: " + dir); continue; }
            RemoveDirTree(dir);
        }
        if (isStartMenu)
        {
            foreach (string f in SafeGetFiles(root, "*.lnk"))
            {
                string n = Path.GetFileName(f).ToLowerInvariant();
                if (!(n.StartsWith("360") || n.Contains("qihoo") || n.Contains("鲁大师") || n.Contains("ludashi"))) continue;
                if (ScanMode) { Find("快捷方式: " + f); continue; }
                TryDeleteFile(f);
            }
        }
    }

    private static void CleanDriverFiles(string dir)
    {
        if (!Directory.Exists(dir)) return;
        foreach (string f in SafeGetFiles(dir, "*.sys"))
        {
            if (!Is360DriverFile(Path.GetFileName(f))) continue;
            if (ScanMode) { Find("驱动文件: " + f); continue; }
            TryDeleteFile(f);
        }
    }

    private static void RemoveDirTree(string dir)
    {
        foreach (string f in SafeGetFiles(dir)) TryDeleteFile(f);
        foreach (string d in SafeGetDirs(dir)) RemoveDirTree(d);
        if (TryDeleteDir(dir, true))
            Parents.Add(Path.GetDirectoryName(dir));
    }

    private static bool TryDeleteFile(string path)
    {
        try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
        try
        {
            File.Delete(path);
            FileCount++;
            Log.WriteLine("  [已删] 文件: " + path);
            return true;
        }
        catch { }
        // 被占用/被保护 → 登记重启后删除
        if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
        {
            Pending.Add(path);
            Log.WriteLine("  [重启删] 文件: " + path);
            return false;
        }
        Blocked.Add("文件: " + path);
        Log.WriteLine("  [拦截] 文件: " + path);
        return false;
    }

    private static bool TryDeleteDir(string dir, bool report)
    {
        if (!Directory.Exists(dir)) return false;
        try { File.SetAttributes(dir, FileAttributes.Normal); } catch { }
        try { Directory.Delete(dir, false); }
        catch { }
        if (!Directory.Exists(dir))
        {
            if (report) { Done.Add("目录: " + dir); Say("  [已删] 目录: " + dir); }
            return true;
        }
        // 仍存在: 若已空则登记重启删除, 否则说明内部有文件被拦截
        bool empty = false;
        try { empty = SafeGetFiles(dir).Length == 0 && SafeGetDirs(dir).Length == 0; } catch { }
        if (empty)
        {
            if (MoveFileEx(dir, null, MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                Pending.Add(dir);
                if (report) Say("  [重启删] 目录: " + dir);
            }
            else if (report) { Blocked.Add("目录: " + dir); Say("  [拦截] 目录: " + dir); }
        }
        else if (report)
        {
            Blocked.Add("目录: " + dir + " (内含被拦截文件)");
            Say("  [拦截] 目录: " + dir + " (内含被拦截文件)");
        }
        return false;
    }

    private static void CleanEmptyParents()
    {
        foreach (string p in Parents)
        {
            if (p == null || !Is360DirName(Path.GetFileName(p))) continue;
            TryDeleteDir(p, true);
        }
    }

    private static void CleanFirewall()
    {
        // 防火墙规则的持久化存储就在注册表: 值名即规则名, 直接删值即删规则
        // (比 netsh 快, 且安全模式里 BFE 服务未启动也能删)
        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", true))
        {
            if (k == null) return;
            foreach (string name in k.GetValueNames())
            {
                string data = k.GetValue(name) as string ?? "";
                if (!Is360FirewallRule(name, data)) continue;
                if (ScanMode) { Find("防火墙规则: " + name); continue; }
                try
                {
                    k.DeleteValue(name);
                    Done.Add("防火墙规则: " + name);
                    Say("  [已删] 防火墙规则: " + name);
                }
                catch { Blocked.Add("防火墙规则: " + name); }
            }
        }
    }

    // 部分规则的值名是 GUID(其中可能恰好含 "360" 子串, 如 7C5F4360...),
    // 这类规则的真实名称/程序路径在值数据里, 只从 Name=/App= 字段判断
    private static bool Is360FirewallRule(string valueName, string data)
    {
        if (Regex.IsMatch(valueName, @"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$"))
        {
            foreach (string tok in data.Split('|'))
            {
                if (tok.StartsWith("Name=") && Is360Text(tok.Substring(5))) return true;
                if (tok.StartsWith("App=") && Is360Path(tok.Substring(4))) return true;
            }
            return false;
        }
        return Is360Text(valueName);
    }

    // ================= 自我保护自动处理 =================
    // 自我保护是 360 的内核驱动(进程/文件/注册表回调), 用户态管理员权限也绕不过。
    // 自动处理思路: 让保护驱动下次启动时不再加载, 重启后补刀 ——
    //   1) 重启后自动继续: 驱动文件登记开机前删除(smss 在任何驱动加载前处理) + 禁用服务 + RunOnce 自动补刀
    //   2) 安全模式: 安全模式下 360 驱动不加载, 保护必然失效, 清完后自动恢复正常启动

    private static void OfferAutoCleanup()
    {
        if (Blocked.Count == 0) return;
        Say("");
        Say("有 " + Blocked.Count + " 项被自我保护拦截, 可选自动处理(无需手动关闭自我保护):");
        Say("[1] 重启后自动继续清理 (推荐, 重启 1 次)");
        Say("[2] 安全模式自动清理 (最彻底, 自动重启 2 次)");
        Say("[0] 跳过 (之后手动处理)");
        string c = (Console.ReadLine() ?? "").Trim();
        if (c == "1") SetupBootCleanup();
        else if (c == "2") SetupSafeMode();
    }

    private static void SetupBootCleanup()
    {
        DisableRemainingServices();
        SetRunOnce("360Kick", "--cleanup-at-boot");
        Say("已设置: 下次登录 Windows 时自动继续清理(此时保护驱动已不加载)。");
        // 校验: 待重启删除的登记是否真正写入系统 —— 若这一步被 360 拦截, 此路不通, 应改走安全模式
        if (Pending.Count > 0 && !PendingRenameRegistered())
            Say("【注意】待重启删除登记未写入系统(可能被拦截), 此方案可能无效, 建议改用安全模式方案(选 [2])。");
        AskReboot();
    }

    private static bool PendingRenameRegistered()
    {
        try
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
            {
                if (k == null) return false;
                object raw = k.GetValue("PendingFileRenameOperations");
                string v = raw as string;
                if (v == null && raw is string[]) v = string.Join("\0", (string[])raw);
                if (string.IsNullOrEmpty(v)) return false;
                v = v.ToLowerInvariant();
                foreach (string p in Pending)
                    if (v.Contains(Path.GetFileName(p).ToLowerInvariant())) return true;
                return false;
            }
        }
        catch { return false; }
    }

    private static void SetupSafeMode()
    {
        Run("bcdedit.exe", "/set {current} safeboot minimal", 15);
        SetRunOnce("*360Kick", "--safemode-cleanup");
        Say("已设置: 重启后进入安全模式(360 保护驱动不加载)自动清理, 完成后自动重启回正常模式收尾。");
        AskReboot();
    }

    private static void AskReboot()
    {
        Say("是否立即重启? (y/n)");
        string c = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
        if (c == "y" || c == "yes") Run("shutdown.exe", "/r /t 5", 10);
        else Say("请稍后手动重启(重启后才生效)。");
    }

    private static void DisableRemainingServices()
    {
        using (RegistryKey svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
        {
            if (svc == null) return;
            foreach (string name in svc.GetSubKeyNames())
            {
                string img = "";
                using (RegistryKey k = svc.OpenSubKey(name))
                    img = k == null ? "" : (k.GetValue("ImagePath") as string ?? "");
                if (!Is360ServiceName(name) && !Is360Path(img)) continue;
                Run("sc.exe", "config \"" + name + "\" start= disabled", 10);
                Say("  [禁用] 服务/驱动: " + name);
            }
        }
    }

    private static void SetRunOnce(string valueName, string arg)
    {
        string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", true))
        {
            if (k != null) k.SetValue(valueName, "\"" + exe + "\" " + arg);
        }
    }

    private static void ClearRunOnce()
    {
        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", true))
        {
            if (k == null) return;
            try { k.DeleteValue("360Kick", false); } catch { }
            try { k.DeleteValue("*360Kick", false); } catch { }
        }
    }

    // ================= 结果汇总 =================

    private static void PrintSummary()
    {
        Say("");
        Say("================ 清除结果 ================");
        Say("主要项已删除: " + Done.Count + " 项");
        Say("文件已删除:   " + FileCount + " 个");
        Say("待重启删除:   " + Pending.Count + " 项 (重启后自动删除)");
        if (Pending.Count > 0)
        {
            int n = 0;
            foreach (string p in Pending) { if (n++ >= 30) { Say("  ... (其余见日志)"); break; } Say("  - " + p); }
        }
        if (Blocked.Count > 0)
        {
            Say("被拦截:       " + Blocked.Count + " 项 (360 自我保护未关闭):");
            int n = 0;
            foreach (string b in Blocked) { if (n++ >= 30) { Say("  ... (其余见日志)"); break; } Say("  - " + b); }
            Say("请关闭 360 自我保护后重跑本工具, 或重启进入安全模式后再跑一次。");
        }
        if (FindCount > 0)
            Say("复查仍检测到 " + FindCount + " 项, 其中「待重启删除」的文件重启后消失。");
        Say("日志已写入: " + Path.Combine(Path.GetTempPath(), "360Kick.log"));
        Say("请重启电脑完成清理, 重启后再运行 360Kick.exe scan 验证是否干净。");
    }
}
