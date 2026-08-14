using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace OmniProxyGui;

public partial class App : Application
{
    public static Window? MainWindow { get; private set; }

    public App()
    {
        InitializeComponent();
        // 未处理异常写崩溃日志（unpackaged 无控制台，便于定位）
        UnhandledException += (_, e) =>
        {
            try
            {
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, ".gui-crash.log"),
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n{e.Exception}");
            }
            catch { }
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindow = new MainWindow();
        MainWindow.Activate();
    }
}
