using System;
using System.IO;
using System.Threading;
using Microsoft.UI.Dispatching;

namespace OmniProxyGui;

public static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        try
        {
            WinRT.ComWrappersSupport.InitializeComWrappers();
            Microsoft.UI.Xaml.Application.Start(p =>
            {
                var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
                SynchronizationContext.SetSynchronizationContext(context);
                _ = new App();
            });
        }
        catch (Exception ex)
        {
            try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, ".gui-crash.log"), ex.ToString()); } catch { }
            throw;
        }
    }
}
