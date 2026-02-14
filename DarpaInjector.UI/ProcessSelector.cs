using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;

namespace DarpaInjector.UI
{
    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string CustomTitle { get; set; } = "";

        public override string ToString()
        {
            return $"{Name} ({Id}) - {CustomTitle}";
        }
    }

    public static class ProcessSelector
    {
        public static List<ProcessInfo> GetRunningProcesses()
        {
            var list = new List<ProcessInfo>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    list.Add(new ProcessInfo
                    {
                        Id = p.Id,
                        Name = p.ProcessName,
                        CustomTitle = p.MainWindowTitle
                    });
                }
                catch { }
            }
            return list.OrderBy(x => x.Name).ToList();
        }
    }
}
