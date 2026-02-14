using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Text;

namespace DarpaInjector.UI
{
    public class MainForm : Form
    {
        private ListBox processListBox;
        private TextBox searchBox;
        private Button refreshButton;
        
        private TextBox dllPathBox;
        private Button browseButton;
        
        private ComboBox methodComboBox;
        private Button injectButton;
        
        private RichTextBox logBox;
        
        private List<ProcessInfo> allProcesses = new List<ProcessInfo>();

        public MainForm()
        {
            InitializeComponent();
            RefreshProcesses();
        }

        private void InitializeComponent()
        {
            this.Text = "Darpa Injector - Advanced Hybrid Injector";
            this.Size = new Size(900, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(30, 30, 30);
            this.ForeColor = Color.White;

            // Layout containers
            var splitContainer = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                SplitterDistance = 300,
                BackColor = Color.FromArgb(45, 45, 48)
            };
            this.Controls.Add(splitContainer);

            // Left Panel (Process Selection)
            var leftPanel = splitContainer.Panel1;
            
            var searchLabel = new Label { Text = "Search Process:", Top = 10, Left = 10, AutoSize = true, ForeColor = Color.LightGray };
            leftPanel.Controls.Add(searchLabel);

            searchBox = new TextBox { Top = 30, Left = 10, Width = 200, BackColor = Color.FromArgb(60, 60, 60), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            searchBox.TextChanged += (s, e) => FilterProcesses();
            leftPanel.Controls.Add(searchBox);

            refreshButton = new Button { Text = "Refresh", Top = 28, Left = 220, Width = 60, Height = 23, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(0, 122, 204), ForeColor = Color.White };
            refreshButton.Click += (s, e) => RefreshProcesses();
            leftPanel.Controls.Add(refreshButton);

            processListBox = new ListBox { Top = 60, Left = 10, Width = 270, Height = 480, BackColor = Color.FromArgb(40, 40, 42), ForeColor = Color.Lime, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9) };
            leftPanel.Controls.Add(processListBox);

            // Right Panel (Injection Controls & Logs)
            var rightPanel = splitContainer.Panel2;

            var dllLabel = new Label { Text = "Target DLL:", Top = 10, Left = 10, AutoSize = true, ForeColor = Color.LightGray };
            rightPanel.Controls.Add(dllLabel);
            
            // Stealth Checkbox
            var stealthCheck = new CheckBox { Text = "Stealth Mode (Erase Headers / Unlink Module)", Top = 125, Left = 10, AutoSize = true, ForeColor = Color.Cyan, Checked = true };
            rightPanel.Controls.Add(stealthCheck);

            dllPathBox = new TextBox { Top = 30, Left = 10, Width = 400, ReadOnly = true, BackColor = Color.FromArgb(60, 60, 60), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            rightPanel.Controls.Add(dllPathBox);

            browseButton = new Button { Text = "Browse...", Top = 28, Left = 420, Width = 80, Height = 23, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(60, 60, 60), ForeColor = Color.White };
            browseButton.Click += BrowseButton_Click;
            rightPanel.Controls.Add(browseButton);

            var methodLabel = new Label { Text = "Injection Method:", Top = 70, Left = 10, AutoSize = true, ForeColor = Color.LightGray };
            rightPanel.Controls.Add(methodLabel);

            methodComboBox = new ComboBox { Top = 90, Left = 10, Width = 200, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Color.FromArgb(60, 60, 60), ForeColor = Color.White };
            methodComboBox.Items.AddRange(new string[] { "LoadLibrary", "Manual Map (Reflective)", "Thread Hijack", "Module Stomping", "APC Injection" });
            methodComboBox.SelectedIndex = 0;
            rightPanel.Controls.Add(methodComboBox);

            injectButton = new Button { Text = "INJECT", Top = 90, Left = 230, Width = 150, Height = 30, FlatStyle = FlatStyle.Flat, BackColor = Color.Crimson, ForeColor = Color.White, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
            injectButton.Click += InjectButton_Click;
            rightPanel.Controls.Add(injectButton);

            var logLabel = new Label { Text = "Logs:", Top = 140, Left = 10, AutoSize = true, ForeColor = Color.LightGray };
            rightPanel.Controls.Add(logLabel);

            logBox = new RichTextBox { Top = 160, Left = 10, Width = 550, Height = 380, ReadOnly = true, BackColor = Color.Black, ForeColor = Color.Lime, Font = new Font("Consolas", 9), BorderStyle = BorderStyle.None };
            rightPanel.Controls.Add(logBox);
        }

        private void RefreshProcesses()
        {
            allProcesses = ProcessSelector.GetRunningProcesses();
            FilterProcesses();
            Log("Process list refreshed.");
        }

        private void FilterProcesses()
        {
            processListBox.Items.Clear();
            var filter = searchBox.Text.ToLower();
            foreach (var p in allProcesses)
            {
                if (p.Name.ToLower().Contains(filter) || p.Id.ToString().Contains(filter) || (p.CustomTitle != null && p.CustomTitle.ToLower().Contains(filter)))
                {
                    processListBox.Items.Add(p); // Uses ToString()
                }
            }
        }

        private void BrowseButton_Click(object? sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = "DLL Files (*.dll)|*.dll|All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    dllPathBox.Text = ofd.FileName;
                    Log($"Selected DLL: {ofd.FileName}");
                }
            }
        }

        private void InjectButton_Click(object? sender, EventArgs e)
        {
            if (processListBox.SelectedItem is not ProcessInfo selectedProcess)
            {
                MessageBox.Show("Please select a target process first.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (string.IsNullOrEmpty(dllPathBox.Text) || !File.Exists(dllPathBox.Text))
            {
                MessageBox.Show("Please select a valid DLL file.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            int method = methodComboBox.SelectedIndex;
            Log($"Attempting injection into {selectedProcess.Name} ({selectedProcess.Id}) using method {methodComboBox.SelectedItem}...");

            try
            {
                // Ensure privileges are enabled
                // InjectorBinding.EnablePrivileges(); // Already called in DLL or should be called here
                
                // For safety in this demo, let's call it via P/Invoke if exposed or assume DLL handles it
                // Our C++ Core.cpp calls it inside InjectRemote, so we are good.

                bool result = InjectorBinding.InjectRemote(selectedProcess.Id, dllPathBox.Text, method);
                
                StringBuilder sb = new StringBuilder(8192);
                InjectorBinding.GetDebugLog(sb, 8192);
                string coreLogs = sb.ToString();
                if (!string.IsNullOrWhiteSpace(coreLogs))
                {
                    Log("\n[CORE DEBUG LOGS]");
                    Log(coreLogs.Trim());
                    Log("[END CORE LOGS]\n");
                }
                
                if (result)
                {
                    Log("Injection SUCCESSFUL!");
                    MessageBox.Show("Injection Successful!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    Log("Injection FAILED.");
                    MessageBox.Show("Injection Failed. check logs or debugger.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                Log($"Error during injection: {ex.Message}");
                MessageBox.Show($"Error: {ex.Message}", "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Log(string message)
        {
            if (logBox.IsDisposed) return;
            logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            logBox.ScrollToCaret();
        }
    }
}
