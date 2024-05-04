using System;
using System.IO;
using System.Security.Cryptography;
using System.Data.SQLite;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;

namespace Antivirus
{
    public class Program
    {
        static SQLiteConnection db;
        static FileSystemWatcher fileSystemWatcher;
        static Form form;
        static TextBox textBox;

        [STAThread]
        static void Main(string[] args)
        {
            // Create a new form
            form = new Form();
            form.Text = "Antivirus";
            form.Width = 400;
            form.Height = 300;

            // Create a text box to display messages
            textBox = new TextBox();
            textBox.Multiline = true;
            textBox.ScrollBars = ScrollBars.Vertical;
            textBox.Dock = DockStyle.Fill;
            form.Controls.Add(textBox);

            // Initialize the malware signature database
            db = new SQLiteConnection("Data Source=malware_signatures.db");
            db.Open();

            // Initialize the file system watcher for real-time protection
            fileSystemWatcher = new FileSystemWatcher(@"C:\", "*.*");
            fileSystemWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName;
            fileSystemWatcher.Created += FileSystemWatcher_Created;
            fileSystemWatcher.Renamed += FileSystemWatcher_Renamed;
            fileSystemWatcher.Deleted += FileSystemWatcher_Deleted;
            fileSystemWatcher.EnableRaisingEvents = true;

            // Scan the file system
            ScanFileSystem(@"C:\");

            // Show the form
            Application.Run(form);
        }

        static void ScanFileSystem(string rootDirectory)
        {
            try
            {
                // Iterate through files and directories
                foreach (string file in Directory.GetFiles(rootDirectory))
                {
                    // Calculate the file hash
                    string fileHash = CalculateFileHash(file);

                    // Check the file hash against the malware signature database
                    if (IsMalware(fileHash, db))
                    {
                        textBox.AppendText($"Malware detected: {file}\r\n");
                    }
                    else
                    {
                        // Submit the file to VirusTotal for analysis
                        SubmitToVirusTotal(file);
                    }
                }

                // Recursively scan subdirectories
                foreach (string subdirectory in Directory.GetDirectories(rootDirectory))
                {
                    ScanFileSystem(subdirectory);
                }
            }
            catch (Exception ex)
            {
                textBox.AppendText($"Error: {ex.Message}\r\n");
            }
        }

        static string CalculateFileHash(string file)
        {
            try
            {
                // Use SHA-256 to calculate the file hash
                using (SHA256 sha256 = SHA256.Create())
                {
                    using (FileStream fileStream = File.OpenRead(file))
                    {
                        byte[] fileBytes = new byte[fileStream.Length];
                        fileStream.Read(fileBytes, 0, fileBytes.Length);
                        byte[] hashBytes = sha256.ComputeHash(fileBytes);
                        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    }
                }
            }
            catch (Exception ex)
            {
                textBox.AppendText($"Error: {ex.Message}\r\n");
                return null;
            }
        }

        static bool IsMalware(string fileHash, SQLiteConnection db)
        {
            try
            {
                // Query the malware signature database
                SQLiteCommand command = new SQLiteCommand("SELECT 1 FROM malware_signatures WHERE hash = @hash", db);
                command.Parameters.AddWithValue("@hash", fileHash);
                object result = command.ExecuteScalar();
                return result!= null;
            }
            catch (Exception ex)
            {
                textBox.AppendText($"Error: {ex.Message}\r\n");
                return false;
            }
        }

        static void SubmitToVirusTotal(string file)
        {
            try
            {
                // Use the VirusTotal API to submit the file for analysis
                string apiKey = "YOUR_VIRUSTOTAL_API_KEY";
                string apiUrl = "https://www.virustotal.com/api/v3/files";
                string response = "";

                using (WebClient webClient = new WebClient())
                {
                    webClient.Headers.Add("x-apikey", apiKey);
                    webClient.UploadFile(apiUrl, file);
                    response = webClient.DownloadString(apiUrl);
                }

                // Parse the response and check for malware detection
                dynamic jsonData = JsonConvert.DeserializeObject(response);
                if (jsonData.data.attributes.last_analysis_stats.malicious > 0)
                {
                    textBox.AppendText($"Malware detected by VirusTotal: {file}\r\n");
                }
            }
            catch (Exception ex)
            {
                textBox.AppendText($"Error: {ex.Message}\r\n");
            }
        }

        static void FileSystemWatcher_Created(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Real-time protection: scan the newly created file
                string fileHash = CalculateFileHash(e.FullPath);
                if (IsMalware(fileHash, db))
                {
                    textBox.AppendText($"Malware detected: {e.FullPath}\r\n");
                }
                else
                {
                    SubmitToVirusTotal(e.FullPath);
                }
            }
            catch (Exception ex)
            {
                textBox.AppendText($"Error: {ex.Message}\r\n");
            }
        }
    }
}
