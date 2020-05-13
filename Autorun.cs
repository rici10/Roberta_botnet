using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace CodeDome_roberta
{
   public static class Autorun
    {
        static readonly string ExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        public static readonly string DefaultPath = Environment.GetEnvironmentVariable("Temp");
        public static string dir = DefaultPath + "\\" + GetHwid();
        public static string GetHwid() // Works
        {
            string HoldingAdress = "";
            try
            {
                string drive = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1);
                ManagementObject disk = new ManagementObject("win32_logicaldisk.deviceid=\"" + drive + ":\"");
                disk.Get();
                string diskLetter = (disk["VolumeSerialNumber"].ToString());
                HoldingAdress = diskLetter;

            }
            catch (Exception)
            {

            }
            return HoldingAdress;
        }
        public static bool IsAdmin()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            return isElevated;
        }

        public static bool CheckAutorun(bool User, string regedit_name)
        {

            using (RegistryKey Key = User ? Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\")
                : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\")) //Тернарный оператор
                if (Key != null)
                {
                    //string val = Key.GetValue("COMODO Internet Security");
                    if (Key.GetValue(regedit_name) == null)
                    {
                        return false;
                    }
                }
            return true;
        }
        public static void FullCheck()
        {
            if (IsAdmin()) //TODO записать в один метод (ты должен понять)
            {
                if (!CheckAutorun(false, "Roberta"))
                {
                    SetAutorunValue(true, false, "Roberta");
                }
                //Scheduler.SetAutorunValue(true, false, "Roberta");
            }
            else
            {
                if (!CheckAutorun(true, "Roberta"))
                {
                    SetAutorunValue(true, true, "Roberta", dir + "\\Roberta.exe");
                }
            }
        }

        public static bool SetAutorunValue(bool autorun, bool User, string name)
        {

            RegistryKey reg;

            reg = User ? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\")
                : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\");
            try
            {
                if (autorun)
                    reg.SetValue("Roberta", ExePath);
                else
                    reg.DeleteValue("Roberta");

                reg.Close();
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static void SetAutorunValue(bool autorun, bool User, string name, string path)
        {
            RegistryKey reg;


            reg = User ? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\")
                : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\");
            try
            {
                if (autorun)
                    reg.SetValue("Roberta", path);
                else
                    reg.DeleteValue("Roberta");

                reg.Close();
            }
            catch
            {

            }
        }
    }
}
