using Microsoft.Win32;
using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Messaging;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SRWatcher
{
    class PowerShellWatcher
    {
        private class LogData
        {
            public int ExerciseId { get; set; }
            public string UserName { get; set; }
            public string CommandOutput { get; set; }
        }


        private static JavaScriptSerializer serializer = new JavaScriptSerializer();
        private static HttpClient client = new HttpClient();
        private static int ExerciseId { get; set; }
        private static string UserName { get; set; }

        // Remote object.
        public class VarSetter : MarshalByRefObject
        {
            private int callCount = 0;

            public int setVars(string usr, int exId)
            {
                UserName = usr;
                ExerciseId = exId;
                callCount++;
                return (callCount);
            }
        }


        private static string Folder;

        private static FileSystemWatcher watcher;
        private static bool ParseRegValues ()
        {
            var Processes = new ManagementObjectSearcher("SELECT * FROM Win32_Process WHERE name ='explorer.exe'").Get();

            string[] ownerSID = new string[1];
            string[] ownerName = new string[1];
            foreach (ManagementObject proc in Processes)
            {
                proc.InvokeMethod("GetOwnerSid", ownerSID);
                proc.InvokeMethod("GetOwner", ownerName);
            }



            var clientNameString = "EMPTY";
            using (var key = Registry.Users.OpenSubKey(ownerSID[0] + "\\Volatile Environment"))
            {
                var sessions = key.GetSubKeyNames();

                foreach (var session in sessions)
                {
                    if (key.OpenSubKey(session).GetValue("SESSIONNAME").ToString().ToLower().Contains("rdp"))
                    {
                        clientNameString = key.OpenSubKey(session).GetValue("CLIENTNAME").ToString();
                        break;
                    }
                }
            }

            if (clientNameString == "EMPTY")
            {
                return false;
            }

            var argsArray = clientNameString.Split(' ');

            UserName = argsArray[1];

            ExerciseId = int.Parse(argsArray[0]);

            Folder = "C:\\Users\\"+ ownerName[0] + "\\Appdata\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\";

            watcher = new FileSystemWatcher(Folder, "ConsoleHost_history.txt")
                    {
                        NotifyFilter = NotifyFilters.LastWrite,
                        IncludeSubdirectories = false
                    };

            return true;
        }

        private async static void OnChanged(object source, FileSystemEventArgs e)
        {

            var cmd = File.ReadLines(e.FullPath).Last();

            var postData = new LogData
            {
                ExerciseId = ExerciseId,
                UserName = UserName,
                CommandOutput = cmd
            };
            try
            {
                await SendData(postData);
            }
            catch (Exception a)
            {
                Console.WriteLine(a.Message);
            }
        }

        private static async Task<bool> SendData(LogData data)
        {
            HttpResponseMessage response = await client.PostAsJsonAsync("api/LogData", data);
            response.EnsureSuccessStatusCode();

            //Console.Write(response.IsSuccessStatusCode.ToString());

            return response.IsSuccessStatusCode;
        }


        private static async Task OpenIPCAsync()
        {

            IDictionary properties = new Hashtable();

            // Get SID code for the EveryOne user
            SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            // Get the NT account related to the SID
            NTAccount account = sid.Translate(typeof(NTAccount)) as NTAccount;

            // Put the account locale name to the properties
            properties.Add("authorizedGroup", account.Value);
            properties.Add("portName", "localhost:1337");

            // Create the server channel.

            IpcServerChannel serverChannel = new IpcServerChannel(properties, null);
            
           
            // Register the server channel.
            ChannelServices.RegisterChannel(serverChannel, false);

            // Expose an object for remote calls.
            RemotingConfiguration.RegisterWellKnownServiceType(typeof(VarSetter), "SRUserInfo.rem", WellKnownObjectMode.Singleton);
            

        }

        static int Main()
        {

            // get application GUID as defined in AssemblyInfo.cs
            var appGuid = ((GuidAttribute)Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(GuidAttribute), false).GetValue(0)).Value.ToString();

            // unique id for global mutex - Global prefix means it is global to the machine
            var mutexId = string.Format("Global\\{{{0}}}", appGuid);

            var allowEveryoneRule = new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), MutexRights.FullControl, AccessControlType.Allow);

            var securitySettings = new MutexSecurity();

            securitySettings.AddAccessRule(allowEveryoneRule);

            // edited by MasonGZhwiti to prevent race condition on security settings via VanNguyen
            var mutex = new Mutex(false, mutexId, out bool createdNew, securitySettings);

            if (!createdNew)
            {

                var setVals = ParseRegValues();

                if (!setVals)
                    return 0;


                    // Create the channel.
                IpcChannel channel = new IpcChannel();

                // Register the channel.
                ChannelServices.RegisterChannel(channel, false);

                // Register as client for remote object.
                WellKnownClientTypeEntry remoteType = new WellKnownClientTypeEntry(typeof(VarSetter), "ipc://localhost:1337/SRUserInfo.rem");

                RemotingConfiguration.RegisterWellKnownClientType(remoteType);

                // Create a message sink.
                IMessageSink messageSink = channel.CreateMessageSink("ipc://localhost:1337/SRUserInfo.rem", null, out string objectUri);

                // Create an instance of the remote object.
                VarSetter service = new VarSetter();

                service.setVars(UserName,ExerciseId);

                return 0;
            }


            var hasHandle = false;
            try
            {
                try
                {
                    hasHandle = mutex.WaitOne(5000, false);
                    if (hasHandle == false)
                        throw new TimeoutException();
                }
                catch (AbandonedMutexException)
                {
                    // the mutex was abandoned in another process,
                    // it will still get acquired
                    hasHandle = true;
                }

                var setVals = ParseRegValues();

                if (!setVals)
                    return 0;

                OpenIPCAsync();

                Run();
            }
            finally
            {
                if (hasHandle)
                {
                    mutex.ReleaseMutex();
                    mutex.Dispose();
                }
            }

            return 0;
        }

        private static void Run()
        {
            client.BaseAddress = new Uri("http://srlogger.net");
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            watcher.Changed += new FileSystemEventHandler(OnChanged);

            watcher.EnableRaisingEvents = true;

            while (Console.ReadLine() != "q");

        }
    }
}
