using System;
using System.Diagnostics;
using System.IO;
using System.Linq;


namespace gdbSniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            Int32 targetPID = 0;
            string targetExe = null;

            string channelName = null;
            ProcessArgs(args, out targetPID, out targetExe);

            if (targetPID <= 0 && string.IsNullOrEmpty(targetExe))
                return;
            EasyHook.RemoteHooking.IpcCreateServer<EvilDll.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "EvilDll.dll");

            try
            {
                // Injecting into existing process by Id
                if (targetPID > 0)
                {
                    Console.WriteLine("Attempting to inject into process {0}", targetPID);
                    // inject into existing process
                    EasyHook.RemoteHooking.Inject(targetPID, injectionLibrary, injectionLibrary, channelName );
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("There was an error while injecting into target:");
                Console.ResetColor();
                Console.WriteLine(e.ToString());
            }
            Console.ReadKey();

        }

        static void ProcessArgs(string[] args, out int targetPID, out string targetExe)
        {
            targetPID = 0;
            targetExe = null;

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Sniffer for gdb.exe");
            Console.WriteLine();
            Console.ResetColor();

            Process[] targetProc = Process.GetProcessesByName("gdb");
            if (targetProc.Length == 0)
            {
                Console.WriteLine("It seems, there is no any gdb process in the system.");
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("<Press any key to exit>");
                Console.ResetColor();
                Console.ReadKey();
            }
            if (targetProc.Length == 1)
            {
                targetPID = targetProc.First().Id;  //getting pid of first gdb.exe and ignoring all others
                Console.WriteLine("I smell some gdb.exe with PID = {0}", targetProc.First().Id);
            }

        }
    }
}
