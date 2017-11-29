using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EvilDll
{
    public class ServerInterface : MarshalByRefObject
    {
        private int startTime;
        public void IsInstalled(int clientPID)
        {
            Console.WriteLine("Successfully injected into process {0}.\r\n", clientPID);
            startTime = Environment.TickCount;
        }

        public void ReportMessages(string[] messages)
        {
            for (int i = 0; i < messages.Length; i++)
            {

                Console.WriteLine($"Time {(Environment.TickCount - startTime) / 1000}.{(Environment.TickCount - startTime) % 1000:000} {messages[i]}");
            }
        }

        public void ReportMessage(string message)
        {
            Console.WriteLine(message);
        }

        public void ReportException(Exception e)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + e.ToString());
        }

        int count = 0;
        public void Ping()
        {
            // Output token animation to visualise Ping
            var oldTop = Console.CursorTop;
            var oldLeft = Console.CursorLeft;
            Console.CursorVisible = false;

            var chars = "\\|/-";
            Console.SetCursorPosition(Console.WindowWidth - 1, oldTop - 1);
            Console.Write(chars[count++ % chars.Length]);

            Console.SetCursorPosition(oldLeft, oldTop);
            Console.CursorVisible = true;
        }
    }
}
