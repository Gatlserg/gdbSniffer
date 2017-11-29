using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace EvilDll
{
    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {
        ServerInterface _server = null;
        Queue<string> _messageQueue = new Queue<string>();

        public InjectionEntryPoint(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            // Connect to server object using provided channel name
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);
            // If Ping fails then the Run method will be not be called
            _server.Ping();
        }

        public void Run(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());

            var sendHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ws2_32.dll", "send"),
                new Send_Delegate(send_Hook), this);
            var recvHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ws2_32.dll", "recv"),
                new recv_Delegate(recv_Hook), this);

            sendHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            recvHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("Hooks installed");

            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }
                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }
            sendHook.Dispose();
            recvHook.Dispose();

            EasyHook.LocalHook.Release();
        }


        #region Send hook
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

        delegate int Send_Delegate(IntPtr Socket, IntPtr buff, int len, int flags);

        [DllImport("ws2_32.dll")]
        static extern int send(IntPtr Socket, IntPtr buff, int len, int flags);

        int send_Hook(IntPtr Socket, IntPtr buff, int len, int flags)
        {
            int result = 0;

            result = send(Socket, buff, len, flags);
            byte[] managedArray = new byte[len];
            Marshal.Copy(buff, managedArray, 0, len);
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        var output = String.Join(";", Regex.Matches(Encoding.UTF8.GetString(managedArray), @"\$(.?)\#|\$(.+?)\#") //im horrible with regular expressions
                                    .Cast<Match>()
                                    .Select(m => m.Groups[2].Value));
                        if (!String.IsNullOrEmpty(output)) this._messageQueue.Enqueue($"Server:<- {output}");
                    }
                }
            }
            catch
            {
                //just in case
            }
            return result;
        }

        #endregion

        #region Recv hook
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

        delegate int recv_Delegate(IntPtr Socket, IntPtr buff, int len, int flags);

        [DllImport("ws2_32.dll")]
        static extern int recv(IntPtr Socket, IntPtr buff, int len, int flags);

        int recv_Hook(IntPtr Socket, IntPtr buff, int len, int flags)
        {
            int result = 0;

            result = recv(Socket, buff, len, flags);
            byte[] managedArray = new byte[len];
            Marshal.Copy(buff, managedArray, 0, len);
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        var output = String.Join(";", Regex.Matches(Encoding.UTF8.GetString(managedArray), @"\$(.?)\#|\$(.+?)\#")
                                    .Cast<Match>()
                                    .Select(m => m.Groups[2].Value));
                        if (!String.IsNullOrEmpty(output))  this._messageQueue.Enqueue($"Client:-> {output}");
                    }
                }
            }
            catch
            {
                //just in case
            }
            return result;
        }

        #endregion
    }
}
