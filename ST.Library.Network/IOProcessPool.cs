using System;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Generic;

namespace ST.Library.Network
{
    internal delegate void IOProcessHandler(SocketAsyncEventArgs e);

    internal static class IOProcessPool
    {
        private static ManualResetEvent m_mre;
        private static Stack<IOHandlerInfo> m_stack_idle;
        private static Queue<IOHandlerInfo> m_queue_work;

        static IOProcessPool() {
            IOHandlerInfo hi = null;
            m_mre = new ManualResetEvent(false);
            m_stack_idle = new Stack<IOHandlerInfo>();
            m_queue_work = new Queue<IOHandlerInfo>();
            new Thread(() => {
                while (true) {
                    hi = null;
                    lock (m_queue_work) {
                        if (m_queue_work.Count != 0) hi = m_queue_work.Dequeue();
                    }
                    if (hi == null) {
                        m_mre.WaitOne();
                        m_mre.Reset();
                        continue;
                    }
                    hi.Handler(hi.Args);
                    IOProcessPool.PushHandler(hi);
                }
            }) { IsBackground = true }.Start();
        }

        private static IOHandlerInfo PopHandler(IOProcessHandler handler, SocketAsyncEventArgs args) {
            IOHandlerInfo hi = null;
            lock (m_stack_idle) {
                if (m_stack_idle.Count != 0) hi = m_stack_idle.Pop();
            }
            if (hi == null) {
                hi = new IOHandlerInfo(handler, args);
            } else {
                hi.Handler = handler;
                hi.Args = args;
            }
            return hi;
        }

        private static void PushHandler(IOHandlerInfo hi) {
            lock (m_stack_idle) m_stack_idle.Push(hi);
        }

        public static void QueueWork(IOProcessHandler handler, SocketAsyncEventArgs args) {
            lock (m_queue_work) {
                m_queue_work.Enqueue(IOProcessPool.PopHandler(handler, args));
            }
            m_mre.Set();
            if (m_queue_work.Count > 1000) Console.WriteLine("======================: " + m_queue_work.Count);
        }

        private class IOHandlerInfo
        {
            private IOProcessHandler _Handler;

            public IOProcessHandler Handler {
                get { return _Handler; }
                set { _Handler = value; }
            }

            private SocketAsyncEventArgs _Args;

            public SocketAsyncEventArgs Args {
                get { return _Args; }
                set { _Args = value; }
            }

            public IOHandlerInfo(IOProcessHandler handler, SocketAsyncEventArgs args) {
                this._Handler = handler;
                this._Args = args;
            }
        }
    }
}
