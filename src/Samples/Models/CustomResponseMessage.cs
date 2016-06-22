using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Samples.Models
{
    internal interface ICustomResponseMessage
    {
        int code { get; }
    }
    public class CustomOKResponseMessage : ICustomResponseMessage
    {
        public int code
        {
            get
            {
                return 200;
            }
        }
    }
    public class CustomErrorResponseMessage : ICustomResponseMessage
    {
        public CustomErrorResponseMessage(string msg)
        {
            this.error = msg;
        }
        public int code
        {
            get
            {
                return 500;
            }
        }
        public string error { get; private set; }
    }
    public class CustomDataResponseMessage<T> : ICustomResponseMessage
    {
        private T _data;
        public int code
        {
            get
            {
                return 200;
            }
        }
        public T data { get { return _data; } set { _data = value; } }
    }
}
