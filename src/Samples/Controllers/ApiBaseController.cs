using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Web.Http;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Samples.Controllers
{
    public abstract class ApiBaseController : ApiController
    {
        /// <summary>
        /// 自定义200，不返回data字段
        /// </summary>
        /// <returns>{"code":200}</returns>
        public IActionResult CustomOk()
        {
            //this.Context.RequestServices.GetService
            return Json<Models.ICustomResponseMessage>(new Models.CustomOKResponseMessage());
        }

        /// <summary>
        /// 自定义返回数据
        /// </summary>
        /// <typeparam name="T">数据类型</typeparam>
        /// <param name="value">返回数据</param>
        /// <returns>{"code":200,"data":T}</returns>
        public IActionResult CustomData<T>(T value)
        {
            return Json<Models.ICustomResponseMessage>(new Models.CustomDataResponseMessage<T>() { data = value });
        }

        /// <summary>
        /// 自定义错误
        /// </summary>
        /// <param name="msg">错误说明</param>
        /// <returns>{"code":500,"data":msg}</returns>
        public IActionResult CustomError(string msg)
        {
            return Json<Models.ICustomResponseMessage>(new Models.CustomErrorResponseMessage(msg));
        }
    }
}
