using lb1_cryptography.Models;
using lb1_cryptography.Models.Enums;
using Microsoft.AspNetCore.Mvc;

namespace lb1_cryptography.Controllers
{
    
    public class DesController : Controller
    {
        public IActionResult ProcessDes(OperationKind operationKind, [FromBody]DesRequestViewModel desRequestViewModel)
        {
            var dp = new DesProcessor();
            if (operationKind == OperationKind.Encrypt) {
                return Ok(dp.Encrypt(desRequestViewModel));
            }
            return Ok(dp.Decrypt(desRequestViewModel));
        }
    }
}
