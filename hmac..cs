using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;  
using System.Security.Cryptography;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;

namespace TurboPascal.API
{
    public static class GenerateHMAC256Signature
    {
        [FunctionName("GenerateHMAC256Signature")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string input = req.Query["input"];
            string secret = req.Query["secret"];     

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);

            input = input ?? data?.input;
            secret = secret ?? data?.secret;

            string signature = HMACSHA256Encode(input,secret);

            string responseMessage = string.IsNullOrEmpty(input)
                ? "This HTTP triggered function executed successfully. Pass input in the query string or in the request body for a personalized response."
                        : $"{signature}";

            return new OkObjectResult(responseMessage);
        }

        public static string HMACSHA256Encode(string input, string key)
        {
            byte[] k = Encoding.ASCII.GetBytes (key);
            HMACSHA256 myhmacsha256 = new HMACSHA256 (k);
            byte[] byteArray = Encoding.ASCII.GetBytes (input);

            using (MemoryStream stream = new MemoryStream (byteArray)){

                string sig = BitConverter.ToString(myhmacsha256.ComputeHash (stream));
                sig = sig.Replace("-","");
            return  sig;
            }

            
        }
    }
}
