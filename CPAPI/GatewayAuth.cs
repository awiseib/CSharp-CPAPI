using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace CPAPI
{
    class GatewayAuth
    {
        private static async Task ConnectWebSocketAsync(Uri wsUri, String session_token)
        {

            CookieContainer cookie_jar = new CookieContainer();
            Cookie raisin = new Cookie("api", session_token) { Domain = wsUri.Host };
            cookie_jar.Add(raisin);


            using (ClientWebSocket webSocket = new ClientWebSocket { Options = {
                    Cookies = cookie_jar,
                    RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
                } } )
            {

                var exitEvent = new ManualResetEvent(false);
                await webSocket.ConnectAsync(wsUri, CancellationToken.None);
                Console.WriteLine("WebSocket connection opened");
                Console.WriteLine(webSocket.State);
                await Task.WhenAny(Receive(webSocket));
            }
        }
        private static async Task Send(ClientWebSocket webSocket)
        {
            Console.WriteLine("In Send");
            // Send a message to the WebSocket server
            string data = "smd+265598+{\"fields\":[\"31\",\"84\",\"86\"]}";
            ArraySegment<byte> sendBuffer = new ArraySegment<byte>(Encoding.UTF8.GetBytes(data));
            await webSocket.SendAsync(sendBuffer, WebSocketMessageType.Text, false, CancellationToken.None);
            Console.WriteLine("Sent message: " + data);
        }

        private static async Task Receive(ClientWebSocket webSocket)
        {
            byte[] buffer = new byte[2048];
            while (webSocket.State == WebSocketState.Open)
            {
                var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                }
                else
                {
                    string message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    Console.WriteLine("Received message: " + message);

                    try
                    {

                        JObject jmsg = JObject.Parse(message);
                        String topic = jmsg.SelectToken("topic").ToString();
                        if (topic == "act")
                        {
                            await Send(webSocket);
                        }
                    } catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                }
            }
        }
        static async Task Main()
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            // Ignores invalid certificate
            clientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            // Pass the handler to httpclient(from you are calling api)
            // HttpClient is intended to be instantiated once per application, rather than per-use.
            HttpClient client = new HttpClient(clientHandler);


            // Call asynchronous network methods in a try/catch block to handle exceptions.
            try
            {
                String base_url = "localhost:5001/v1/api";

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "https://"+ base_url + "/tickle");
                request.Headers.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/6.0;)");
                HttpResponseMessage response = client.SendAsync(request).Result;
                String resp_content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(resp_content);

                JObject resp_json = JObject.Parse(resp_content);
                String session_token = resp_json.SelectToken("session").ToString();


                var wsUri = new Uri("wss://" + base_url + "/ws");

                await ConnectWebSocketAsync(wsUri, session_token);

            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }


        }

    }
}
