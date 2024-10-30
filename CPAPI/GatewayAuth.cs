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
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Globalization;
using System.Text.Json;

namespace CPAPI
{
    class GatewayAuth
    {
        static async Task<string> WebHeaderPrint(HttpRequestMessage request, HttpResponseMessage response)
        {
            // Print out the request and response content of our web requests to capture headers.
            await Console.Out.WriteLineAsync("########## Request ###########");
            await Console.Out.WriteLineAsync($"{request.Method} {request.RequestUri}");
            await Console.Out.WriteLineAsync(request.Headers.ToString());
            if (request.Content != null)
            {
                await Console.Out.WriteLineAsync(await request.Content.ReadAsStringAsync());
            }
            await Console.Out.WriteLineAsync("\n########## Response ###########");
            await Console.Out.WriteLineAsync($"{(int)response.StatusCode} {response.StatusCode.ToString()}");
            await Console.Out.WriteLineAsync(await response.Content.ReadAsStringAsync());
            await Console.Out.WriteLineAsync("----------------------------\n");

            return response.Content.ReadAsStringAsync().Result;
        }

        static string StandardRequest(HttpClient client, HttpMethod request_method, string request_url, string req_content = "{}")
        {
            try
            {

                HttpRequestMessage request = new(request_method, request_url);

                request.Headers.Add("Host", "api.ibkr.com");
                request.Headers.Add("User-Agent", "csharp/6.0");
                request.Headers.Add("Accept", "*/*");
                request.Headers.Add("Connection", "keep-alive");

                StringContent req_content_json = new(req_content, Encoding.UTF8, "application/json");

                request.Content = req_content_json;

                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"Request to {request_url} failed. Received status code {(int)response.StatusCode}");

                    WebHeaderPrint(request, response);
                }
                else
                {
                    WebHeaderPrint(request, response);
                }

                // We want to return our response values so we can later work with them.
                return response.Content.ReadAsStringAsync().Result;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            return "";
        }
        private static async Task ConnectWebSocketAsync(Uri wsUri, String session_token)
        {

            CookieContainer cookie_jar = new CookieContainer();
            Cookie raisin = new Cookie("api", session_token) { Domain = wsUri.Host };
            cookie_jar.Add(raisin);


            using (ClientWebSocket webSocket = new ClientWebSocket
            {
                Options = {
                    Cookies = cookie_jar,
                    RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
                }
            })
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
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                }
            }
        }
        public async Task Gateway_Main()
        {
            HttpClientHandler clientHandler = new()
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            // Ignores invalid certificate
            clientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            // Pass the handler to httpclient(from you are calling api)
            // HttpClient is intended to be instantiated once per application, rather than per-use.
            HttpClient client = new HttpClient(clientHandler);


            // Call asynchronous network methods in a try/catch block to handle exceptions.
            try
            {
                String base_url = "localhost:5001/v1/api";
                String endpoint;
                HttpMethod method;
                string resp_content;

                // -------------------------------------------------------------------
                // Initialize our Brokerage Session
                // -------------------------------------------------------------------
                method = HttpMethod.Get;
                endpoint = "/iserver/auth/ssodh/init";
                string req_content = JsonSerializer.Serialize(new { compete = true, publish = true });
                resp_content = StandardRequest(client, method, "https://" + base_url + endpoint, req_content);

                // -------------------------------------------------------------------
                // Call /portfolio/accounts to retrieve account details
                // -------------------------------------------------------------------
                method = HttpMethod.Get;
                endpoint = "/portfolio/accounts";
                resp_content = StandardRequest(client, method, "https://" + base_url + endpoint);

                // -------------------------------------------------------------------
                // Call /tickle to retrieve the session token
                // -------------------------------------------------------------------
                method = HttpMethod.Get;
                endpoint = "/tickle";
                string tickle_resp_content = StandardRequest(client, method, "https://" + base_url + endpoint);

                // Convert our response content to a json object
                JObject tickle_json = JObject.Parse(tickle_resp_content);

                // From our json object, retrieve our session token from /tickle
                string session_token = tickle_json.SelectToken("session").ToString();


                // -------------------------------------------------------------------
                // Establish a websocket connection
                // -------------------------------------------------------------------
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
