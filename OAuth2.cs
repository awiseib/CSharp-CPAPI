using Newtonsoft.Json.Linq;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Text.Json;
using System.Net.WebSockets;

namespace CPAPI
{
    class Oauth2
    {
        // Interactive Brokers URLs
        private const string cpapi_url = "api.ibkr.com/v1/api";
        private const string oauth2_url = "https://api.ibkr.com/oauth2";
        private const string gw_url = "https://api.ibkr.com/gw";

        // Predefined Interactive Brokers variables
        private const string request_scope = "sso-sessions.write sso-sessions.read";
        private const string audience = "/token";

        // Unique Client Varaibles
        // For questions regarding these credentials, please contact api-solutions@interactivebrokers.com to get started with the OAuth 2 authentication procedure.
        private const string clientPemPath = @"\path\to\privatekey.pem";
        private const string clientKeyId = "main"; // The clientKeyId is used to uniquely identify a client’s public key from other keys in their key ring. The value “main” is just the default client key id used when the client only registers a single key with IB (i.e., a key ring size of 1).

        private const string clientId = "SAMPLE_CLIENTID"; // The clientId uniquely identifies the client within the OAuth 2.0 server and will be different for each client. 
        private const string credential = "SAMPLE_CREDENTIAL"; // The unique username 

        static long GenTimeStamp()
        {
            // Interactive Brokers requires a 10 digit Unix timestamp value.
            // Values beyond 10 digits will result in an error.
            long timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
            return timestamp;
        }

        static async Task WebHeaderPrint(HttpRequestMessage request, HttpResponseMessage response)
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
            await Console.Out.WriteLineAsync($"{(int)response.StatusCode} {response.StatusCode}");
            await Console.Out.WriteLineAsync(await response.Content.ReadAsStringAsync());
            await Console.Out.WriteLineAsync("----------------------------\n");
        }
       
        static string StandardRequest(HttpClient client, HttpMethod request_method, string request_url, string bearer_token, string req_content = "{}")
        {
            try
            {

                HttpRequestMessage request = new(request_method, request_url);

                request.Headers.Add("Host", "api.ibkr.com");
                request.Headers.Add("User-Agent", "csharp/6.0");

                request.Headers.Add("Accept", "*/*");
                request.Headers.Add("Connection", "keep-alive");
                request.Headers.Add("Authorization", $"Bearer {bearer_token}");

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

        private static async Task ConnectWebSocketAsync(Uri wsUri, string session_token)
        {
            try
            {
                // Create a cookie container
                CookieContainer cookie_jar = new();

                // Build a cookie to reference our session token in the websocket
                Cookie raisin = new("api", session_token) { Domain = wsUri.Host };

                // Add the cookie to our container
                cookie_jar.Add(raisin);

                // Build a websocket client, assigning our cookie appropriately 
                ClientWebSocket webSocket = new()
                {
                    Options = {
                        Cookies = cookie_jar
                    }
                };

                // Assign additional headers in our websocket, including origin and user-agent.
                webSocket.Options.SetRequestHeader("User-Agent", "csharp/6.0");

                // Send a request to connect our websocket client
                await webSocket.ConnectAsync(wsUri, CancellationToken.None);

                Console.WriteLine("WebSocket connection opened");
                Console.WriteLine(webSocket.State);

                // Create an ongoing thread to read our weboscket content once new updates are available
                await Task.WhenAny(Receive(webSocket));

            }
            catch (Exception ex)
            {
                Console.WriteLine("Failure in WS Connection");
                Console.WriteLine(ex.ToString());
            }
        }

        private static async Task Send(ClientWebSocket webSocket, string data)
        {
            try
            {
                Console.WriteLine("In Send");
                // Send a message to the WebSocket server
                ArraySegment<byte> sendBuffer = new(Encoding.UTF8.GetBytes(data));
                await webSocket.SendAsync(sendBuffer, WebSocketMessageType.Binary, true, CancellationToken.None);
                Console.WriteLine("Sent message: " + data);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failure in WS Send");
                Console.WriteLine(ex.ToString());
            }
        }

        private static async Task Receive(ClientWebSocket webSocket)
        {
            try
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
                            string topic = jmsg.SelectToken("topic").ToString();

                            if (topic == "sts" && ((bool)jmsg.SelectToken("args").SelectToken("authenticated")) == true)
                            {
                                string data = "smd+265598+{\"fields\":[\"31\",\"84\",\"86\"]}";
                                await Send(webSocket, data);
                            }
                        }
                        catch (JsonReaderException ex) {}
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failure in WS Receive");
                Console.WriteLine(ex.ToString());
            }
        }

        static string GetMyIp(HttpClient client)
        {
            try
            {

                HttpRequestMessage request = new(HttpMethod.Get, new Uri("https://api.ipify.org"));

                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"IP Request Failed");

                    WebHeaderPrint(request, response);
                }
                else
                {
                    // We want to return our response values so we can later work with them.
                    return response.Content.ReadAsStringAsync().Result;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            return "";

        }

        static string Base64UrlEncode(string b_data)
        {
            return b_data.Replace("+", "-").Replace("/", "_").Replace("=", "").Replace("\"","'");
        }

        static byte[] Sha256Md(string payload)
        {
            // Create a Sha256 Instance
            SHA256 sha256_inst = SHA256.Create();

            // Generate SHA256 hash of payload's bytestring.
            byte[] md = sha256_inst.ComputeHash(Encoding.UTF8.GetBytes(payload));

            // Create the crypto provider for our signature
            RSACryptoServiceProvider signer = new()
            {
                // Utililze a keysize of 3072 rather than the default 7168
                KeySize = 3072
            };

            // Import the bytes object as our key
            signer.ImportFromPem(File.ReadAllText(clientPemPath));

            //Generate the Pkcs115 signature key
            RSAPKCS1SignatureFormatter rsaFormatter = new(signer);

            rsaFormatter.SetHashAlgorithm("SHA256");

            //Receive the bytestring of our signature
            byte[] signature = rsaFormatter.CreateSignature(md);

            // Convert the bytestring signature to base64.
            return signature;
        }

        static string MakeJws(Dictionary<string, dynamic> header, Dictionary<string, dynamic> claims)
        {
            string json_header = JsonConvert.SerializeObject(header);
            byte[] byte_head = Encoding.UTF8.GetBytes(json_header);
            string b64_header = Base64UrlEncode(Convert.ToBase64String(byte_head));

            string json_claims = JsonConvert.SerializeObject(claims);
            byte[] byte_claims = Encoding.UTF8.GetBytes(json_claims);
            string b64_claims = Base64UrlEncode(Convert.ToBase64String(byte_claims));

            string payload = $"{b64_header}.{b64_claims}";

            byte[] signature = Sha256Md(payload);

            string encoded_signature = Base64UrlEncode(Convert.ToBase64String(signature));

            return payload + "." + encoded_signature;
        }
        
        static string ComputeClientAssertion()
        {
            long now = GenTimeStamp();

            Dictionary<string, dynamic> header = new() {
                { "typ","JWT"},
                { "alg", "RS256" },
                { "kid", clientKeyId }
            };

            Dictionary<string, dynamic> claims = new() {
                {"sub", clientId },
                {"aud", audience },

                { "iss", clientId },
                { "exp", now+20 },
                { "iat", now-10 }
            };

            string assertion = MakeJws(header, claims);

            return assertion;
        }
        
        static string ComputeSignedRequest(HttpClient client)
        {
            long now = GenTimeStamp();

            Dictionary<string, dynamic> header = new() {
                { "typ","JWT"},
                { "alg", "RS256" },
                { "kid", clientKeyId }
            };

            Dictionary<string, dynamic> claims = new() {
                {"ip", GetMyIp(client) },
                {"service", "AM.LOGIN" },
                {"credential", credential },

                { "iss", clientId },
                { "exp", now+86400 },
                { "iat", now }
            };

            string assertion = MakeJws(header, claims);

            return assertion;
        }

        static string AccessToken(HttpClient client)
        {
            try
            {

                HttpRequestMessage request = new(HttpMethod.Post, new Uri($"{oauth2_url}/api/v1/token")) {
                    Headers =
                    {
                        { "Host", "api.ibkr.com" },
                        { "Cache-Control", "no-cache" },
                        { "User-Agent", "csharp/6.0" },
                    }
                };

                Dictionary<string, string> req_content =  new() 
                {
                    { "client_assertion_type","urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                    { "client_assertion", ComputeClientAssertion() },
                    { "grant_type", "client_credentials" },
                    { "scope", request_scope }
                };

                request.Content = new FormUrlEncodedContent(req_content);


                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"Request for Access Token failed. Received status code {(int)response.StatusCode}");

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

        static string BearerToken(HttpClient client, string access_token)
        {
            try
            {

                HttpRequestMessage request = new(HttpMethod.Post, new Uri($"{gw_url}/api/v1/sso-sessions"))
                {
                    Headers =
                    {
                        { "Host", "api.ibkr.com" },
                        { "Cache-Control", "no-cache" },
                        { "User-Agent", "csharp/6.0" },
                        { "Authorization", $"Bearer {access_token}" },
                    },

                    Content = new StringContent(ComputeSignedRequest(client))
                };


                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"Request for Access Token failed. Received status code {(int)response.StatusCode}");

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
        public static async Task Main()
        {
            HttpClientHandler clientHandler = new()
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };

            // HttpClient is intended to be instantiated once per application, rather than per-use.
            HttpClient client = new(clientHandler);


            // -------------------------------------------------------------------
            // Request #1: Request an Accesss Token
            // -------------------------------------------------------------------
            string access_token_request = AccessToken(client);
            // Convert our response content to a json object
            JObject at_json = JObject.Parse(access_token_request);
            // From our json object, retrieve our session token from /tickle
            string access_token = at_json.SelectToken("access_token").ToString();


            // -------------------------------------------------------------------
            // Request #2: Request a Bearer Token using our Access Token
            // -------------------------------------------------------------------
            string bearer_token_request = BearerToken(client, access_token);
            // Convert our response content to a json object
            JObject bt_json = JObject.Parse(bearer_token_request);
            // From our json object, retrieve our session token from /tickle
            string bearer_token = bt_json.SelectToken("access_token").ToString();

            // -------------------------------------------------------------------
            // Request #3: Initialize Brokerage Session
            // -------------------------------------------------------------------
            HttpMethod brokerage_method = HttpMethod.Post;
            string endpoint = "/iserver/auth/ssodh/init";
            string req_content = System.Text.Json.JsonSerializer.Serialize(new { compete = true, publish = true });
            StandardRequest(client, brokerage_method, "https://" + cpapi_url + endpoint, bearer_token, req_content);

            // The system needs a moment to spin up before making requests.
            System.Threading.Thread.Sleep(1000);

            // -------------------------------------------------------------------
            // Request #4: Confirm valid accounts within the portfolio.
            // -------------------------------------------------------------------
            HttpMethod portfolio_method = HttpMethod.Get;
            endpoint = "/portfolio/accounts";
            StandardRequest(client, portfolio_method, "https://" + cpapi_url + endpoint, bearer_token);

            HttpMethod rule_method = HttpMethod.Get;
            endpoint = "/iserver/contract/265598/info-and-rules?isBuy=false";
            StandardRequest(client, rule_method, "https://" + cpapi_url + endpoint, bearer_token);
            // -------------------------------------------------------------------
            // Request #5: Init and make a call for historical market data
            // -------------------------------------------------------------------

            HttpMethod hmds_init_method = HttpMethod.Post;
            endpoint = "/hmds/auth/init";

            // Among other endpoints, the /hmds endpoint requires a pre-flight request in order to appropriately return data.
            StandardRequest(client, hmds_init_method, "https://" + cpapi_url + endpoint, bearer_token);

            HttpMethod hmds_method = HttpMethod.Get;
            endpoint = "/hmds/history?conid=265598&period=1d&bar=1day&barType=Last";
            StandardRequest(client, hmds_method, "https://" + cpapi_url + endpoint, bearer_token);


            System.Threading.Thread.Sleep(1000);
            // -------------------------------------------------------------------
            // Request #7: Call /tickle to retrieve the session token
            // -------------------------------------------------------------------
            HttpMethod md_method = HttpMethod.Get;
            endpoint = "/tickle";
            string resp_content = StandardRequest(client, md_method, "https://" + cpapi_url + endpoint, bearer_token);

            // Convert our response content to a json object
            JObject tickle_json = JObject.Parse(resp_content);

            // From our json object, retrieve our session token from /tickle
            string session_token = tickle_json.SelectToken("session").ToString();


            // -------------------------------------------------------------------
            // Request #8: Create a websocket to stream live market data
            // -------------------------------------------------------------------
            // Build our websocket URI for our Websocket requests
            var wsUri = new Uri($"wss://{cpapi_url}/ws");
            await ConnectWebSocketAsync(wsUri, session_token);

        }
    }
}
