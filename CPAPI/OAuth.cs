using Newtonsoft.Json.Linq;
using System.Net;
using System.Text;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Globalization;
using System.Text.Json;
using System.Net.WebSockets;

namespace CPAPI
{
    internal class OAuth
    {
        static string EscapeUriDataStringRfc3986(string value)
        {
            // Replace the default RFC 2396 supported through C# with its RFC 3986 equivalent

            string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };

            StringBuilder escaped = new(Uri.EscapeDataString(value));

            // Upgrade the escaping to RFC 3986, if necessary.
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }

            // Return the fully-RFC3986-escaped string.
            return escaped.ToString();
        }

        static byte[] EasySha1(byte[] intended_key, byte[] intended_msg)
        {
            // Create HMAC SHA1 object
            HMACSHA1 bytes_hmac_hash_K = new()
            {
                // Set the HMAC key to our passed intended_key byte array
                Key = intended_key
            };
            // Hash the SHA1 bytes of our key against the msg content.
            byte[] K_hash = bytes_hmac_hash_K.ComputeHash(intended_msg);

            return K_hash;
        }

        static byte[] ConstructDerBytes(string pem_fp)
        {
            // Read the content of our DH Param PEM file and assign the content to a String
            StreamReader sr = new(pem_fp);
            string reader = sr.ReadToEnd();
            sr.Close();

            // Find the pem field content from the StreamReader string
            PemFields pem_fields = PemEncoding.Find(reader);

            // Convert the pem base 64 string content into a byte array for use in our import
            byte[] der_data = Convert.FromBase64String(reader[pem_fields.Base64Data]);
            return der_data;

        }

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

        static string CheckHexLen(string hex_str_k)
        {
            // Validate our hexidecimal string value.
            if (hex_str_k.Length % 2 != 0)
            {
                // Set the lead byte to 0 for a positive sign bit.
                hex_str_k = "0" + hex_str_k;
                return hex_str_k;
            }
            else
            {
                // If we have an already even hexidecimal K value, we simply return the existing value.
                return hex_str_k;
            }
        }

        static string StandardRequest(HttpClient client, HttpMethod request_method, string request_url, string consumer_key, string realm, string access_token, string computed_lst, string req_content = "{}")
        {
            try
            {

                HttpRequestMessage request = new(request_method, request_url);

                //Create a dictionary for all oauth params in our header.
                Dictionary<string, string> oauth_params = new()
                {
                    { "oauth_consumer_key", consumer_key },
                    { "oauth_nonce", RandomNumberGenerator.GetInt32(2147483647).ToString() },
                    { "oauth_timestamp", DateTimeOffset.Now.ToUnixTimeMilliseconds().ToString() },
                    { "oauth_token", access_token },
                    { "oauth_signature_method", "HMAC-SHA256" }
                };

                // Sort our oauth_params dictionary by key.
                Dictionary<string, string> sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);

                // Combine our oauth_params into a single string for our base_string.
                string params_string = string.Join("&", sorted_params.Select(kv => $"{kv.Key}={kv.Value}"));

                // Create a base string by combining the prepend, url, and params string.
                string base_string = $"{request_method}&{EscapeUriDataStringRfc3986(request_url.ToLower())}&{EscapeUriDataStringRfc3986(params_string)}";

                // Convert our new string to a bytestring 
                byte[] encoded_base_string = Encoding.UTF8.GetBytes(base_string);

                // Create HMAC SHA256 object
                HMACSHA256 bytes_hmac_hash_K = new()
                {
                    // Set the HMAC key to our live_session_token
                    Key = Convert.FromBase64String(computed_lst)
                };

                // Hash the SHA256 bytes against our encoded bytes.
                byte[] K_hash = bytes_hmac_hash_K.ComputeHash(encoded_base_string);

                // Generate str from base64-encoded bytestring hash.
                string b64_str_hmac_hash = Convert.ToBase64String(K_hash);

                // URL-encode the base64 hash str and add to oauth params dict.
                oauth_params.Add("oauth_signature", EscapeUriDataStringRfc3986(b64_str_hmac_hash));

                // Oauth realm param omitted from signature, added to header afterward.
                oauth_params.Add("realm", realm);

                // Sort our params alphabetically by key.
                Dictionary<string, string> fin_sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);

                // Assemble oauth params into auth header value as comma-separated str.
                string oauth_header = $"OAuth " + string.Join(",", oauth_params.Select(kv => $"{kv.Key}=\"{kv.Value}\""));


                request.Headers.Add("Host", "api.ibkr.com");
                request.Headers.Add("User-Agent", "csharp/6.0");

                request.Headers.Add("Accept", "*/*");
                request.Headers.Add("Connection", "keep-alive");
                request.Headers.Add("Authorization", oauth_header);

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

        static BigInteger DhRandomGenerator()
        {
            // Create a Random object, and then retrieve any random positive integer value.
            Random random = new();

            return random.Next(1, int.MaxValue);
        }

        private static async Task ConnectWebSocketAsync(Uri wsUri, string session_token)
        {
            try
            {
                // Create a cookie container
                CookieContainer cookie_jar = new();

                // Build a cookie to reference our session token in the websocket
                Cookie raisin = new Cookie("api", session_token) { Domain = wsUri.Host };

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
                webSocket.Options.SetRequestHeader("Origin", "api.ibkr.com");
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
                ArraySegment<byte> sendBuffer = new ArraySegment<byte>(Encoding.UTF8.GetBytes(data));
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

        static async Task Main()
        {
            HttpClientHandler clientHandler = new() { };

            // HttpClient is intended to be instantiated once per application, rather than per-use.
            HttpClient client = new(clientHandler);

            string base_url = "api.ibkr.com/v1/api";

            // Declare our L1 Json KEY
            string credential = "user1";

            string line;
            try
            {
                //Read our credentials file
                StreamReader sr = new(@"../../../sample_credential.json");
                line = sr.ReadToEnd();

                // Convert credentials content to JSON
                JObject credentials_json = JObject.Parse(line);

                // Set our string values from the JSON L2 content.
                string consumer_key = credentials_json.SelectToken(credential).SelectToken("consumer_key").ToString();
                string access_token = credentials_json.SelectToken(credential).SelectToken("access_token").ToString();
                string access_token_secret = credentials_json.SelectToken(credential).SelectToken("access_token_secret").ToString();

                // Retrieve our PEM content from the JSON L2 content.
                string dhparam_fp = credentials_json.SelectToken(credential).SelectToken("dhparam").ToString();
                string encryption_fp = credentials_json.SelectToken(credential).SelectToken("encryption").ToString();
                string signature_fp = credentials_json.SelectToken(credential).SelectToken("signature").ToString();

                //close the file
                sr.Close();

                // Retrieve a byte array of our dhparam file's contents.
                byte[] dh_der_data = ConstructDerBytes(dhparam_fp);

                // Extract our dh_modulus and dh_generator values from our dhparam.pem file's bytes.
                AsnReader asn1Seq = new AsnReader(dh_der_data, AsnEncodingRules.DER).ReadSequence();
                BigInteger dh_modulus = asn1Seq.ReadInteger();
                BigInteger dh_generator = asn1Seq.ReadInteger();

                // -------------------------------------------------------------------
                // Request #1: Obtaining a LST
                // -------------------------------------------------------------------

                // Generate a random value for our challenge calculation
                BigInteger dh_random = DhRandomGenerator();

                // Generate our dh_challenge value by calculating the result of our generator to the power of our random value, modular divided by our dh_modulus.
                BigInteger dh_challenge = BigInteger.ModPow(dh_generator, dh_random, dh_modulus);

                string realm;
                // create an if statement where we set realm according to our consumer key.
                if (credential == "testcons")
                {
                    realm = "test_realm";
                }
                else
                {
                    realm = "limited_poa";
                }

                // Create the crypto provider 
                RSACryptoServiceProvider bytes_decrypted_secret = new()
                {
                    // Utililze a keysize of 2048 rather than the default 7168
                    KeySize = 2048
                };

                // Use our function to retrieve the object bytes
                byte[] enc_der_data = ConstructDerBytes(encryption_fp);

                // Import the bytes object as our key
                bytes_decrypted_secret.ImportPkcs8PrivateKey(enc_der_data, out _);

                // Encode the access token secret as an ASCII bytes object
                byte[] encryptedSecret = Convert.FromBase64String(access_token_secret);

                // Decrypt our secret bytes with the encryption key
                byte[] raw_prepend = bytes_decrypted_secret.Decrypt(encryptedSecret, RSAEncryptionPadding.Pkcs1);

                // Convert our bytestring to a hexadecimal string
                string prepend = Convert.ToHexString(raw_prepend).ToLower();

                string endpoint = "/oauth/live_session_token";

                string lst_url = "https://" + base_url + endpoint;

                HttpRequestMessage request = new(HttpMethod.Post, lst_url);

                // Interactive Brokers requires a 10 digit Unix timestamp value.
                // Values beyond 10 digits will result in an error.
                string timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds().ToString();
                timestamp = timestamp.Substring(0, timestamp.Length - 3);

                //Create a dictionary for all oauth params in our header.
                Dictionary<string, string> oauth_params = new()
                {
                    { "oauth_consumer_key", consumer_key },
                    { "oauth_nonce", DhRandomGenerator().ToString("X").ToLower() },
                    { "oauth_timestamp", timestamp },
                    { "oauth_token", access_token },
                    { "oauth_signature_method", "RSA-SHA256" },
                    { "diffie_hellman_challenge", dh_challenge.ToString("X").ToLower() }
                };

                // Sort our oauth_params dictionary by key.
                Dictionary<string, string> sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);

                // Combine our oauth_params into a single string for our base_string.
                string params_string = string.Join("&", sorted_params.Select(kv => $"{kv.Key}={kv.Value}"));

                // Create a base string by combining the prepend, url, and params string.
                string base_string = $"{prepend.ToLower()}POST&{EscapeUriDataStringRfc3986(lst_url)}&{EscapeUriDataStringRfc3986(params_string)}";

                // Convert our new string to a bytestring 
                byte[] encoded_base_string = Encoding.UTF8.GetBytes(base_string);

                // Create a Sha256 Instance
                SHA256 sha256_inst = SHA256.Create();

                // Generate SHA256 hash of base string bytestring.
                byte[] sha256_hash = sha256_inst.ComputeHash(encoded_base_string);

                // Create the crypto provider for our signature
                RSACryptoServiceProvider bytes_pkcs115_signature = new()
                {
                    // Utililze a keysize of 2048 rather than the default 7168
                    KeySize = 2048
                };

                // Use our function to retrieve the object bytes
                byte[] sig_der_data = ConstructDerBytes(signature_fp);

                // Import the bytes object as our key
                bytes_pkcs115_signature.ImportPkcs8PrivateKey(sig_der_data, out _);

                //Generate the Pkcs115 signature key
                RSAPKCS1SignatureFormatter rsaFormatter = new(bytes_pkcs115_signature);

                rsaFormatter.SetHashAlgorithm("SHA256");

                //Receive the bytestring of our signature
                byte[] signedHash = rsaFormatter.CreateSignature(sha256_hash);

                // Convert the bytestring signature to base64.
                string b64_str_pkcs115_signature = Convert.ToBase64String(signedHash);

                // URL-encode the base64 signature str and add to oauth params dict.
                oauth_params.Add("oauth_signature", EscapeUriDataStringRfc3986(b64_str_pkcs115_signature));

                // Oauth realm param omitted from signature, added to header afterward.
                oauth_params.Add("realm", realm);

                Dictionary<string, string> fin_sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);

                // Assemble oauth params into auth header value as comma-separated str.
                string oauth_header = $"OAuth " + string.Join(", ", fin_sorted_params.Select(kv => $"{kv.Key}=\"{kv.Value}\""));


                // Build out our request headers
                request.Headers.Add("Host", "api.ibkr.com");
                request.Headers.Add("User-Agent", "csharp/6.0");
                request.Headers.Add("Accept-Encoding", "gzip,deflate");
                request.Headers.Add("Accept", "*/*");
                request.Headers.Add("Connection", "keep-alive");
                request.Headers.Add("Authorization", oauth_header);

                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"Request to {endpoint} failed. Received status code {(int)response.StatusCode}");
                    await WebHeaderPrint(request, response);
                    Environment.Exit(1);
                }

                // Retrieve the results of our live session token request.
                string lst_result = WebHeaderPrint(request, response).Result;

                // Convert our lst results to a JSON Object
                JObject resp_json = JObject.Parse(lst_result);

                string dh_response = resp_json.SelectToken("diffie_hellman_response").ToString(); // Returned DH Response is a hex-string
                string lst_signature = resp_json.SelectToken("live_session_token_signature").ToString();
                string lst_expiration = resp_json.SelectToken("live_session_token_expiration").ToString();

                Console.WriteLine($"dh_random: {dh_random}\nprepend: {prepend}\ndh_response: {dh_response}\nlst_signature: {lst_signature}\nlst_expiration: {lst_expiration}\n");

                // -------------------------------------------------------------------
                // Request #2: Compute Live Session Token
                // -------------------------------------------------------------------

                //Generate bytestring from prepend hex str.
                byte[] prepend_bytes = Convert.FromHexString(prepend);

                // Convert hex string response to integer and compute K=B^a mod p.
                // The error has to take place between here and the computed_lst section
                BigInteger a = dh_random;

                // Validate that our dh_response value has a leading sign bit, and if it's not there then be sure to add it.
                BigInteger p = dh_modulus;
                if (dh_response[0] != 0)
                {
                    dh_response = "0" + dh_response;
                }

                // Convert our dh_response hex string to a biginteger. 
                BigInteger B = BigInteger.Parse(dh_response, NumberStyles.HexNumber);

                // K will be used to hash the prepend bytestring (the decrypted access token) to produce the LST.
                BigInteger K = BigInteger.ModPow(B, a, p);

                // Generate hex string representation of integer K. Be sure to strip the leading sign bit.
                string hex_str_k = K.ToString("X").ToLower(); // It must be converted to lowercase values prior to byte conversion.

                // If hex string K has odd number of chars, add a leading 0
                hex_str_k = CheckHexLen(hex_str_k);

                // Generate hex bytestring from hex string K.
                byte[] hex_bytes_K = Convert.FromHexString(hex_str_k);

                // Generate bytestring HMAC hash of hex prepend bytestring.
                byte[] K_hash = EasySha1(hex_bytes_K, prepend_bytes);

                // Convert hash to base64 to retrieve the computed live session token.
                string computed_lst = Convert.ToBase64String(K_hash);


                //-------------------------------------------------------------------
                //Request #3: Validate Live Session Token
                // ------------------------------------------------------------------ -
                //Generate hex - encoded str HMAC hash of consumer key bytestring.
                // Hash key is base64 - decoded LST bytestring, method is SHA1

                byte[] b64_decode_lst = Convert.FromBase64String(computed_lst);

                // Convert our consumer key str to bytes
                byte[] consumer_bytes = Encoding.UTF8.GetBytes(consumer_key);

                // Hash the SHA1 bytes against our hex bytes of K.
                byte[] hashed_consumer = EasySha1(b64_decode_lst, consumer_bytes);

                // Convert hash to base64 to retrieve the computed live session token.
                string hex_lst_hash = Convert.ToHexString(hashed_consumer).ToLower();


                // If our hex hash of our computed LST matches the LST signature received in response, we are successful.
                if (hex_lst_hash == lst_signature)
                {
                    string live_session_token = computed_lst;
                    Console.WriteLine("Live session token computation and validation successful.");
                    Console.WriteLine($"LST: {live_session_token}; expires: {lst_expiration}\n");
                }
                else
                {
                    Console.WriteLine("######## LST MISMATCH! ########");
                    Console.WriteLine($"Hexed LST: {hex_lst_hash} | LST Signature: {lst_signature}\n");
                }

                // -------------------------------------------------------------------
                // Request #4: Initialize Brokerage Session
                // -------------------------------------------------------------------
                HttpMethod brokerage_method = HttpMethod.Post;
                endpoint = "/iserver/auth/ssodh/init";
                string req_content = JsonSerializer.Serialize(new { compete = true, publish = true });
                StandardRequest(client, brokerage_method, "https://" + base_url + endpoint, consumer_key, realm, access_token, computed_lst, req_content);

                // The system needs a moment to spin up before making requests.
                System.Threading.Thread.Sleep(1000);

                // -------------------------------------------------------------------
                // Request #5: Confirm valid accounts within the portfolio.
                // -------------------------------------------------------------------
                HttpMethod portfolio_method = HttpMethod.Get;
                endpoint = "/portfolio/accounts";
                StandardRequest(client, portfolio_method, "https://" + base_url + endpoint, consumer_key, realm, access_token, computed_lst);

                // -------------------------------------------------------------------
                // Request #6: Make a call for historical market data
                // -------------------------------------------------------------------
                HttpMethod hmds_method = HttpMethod.Get;
                endpoint = "/hmds/history?conid=265598&period=3600S&bar=1mins";

                // Among other endpoints, the /hmds endpoint requires a pre-flight request in order to appropriately return data.
                StandardRequest(client, hmds_method, "https://" + base_url + endpoint, consumer_key, realm, access_token, computed_lst);
                StandardRequest(client, hmds_method, "https://" + base_url + endpoint, consumer_key, realm, access_token, computed_lst);


                System.Threading.Thread.Sleep(1000);
                // -------------------------------------------------------------------
                // Request #7: Call /tickle to retrieve the session token
                // -------------------------------------------------------------------
                HttpMethod md_method = HttpMethod.Get;
                endpoint = "/tickle";
                string resp_content = StandardRequest(client, md_method, "https://" + base_url + endpoint, consumer_key, realm, access_token, computed_lst);

                // Convert our response content to a json object
                JObject tickle_json = JObject.Parse(resp_content);

                // From our json object, retrieve our session token from /tickle
                string session_token = tickle_json.SelectToken("session").ToString();


                // -------------------------------------------------------------------
                // Request #8: Create a websocket to stream live market data
                // -------------------------------------------------------------------
                // Build our websocket URI for our Websocket requests
                var wsUri = new Uri($"wss://{base_url}/ws?oauth_token={access_token}");
                await ConnectWebSocketAsync(wsUri, session_token);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
            }

        }

    }
}