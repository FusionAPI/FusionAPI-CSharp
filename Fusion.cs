using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Principal;
using System.Threading.Tasks;

namespace Fusion
{
    public struct FusionApp
    {
        private static HttpClient client = null;
        private static string baseUrl = null;
        private static string session;
        private static readonly string url = "https://fusionapi.dev/";

        public FusionApp(string app)
        {
            if (client == null)
            {
                var handler = new HttpClientHandler() { Proxy = null };
                client = new HttpClient(handler);
                baseUrl = $"{url}app/{app}/api";
            }
        }

        private async static Task Check42FA(string username)
        {
            var g2faDictionary = new Dictionary<string, string>
            {
                { "action", "has2fa" },
                { "username", username }
            };

            var g2faSource = new FormUrlEncodedContent(g2faDictionary);
            var g2faResponse = await client.PostAsync(baseUrl, g2faSource);
            var g2faContent = await g2faResponse.Content.ReadAsStringAsync();
            var g2faObject = JsonConvert.DeserializeObject<FusionResponse>(g2faContent);

            if (g2faObject.Session == "true")
                User.ValidateTwoFactor = true;
            else
                User.ValidateTwoFactor = false;
        }
        public async static Task RefreshApp()
        {
            var appBlobDictionary = new Dictionary<string, string>
            {
                { "action", "appblob" },
                { "session", session }
            };

            var appBlobSource = new FormUrlEncodedContent(appBlobDictionary);
            var appBlobResponse = await client.PostAsync(baseUrl, appBlobSource);
            var appBlobContent = await appBlobResponse.Content.ReadAsStringAsync();
            var appObject = JsonConvert.DeserializeObject<AppRoot>(appBlobContent);

            App.ActiveApis = appObject.Blob.ActiveApi;
            App.ApiCount = appObject.Blob.ApiCount;
            App.UserCount = appObject.Blob.UserCount;
            App.AppName = appObject.Blob.Label;
            App.AppDescription = appObject.Blob.Description;
        }
        public static async Task<string> GetIp()
        {
            var webResponse = await client.GetAsync("https://api.ipify.org");
            return await webResponse.Content.ReadAsStringAsync();
        }
        public static string GetHwid()
        {
            return WindowsIdentity.GetCurrent().User.Value;
        }
        public async Task<FusionResponse> Login(string username, string password, string g2fa = null, bool checkhwid = false, bool checkip = false)
        {
            await Check42FA(username);

            var loginDictionary = new Dictionary<string, string>
            {
                { "action", "login" },
                { "username", username },
                { "password", password }
            };

            if (User.ValidateTwoFactor == true)
                loginDictionary.Add("2fa", g2fa);

            var loginSource = new FormUrlEncodedContent(loginDictionary);
            var loginResponse = await client.PostAsync(baseUrl, loginSource);
            var loginContent = await loginResponse.Content.ReadAsStringAsync();

            try
            {
                var resp = JsonConvert.DeserializeObject<FusionResponse>(loginContent);
                if (!resp.Error) session = resp.Session;

                #region "Get User Blob"
                var userBlobDictionary = new Dictionary<string, string>
                {
                    { "action", "myblob" },
                    { "session", resp.Session }
                };
                var userBlobSource = new FormUrlEncodedContent(userBlobDictionary);
                var userBlobResponse = await client.PostAsync(baseUrl, userBlobSource);
                var userBlobContent = await userBlobResponse.Content.ReadAsStringAsync();
                var userObject = JsonConvert.DeserializeObject<UserRoot>(userBlobContent);

                string expdate;
                try { expdate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(userObject.Blob.Expiry)).DateTime.ToString(); } catch { expdate = "N/a"; }

                User.MfaCode = userObject.Blob.TwoFactorCode;
                User.Ip = await GetIp();
                User.HardwareId = GetHwid();
                User.Level = userObject.Blob.Level;
                User.Expiry = expdate;
                User.UserId = userObject.Blob.UserId;
                User.Username = username;
                #endregion

                #region "Get App Blob"
                var appBlobDictionary = new Dictionary<string, string>
                {
                    { "action", "appblob" },
                    { "session", resp.Session }
                };
                var appBlobSource = new FormUrlEncodedContent(appBlobDictionary);
                var appBlobResponse = await client.PostAsync(baseUrl, appBlobSource);
                var appBlobContent = await appBlobResponse.Content.ReadAsStringAsync();
                var appObject = JsonConvert.DeserializeObject<AppRoot>(appBlobContent);

                App.ActiveApis = appObject.Blob.ActiveApi;
                App.ApiCount = appObject.Blob.ApiCount;
                App.UserCount = appObject.Blob.UserCount;
                App.AppName = appObject.Blob.Label;
                App.AppDescription = appObject.Blob.Description;
                #endregion

                #region "Verify Hardware ID & IP"
                if (checkhwid == true)
                {
                    try
                    {
                        if (!string.Equals(GetUserVar("hwid"), User.HardwareId))
                        {
                            Environment.Exit(0);
                        }
                    }
                    catch
                    {
                        await SetUserVar("hwid", User.HardwareId);
                    }
                }
                if (checkip == true)
                {
                    try
                    {
                        if (!string.Equals(GetUserVar("ip"), User.Ip))
                        {
                            Environment.Exit(0);
                        }
                    }
                    catch
                    {
                        await SetUserVar("ip", User.Ip);
                    }
                }
                #endregion

                return resp;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public async Task<FusionResponse> Register(string username, string password, string token)
        {
            var registerDictionary = new Dictionary<string, string>
            {
                { "action", "register" },
                { "token", token },
                { "username", username },
                { "password", password }
            };

            var registerSource = new FormUrlEncodedContent(registerDictionary);
            var registerResponse = await client.PostAsync(baseUrl, registerSource);
            var registerContent = await registerResponse.Content.ReadAsStringAsync();

            try
            {
                var resp = JsonConvert.DeserializeObject<FusionResponse>(registerContent);
                if (!resp.Error) session = resp.Session;

                return resp;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<FusionResponse> ResetPassword(string oldpassword, string newpassword)
        {
            var changePassDictionary = new Dictionary<string, string>
            {
                { "action", "change-pass" },
                { "session", session },
                { "oldpassword", oldpassword },
                { "newpassword", newpassword }
            };

            var changePassSource = new FormUrlEncodedContent(changePassDictionary);
            var changePassResponse = await client.PostAsync(baseUrl, changePassSource);
            var changePassContent = await changePassResponse.Content.ReadAsStringAsync();

            try
            {
                var changePassJson = JsonConvert.DeserializeObject<FusionResponse>(changePassContent);
                return changePassJson;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<string> GetUserVar(string var)
        {
            var getUserVarDictionary = new Dictionary<string, string>
            {
                { "action", "myvars" },
                { "session", session }
            };

            var getUserVarSource = new FormUrlEncodedContent(getUserVarDictionary);
            var getUserVarResponse = await client.PostAsync(baseUrl, getUserVarSource);
            var getUserVarContent = await getUserVarResponse.Content.ReadAsStringAsync();

            try
            {
                var varObject = JsonConvert.DeserializeObject<VarRoot>(getUserVarContent);
                return varObject.Vars[var];
            }
            catch
            {
                return "Invalid Var";
            }
        }
        public static async Task SetUserVar(string key, string value)
        {
            var setUserVarDictionary = new Dictionary<string, string>
            {
                { "action", "set-user-vars" },
                { "session", session },
                { "key", key },
                { "value", value }
            };

            var setUserVarSource = new FormUrlEncodedContent(setUserVarDictionary);
            var setUserVarResponse = await client.PostAsync(baseUrl, setUserVarSource);
            await setUserVarResponse.Content.ReadAsStringAsync();
        }
        public static async Task<string> GetAppVar(string var)
        {
            var getAppVarDictionary = new Dictionary<string, string>
            {
                { "action", "get-app-vars" },
                { "session", session }
            };

            var getAppVarSource = new FormUrlEncodedContent(getAppVarDictionary);
            var getAppVarResponse = await client.PostAsync(baseUrl, getAppVarSource);
            var getAppVarContent = await getAppVarResponse.Content.ReadAsStringAsync();

            try
            {
                var varObject = JsonConvert.DeserializeObject<VarRoot>(getAppVarContent);
                return varObject.Vars[var];
            }
            catch
            {
                return "Invalid Var";
            }
        }
        public static async Task<FusionResponse> ExecuteAPI(string id, string data)
        {
            var executeApiDictionary = new Dictionary<string, string>
            {
                { "data", data }
            };

            var executeApiSource = new FormUrlEncodedContent(executeApiDictionary);
            var executeApiResponse = await client.PostAsync($"{url}executeapi/{id}", executeApiSource);
            var executeApiContent = await executeApiResponse.Content.ReadAsStringAsync();

            try
            {
                var apiResponse = JsonConvert.DeserializeObject<FusionResponse>(executeApiContent);
                return apiResponse;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<FusionResponse> ExecuteTimeAPI(string id, string data, int time)
        {
            var executeApiDictionary = new Dictionary<string, string>
            {
                { "data", data },
                { "time", time.ToString() }
            };

            var executeApiSource = new FormUrlEncodedContent(executeApiDictionary);
            var executeApiResponse = await client.PostAsync($"{url}executeapi/{id}", executeApiSource);
            var executeApiContent = await executeApiResponse.Content.ReadAsStringAsync();

            try
            {
                var apiResponse = JsonConvert.DeserializeObject<FusionResponse>(executeApiContent);
                return apiResponse;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<FusionResponse> ExecuteAuthAPI(string id, string data)
        {
            var executeApiDictionary = new Dictionary<string, string>
            {
                { "data", data },
                { "session", session }
            };

            var executeApiSource = new FormUrlEncodedContent(executeApiDictionary);
            var executeApiResponse = await client.PostAsync($"{url}executeapi/{id}", executeApiSource);
            var executeApiContent = await executeApiResponse.Content.ReadAsStringAsync();

            try
            {
                var apiResponse = JsonConvert.DeserializeObject<FusionResponse>(executeApiContent);
                return apiResponse;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<FusionResponse> ExecuteFullAPI(string id, string data, int time)
        {
            var executeApiDictionary = new Dictionary<string, string>
            {
                { "data", data },
                { "time", time.ToString() },
                { "session", session }
            };

            var executeApiSource = new FormUrlEncodedContent(executeApiDictionary);
            var executeApiResponse = await client.PostAsync($"{url}executeapi/{id}", executeApiSource);
            var executeApiContent = await executeApiResponse.Content.ReadAsStringAsync();

            try
            {
                var resp = JsonConvert.DeserializeObject<FusionResponse>(executeApiContent);
                return resp;
            }
            catch (JsonReaderException)
            {
                return new FusionResponse { Error = true, Message = "Response Was Not Valid" };
            }
        }
        public static async Task<ChatRoot> GetChat()
        {
            var getChatDictionary = new Dictionary<string, string>
            {
                { "action", "get-app-chat" },
                { "session", session }
            };

            var getChatSource = new FormUrlEncodedContent(getChatDictionary);
            var getChatResponse = await client.PostAsync(baseUrl, getChatSource);
            var getChatContent = await getChatResponse.Content.ReadAsStringAsync();
            ChatRoot chatRoot = JsonConvert.DeserializeObject<ChatRoot>(getChatContent);
            return chatRoot;
        }
        public static async Task<ManageMessageResponse> DeleteMessage(string messageid)
        {
            var deleteMessageDictionary = new Dictionary<string, string>
            {
                { "action", "del-app-msg" },
                { "mid", messageid },
                { "session", session }
            };

            var deleteMessageSource = new FormUrlEncodedContent(deleteMessageDictionary);
            var deleteMessageResponse = await client.PostAsync(baseUrl, deleteMessageSource);
            var deleteMessageContent = await deleteMessageResponse.Content.ReadAsStringAsync();
            ManageMessageResponse deleteMsgResponse = JsonConvert.DeserializeObject<ManageMessageResponse>(deleteMessageContent);
            return deleteMsgResponse;
        }
        public static async Task<ManageMessageResponse> EditMessage(string messageid, string newmessage)
        {
            var editMessageDictionary = new Dictionary<string, string>
            {
                { "action", "edit-app-msg" },
                { "mid", messageid },
                { "content", newmessage },
                { "session", session }
            };

            var editMessageSource = new FormUrlEncodedContent(editMessageDictionary);
            var editMessageResponse = await client.PostAsync(baseUrl, editMessageSource);
            var editMessageContent = await editMessageResponse.Content.ReadAsStringAsync();
            ManageMessageResponse deleteMsgResponse = JsonConvert.DeserializeObject<ManageMessageResponse>(editMessageContent);
            return deleteMsgResponse;
        }
        public static async Task<MessageRoot> SendMessage(string content)
        {
            var sendMessageDictionary = new Dictionary<string, string>
            {
                { "action", "send-app-msg" },
                { "session", session },
                { "message", content }
            };

            var sendMessageSource = new FormUrlEncodedContent(sendMessageDictionary);
            var sendMessageResponse = await client.PostAsync(baseUrl, sendMessageSource);
            var sendMessageContent = await sendMessageResponse.Content.ReadAsStringAsync();
            MessageRoot messageRoot = JsonConvert.DeserializeObject<MessageRoot>(sendMessageContent);
            return messageRoot;
        }
    }

    public class MessageRoot
    {
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("id")] public string Id { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
    }
    public class ManageMessageResponse
    {
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
    }
    public class ChatResponse
    {
        [JsonProperty("author")] public List<string> Author { get; set; }
        [JsonProperty("content")] public string Content { get; set; }
        [JsonProperty("edited")] public bool Edited { get; set; }
        [JsonProperty("message-id")] public string MessageId { get; set; }
        [JsonProperty("timestamp")] public int Timestamp { get; set; }
    }
    public class ChatRoot
    {
        [JsonProperty("chat")] public List<ChatResponse> Chat { get; set; }
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
    }

    public class AppBlob
    {
        [JsonProperty("activeapis")] public string ActiveApi { get; set; }
        [JsonProperty("apicount")] public string ApiCount { get; set; }
        [JsonProperty("usercount")] public string UserCount { get; set; }
        [JsonProperty("label")] public string Label { get; set; }
        [JsonProperty("description")] public string Description { get; set; }
    }
    public class AppRoot
    {
        [JsonProperty("blob")] public AppBlob Blob { get; set; }
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
    }

    public class UserLog
    {
        [JsonProperty("ip")] public string Ip { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
        [JsonProperty("time")] public string Time { get; set; }
    }
    public class UserBlob
    {
        [JsonProperty("2fa-code")] public string TwoFactorCode { get; set; }
        [JsonProperty("expiry")] public string Expiry { get; set; }
        [JsonProperty("ip")] public string Ip { get; set; }
        [JsonProperty("level")] public int Level { get; set; }
        [JsonProperty("logs")] public List<UserLog> Logs { get; set; }
        [JsonProperty("uid")] public string UserId { get; set; }
        [JsonProperty("using2fa")] public bool Using2fa { get; set; }
    }
    public class UserRoot
    {
        [JsonProperty("blob")] public UserBlob Blob { get; set; }
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
    }

    public struct VarRoot
    {
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
        [JsonProperty("vars")] public Dictionary<string, string> Vars { get; set; }
    }

    public struct FusionResponse
    {
        [JsonProperty("error")] public bool Error { get; set; }
        [JsonProperty("session")] public string Session { get; set; }
        [JsonProperty("message")] public string Message { get; set; }
        [JsonProperty("response")] public string Response { get; set; }
        [JsonProperty("status")] public string Status { get; set; }
        [JsonProperty("blob")] public string Blob { get; set; }
    }

    public struct App
    {
        public static string ActiveApis;
        public static string ApiCount;
        public static string UserCount;
        public static string AppName;
        public static string AppDescription;
    }
    public struct User
    {
        public static bool ValidateTwoFactor = false;
        public static string MfaCode;
        public static string Ip;
        public static string HardwareId;
        public static int Level;
        public static string Expiry;
        public static string Username;
        public static string UserId;
    }
}
