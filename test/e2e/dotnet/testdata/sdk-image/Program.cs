using Newtonsoft.Json;
Console.WriteLine("Vulnerable Newtonsoft.Json version in use: " + typeof(JsonConvert).Assembly.GetName().Version);
