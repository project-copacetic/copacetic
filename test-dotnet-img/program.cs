using System;
using Newtonsoft.Json;

class Program
{
    static void Main()
    {
        Console.WriteLine("Hello, vulnerable world!");

        // Trigger basic Newtonsoft.Json usage
        var obj = JsonConvert.DeserializeObject("{\"greeting\":\"hello\"}");
        Console.WriteLine("Parsed JSON: " + obj);
    }
}
