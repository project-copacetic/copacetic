using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => 
{
    var version = typeof(JsonConvert).Assembly.GetName().Version;
    return new
    {
        message = "Hello from vulnerable .NET app!",
        newtonsoftVersion = version?.ToString() ?? "unknown"
    };
});

app.Run();
