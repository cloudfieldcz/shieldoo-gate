using Newtonsoft.Json;

var info = new
{
    Name = "Shieldoo Gate",
    Version = "1.0.0",
    Secure = true,
};

Console.WriteLine("Newtonsoft.Json 13.0.3 installed successfully!\n");
Console.WriteLine("Serialized JSON:");
Console.WriteLine(JsonConvert.SerializeObject(info, Formatting.Indented));
Console.WriteLine("\nDone!");
