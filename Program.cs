using Serilog;
using Serilog.Formatting.Compact;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, _, loggerConfiguration) =>
{
    // Development console logging will be setup automatically from ReadFrom.Configuration
    loggerConfiguration.ReadFrom.Configuration(builder.Configuration);

    // Add file logging without JSON formatting to demonstrate log injection vulnerability
    loggerConfiguration
        .Enrich.FromLogContext()
        .WriteTo.File("logs/app.log", 
            rollingInterval: RollingInterval.Day,
            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}");
    
    if (!context.HostingEnvironment.IsDevelopment())
    {
        loggerConfiguration
            .Enrich.FromLogContext()
            .WriteTo.Console(formatter: new RenderedCompactJsonFormatter());
    }
});

// Add services to the container.

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseSerilogRequestLogging();

app.UseAuthorization();

app.MapControllers();

app.Run();
