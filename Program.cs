using Serilog;
using Serilog.Formatting.Compact;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, _, loggerConfiguration) =>
{
    // Development console logging will be setup automatically from ReadFrom.Configuration
    loggerConfiguration.ReadFrom.Configuration(builder.Configuration);

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
