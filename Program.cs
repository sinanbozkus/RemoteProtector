using System;
using WindowsFirewallHelper;
using System.Linq;
using Microsoft.Extensions.Configuration;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using WindowsFirewallHelper.FirewallRules;
using WindowsFirewallHelper.Addresses;
using System.Net;
using System.Collections.Generic;
using System.Threading;

namespace RemoteProtector
{
    class Program
    {
        public static IConfiguration Configuration { get; set; }

        static async Task Main(string[] args)
        {
            // Application Settings.

            using IHost host = CreateHostBuilder(args).Build();

            AppSettings settings = new();
            Configuration.Bind(settings);

            // Checking Firewall

            if (FirewallWAS.IsSupported == false && FirewallWASRuleWin8.IsSupported == false)
            {
                if (settings.DebugMode)
                {
                    // todo logs...
                }
                Console.WriteLine("There is no support for FirewallWASRuleWin8.");
            }

            Interval.Set(() =>
            {

                // Step 1 - Deleting current rules if exists.

                var currentRules = FirewallManager.Instance.Rules.Where(x => x.Name.ToLower() == "remote protector").ToList();

                if (currentRules.Any())
                {
                    foreach (var rule in currentRules)
                    {
                        FirewallManager.Instance.Rules.Remove(rule);
                    }

                    if (settings.DebugMode) Console.WriteLine($"Current rules rules deleted.");
                }

                // Step 2 - Resolving ip addreses from hostnames and creating an IP list.

                List<string> ipAddreses = new();

                if(settings.Hostnames != null && settings.Hostnames.Any())
                {
                    foreach (var hostname in settings.Hostnames)
                    {
                        try
                        {
                            if (settings.DebugMode) Console.WriteLine($"Hostname {hostname} is checking...");

                            var ipAddress = Dns.GetHostAddresses(hostname);
                            ipAddreses.Add(ipAddress[0].ToString());

                            if (settings.DebugMode) Console.WriteLine($"IP found {ipAddreses[0]} for {hostname}");
                        }
                        catch (Exception ex)
                        {
                            if (settings.DebugMode) { Console.WriteLine($"Error: {ex.Message}"); }
                        }
                    }
                }

                if(settings.IpAddresses != null && settings.IpAddresses.Any())
                {
                    ipAddreses.AddRange(settings.IpAddresses);
                }
                

                // Step 3 - Creating new rule.

                var newIpAddreses = ipAddreses.Select(ip => new SingleIP(IPAddress.Parse(ip))).Distinct().ToArray();

                var newRule = new FirewallWASRuleWin8(
                    "Remote Protector",
                    FirewallAction.Allow,
                    FirewallDirection.Inbound,
                    FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public

                )
                {
                    Description = "https://github.com/sinanbozkus/RemoteProtector",
                    NetworkInterfaceTypes = NetworkInterfaceTypes.RemoteAccess | NetworkInterfaceTypes.Lan | NetworkInterfaceTypes.Wireless,
                    Protocol = FirewallProtocol.TCP,
                    RemoteAddresses = newIpAddreses,
                    LocalPorts = settings.Ports
                };
                FirewallWAS.Instance.Rules.Add(newRule);

                if (settings.DebugMode) Console.WriteLine($"New firewall rule added.");

            }, settings.TimePeriod * 60000);

            await host.RunAsync();
        }

        static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, configuration) =>
                {
                    configuration
                        .AddJsonFile("settings.json", optional: true, reloadOnChange: true);

                    Configuration = configuration.Build();
                })
                .UseWindowsService();
    }
}
