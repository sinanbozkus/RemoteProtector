namespace RemoteProtector
{
    public class AppSettings
    {
        public string[] IpAddresses { get; set; }
        public string[] Hostnames { get; set; }
        public ushort[] Ports { get; set; }
        public int TimePeriod { get; set; }
        public bool DebugMode { get; set; }
    }
}
