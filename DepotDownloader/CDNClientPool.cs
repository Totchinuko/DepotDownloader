// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SteamKit2.CDN;

namespace DepotDownloader
{
    /// <summary>
    /// CDNClientPool provides a pool of connections to CDN endpoints, requesting CDN tokens as needed
    /// </summary>
    public class CDNClientPool
    {
        private readonly Steam3Session steamSession;
        private readonly List<uint> appIds;
        public Client CDNClient { get; }
        public Server ProxyServer { get; private set; }

        private readonly List<Server> servers = [];
        private int nextServer;

        public CDNClientPool(Steam3Session steamSession, List<uint> appIds)
        {
            this.steamSession = steamSession;
            this.appIds = appIds;
            CDNClient = new Client(steamSession.steamClient);
        }

        public async Task UpdateServerList()
        {
            var servers = await this.steamSession.steamContent.GetServersForSteamPipe();

            ProxyServer = servers.Where(x => x.UseAsProxy).FirstOrDefault();

                    var weightedCdnServers = servers
                        .Where(server =>
                        {
                            var isEligibleForApp = server.AllowedAppIds.Length == 0 || server.AllowedAppIds.Intersect(appIds).Count() == appIds.Count;
                            return isEligibleForApp && (server.Type == "SteamCache" || server.Type == "CDN");
                        })
                        .Select(server =>
                        {
                            AccountSettingsStore.Instance.ContentServerPenalty.TryGetValue(server.Host, out var penalty);

                    return (server, penalty);
                })
                .OrderBy(pair => pair.penalty).ThenBy(pair => pair.server.WeightedLoad);

            foreach (var (server, weight) in weightedCdnServers)
            {
                for (var i = 0; i < server.NumEntries; i++)
                {
                    this.servers.Add(server);
                }
            }

            if (this.servers.Count == 0)
            {
                throw new Exception("Failed to retrieve any download servers.");
            }
        }

        public Server GetConnection()
        {
            return servers[nextServer % servers.Count];
        }

        public void ReturnConnection(Server server)
        {
            if (server == null) return;

            // nothing to do, maybe remove from ContentServerPenalty?
        }

        public void ReturnBrokenConnection(Server server)
        {
            if (server == null) return;

            lock (servers)
            {
                if (servers[nextServer % servers.Count] == server)
                {
                    nextServer++;

                    // TODO: Add server to ContentServerPenalty
                }
            }
        }
    }
}
