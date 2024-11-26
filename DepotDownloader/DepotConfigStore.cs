// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using ProtoBuf;

namespace DepotDownloader
{
    [ProtoContract]
    public class DepotConfigStore
    {
        [ProtoMember(1)]
        public Dictionary<uint, ulong> InstalledManifestIDs { get; private set; }

        [ProtoMember(2)]
        public Dictionary<ulong, ulong> InstalledUGCManifestIDs { get; } = new Dictionary<ulong, ulong>();

        string FileName;

        DepotConfigStore()
        {
            InstalledManifestIDs = [];
        }

        static bool Loaded
        {
            get { return Instance != null; }
        }

        public static DepotConfigStore Instance;

        public static void LoadFromFile(string filename)
        {
            if (Instance != null)
                throw new Exception("Config already loaded");
            Instance = LoadInstanceFromFile(filename);
        }

        public static DepotConfigStore LoadInstanceFromFile(string filename)
        {
            DepotConfigStore DepotConfigStore;
            if (File.Exists(filename))
            {
                using var fs = File.Open(filename, FileMode.Open);
                using var ds = new DeflateStream(fs, CompressionMode.Decompress);
                DepotConfigStore = Serializer.Deserialize<DepotConfigStore>(ds);
            }
            else
            {
                DepotConfigStore = new DepotConfigStore();
            }

            DepotConfigStore.FileName = filename;
            return DepotConfigStore;
        }

        public static void Save()
        {
            if (!Loaded)
                throw new Exception("Saved config before loading");

            using var fs = File.Open(Instance.FileName, FileMode.Create);
            using var ds = new DeflateStream(fs, CompressionMode.Compress);
            Serializer.Serialize(ds, Instance);
        }
    }
}
