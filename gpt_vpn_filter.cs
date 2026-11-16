using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

// User-mode Windows Filtering Platform. No driver, route changes, or DNS polling.
public static class GptVpnFilter
{
    private static readonly Guid Owner = new Guid("5f7c0c61-4a3d-4981-a9f6-b7fc0ab24dd8");
    private static readonly Guid[] Layers = {
        new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), // ALE_AUTH_CONNECT_V4
        new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")  // ALE_AUTH_CONNECT_V6
    };
    private static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid PackageId = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
    private static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    private static readonly Guid NextHop = new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04");
    private static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    private const uint Persistent = 1, Block = 0x1001, SoftPermit = 0x1002;
    private const uint AlreadyExists = 0x80320009, NoSublayer = 0x80320007;
    private const uint Equal = 0, FlagsAllSet = 6, MatchSuffix = 11; // SDK: FWP_MATCH_PREFIX
    private const uint UInt8 = 1, UInt32 = 3, UInt64 = 4, ByteBlob = 12, Sid = 13;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Display { public string Name, Description; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Value { public uint Type; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Condition { public Guid Key; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Sublayer {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider;
        public Blob ProviderData; public ushort Weight;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit)]
    private struct Context {
        [FieldOffset(0)] public ulong Raw;
        [FieldOffset(0)] public Guid Key;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Filter {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider;
        public Blob ProviderData; public Guid Layer, Sublayer; public Value Weight;
        public uint Count; public IntPtr Conditions; public Action Action; public Context Context;
        public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineOpen0(IntPtr server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer layer, IntPtr security);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint limit, out IntPtr entries, out uint count);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr blob);
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint DeriveAppContainerSidFromAppContainerName(string family, out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);

    private static IntPtr GetPackageSid(string family)
    {
        IntPtr sid;
        Check(DeriveAppContainerSidFromAppContainerName(family, out sid), "Identify OpenAI package " + family);
        return sid;
    }

    private static void Check(uint code, string operation)
    {
        if (code != 0) throw new InvalidOperationException(operation + " failed (0x" + code.ToString("X8") + ").");
    }

    private static IntPtr Open()
    {
        IntPtr engine;
        Check(FwpmEngineOpen0(IntPtr.Zero, 10 /* RPC_C_AUTHN_WINNT */, IntPtr.Zero, IntPtr.Zero, out engine), "Open WFP engine");
        return engine;
    }

    private static List<Guid> OwnedFilters(IntPtr engine)
    {
        var keys = new List<Guid>();
        IntPtr handle;
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out handle), "Enumerate WFP filters");
        try {
            int sublayerOffset = Marshal.OffsetOf(typeof(Filter), "Sublayer").ToInt32();
            uint count;
            do {
                IntPtr entries;
                Check(FwpmFilterEnum0(engine, handle, 256, out entries, out count), "Read WFP filters");
                try {
                    for (int i = 0; i < count; i++) {
                        IntPtr filter = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        if ((Guid)Marshal.PtrToStructure(IntPtr.Add(filter, sublayerOffset), typeof(Guid)) == Owner)
                            keys.Add((Guid)Marshal.PtrToStructure(filter, typeof(Guid)));
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            } while (count == 256);
        } finally { FwpmFilterDestroyEnumHandle0(engine, handle); }
        return keys;
    }

    private static Condition Match(Guid key, uint match, uint type, IntPtr value)
    {
        return new Condition { Key = key, Match = match, Value = new Value { Type = type, Data = value } };
    }

    private static void Add(IntPtr engine, Guid layer, string target, string purpose, uint action, int weight, bool persistent, params Condition[] conditions)
    {
        int size = Marshal.SizeOf(typeof(Condition));
        IntPtr data = Marshal.AllocHGlobal(size * conditions.Length);
        try {
            for (int i = 0; i < conditions.Length; i++)
                Marshal.StructureToPtr(conditions[i], IntPtr.Add(data, size * i), false);
            var filter = new Filter {
                Display = new Display { Name = "GPT VPN: " + purpose + " / " + target }, Flags = persistent ? Persistent : 0,
                Layer = layer, Sublayer = Owner, Weight = new Value { Type = UInt8, Data = new IntPtr(weight) },
                Count = (uint)conditions.Length, Conditions = data, Action = new Action { Type = action }
            };
            ulong id;
            Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "Install " + filter.Display.Name);
        } finally { Marshal.FreeHGlobal(data); }
    }

    private static void AddTarget(IntPtr engine, string target, Condition identity, IntPtr luid)
    {
        var loopback = Match(Flags, FlagsAllSet, UInt32, new IntPtr(1)); // FWP_CONDITION_FLAG_IS_LOOPBACK
        foreach (Guid layer in Layers) {
            // The higher-weight soft permits skip only our own block. Other WFP
            // providers (Defender Firewall, VPN client, etc.) may still block.
            Add(engine, layer, target, "block outside VPN", Block, 1, true, identity);
            Add(engine, layer, target, "allow local IPC", SoftPermit, 3, true, identity, loopback);
            if (luid != IntPtr.Zero) {
                // Do not persist an old tunnel's LUID across BFE restart. Only
                // the deny policy survives; reapply to verify the VPN again.
                Add(engine, layer, target, "allow selected VPN", SoftPermit, 2, false, identity,
                    Match(LocalInterface, Equal, UInt64, luid), Match(NextHop, Equal, UInt64, luid));
            }
        }
    }

    public static int Count()
    {
        IntPtr engine = Open();
        try { return OwnedFilters(engine).Count; }
        finally { FwpmEngineClose0(engine); }
    }

    // A single transaction replaces both address families, or keeps the old policy intact.
    // An empty adapter GUID installs the block without a tunnel exception.
    public static int Apply(Guid adapter, string[] executableNames, string[] exactPaths, string[] packages)
    {
        int targets = executableNames.Length + exactPaths.Length + packages.Length;
        if (targets == 0) throw new ArgumentException("No executable targets.");
        IntPtr engine = Open(), luid = IntPtr.Zero;
        try {
            if (adapter != Guid.Empty) {
                ulong value;
                Check(ConvertInterfaceGuidToLuid(ref adapter, out value), "Identify the selected VPN interface");
                luid = Marshal.AllocHGlobal(sizeof(ulong));
                Marshal.WriteInt64(luid, unchecked((long)value));
            }
            Check(FwpmTransactionBegin0(engine, 0), "Start WFP transaction");
            try {
                var sublayer = new Sublayer { Key = Owner, Flags = Persistent, Weight = UInt16.MaxValue,
                    Display = new Display { Name = "VPN_WORK: GPT VPN guard" } };
                uint code = FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero);
                if (code != AlreadyExists) Check(code, "Create GPT VPN sublayer");
                foreach (Guid old in OwnedFilters(engine)) {
                    Guid key = old;
                    Check(FwpmFilterDeleteByKey0(engine, ref key), "Replace previous GPT VPN filter");
                }
                foreach (string name in executableNames) {
                    byte[] bytes = Encoding.Unicode.GetBytes("\\" + name.ToLowerInvariant() + "\0");
                    IntPtr data = Marshal.AllocHGlobal(bytes.Length), blob = IntPtr.Zero;
                    try {
                        Marshal.Copy(bytes, 0, data, bytes.Length);
                        blob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Blob)));
                        Marshal.StructureToPtr(new Blob { Size = (uint)bytes.Length, Data = data }, blob, false);
                        AddTarget(engine, name, Match(AppId, MatchSuffix, ByteBlob, blob), luid);
                    } finally {
                        if (blob != IntPtr.Zero) Marshal.FreeHGlobal(blob);
                        Marshal.FreeHGlobal(data);
                    }
                }
                foreach (string path in exactPaths) {
                    IntPtr app;
                    Check(FwpmGetAppIdFromFileName0(path, out app), "Get application ID: " + path);
                    try { AddTarget(engine, path, Match(AppId, Equal, ByteBlob, app), luid); }
                    finally { FwpmFreeMemory0(ref app); }
                }
                foreach (string family in packages) {
                    IntPtr sid = GetPackageSid(family);
                    try { AddTarget(engine, family, Match(PackageId, Equal, Sid, sid), luid); }
                    finally { FreeSid(sid); }
                }
                Check(FwpmTransactionCommit0(engine), "Commit GPT VPN policy");
            } catch { FwpmTransactionAbort0(engine); throw; }
            int installed = OwnedFilters(engine).Count;
            int expected = targets * Layers.Length * (luid == IntPtr.Zero ? 2 : 3);
            if (installed != expected)
                throw new InvalidOperationException("WFP readback found " + installed + " of " + expected + " expected GPT VPN filters.");
            return installed;
        } finally {
            if (luid != IntPtr.Zero) Marshal.FreeHGlobal(luid);
            FwpmEngineClose0(engine);
        }
    }

    public static int Remove()
    {
        IntPtr engine = Open();
        try {
            Check(FwpmTransactionBegin0(engine, 0), "Start WFP transaction");
            try {
                var filters = OwnedFilters(engine);
                foreach (Guid old in filters) {
                    Guid key = old;
                    Check(FwpmFilterDeleteByKey0(engine, ref key), "Remove GPT VPN filter");
                }
                Guid sublayer = Owner;
                uint code = FwpmSubLayerDeleteByKey0(engine, ref sublayer);
                if (code != NoSublayer) Check(code, "Remove GPT VPN sublayer");
                Check(FwpmTransactionCommit0(engine), "Commit GPT VPN removal");
                return filters.Count;
            } catch { FwpmTransactionAbort0(engine); throw; }
        } finally { FwpmEngineClose0(engine); }
    }
}
