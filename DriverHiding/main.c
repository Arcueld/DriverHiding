#include <ntifs.h>    

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
    );
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;
typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;
typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;
typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
typedef struct _LDRP_LOAD_CONTEXT* PLDRP_LOAD_CONTEXT;
typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;
typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    PLDRP_LOAD_CONTEXT LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason; // since WIN8
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum; // since 22H1
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef NTKERNELAPI NTSTATUS(NTAPI* pObReferenceObjectByName)(
    _In_ PUNICODE_STRING 	ObjectName,
    _In_ ULONG 	Attributes,
    _In_opt_ PACCESS_STATE 	PassedAccessState,
    _In_opt_ ACCESS_MASK 	DesiredAccess,
    _In_ POBJECT_TYPE 	ObjectType,
    _In_ KPROCESSOR_MODE 	AccessMode,
    _Inout_opt_ PVOID 	ParseContext,
    _Out_ PVOID* Object
);

ERESOURCE PsLoadedModuleResource;
KSPIN_LOCK PsLoadedModuleSpinLock;
LIST_ENTRY PsLoadedModuleList;


typedef VOID (NTAPI* pMiProcessLoaderEntry)(IN PLDR_DATA_TABLE_ENTRY LdrEntry, IN BOOLEAN Insert);


VOID NTAPI MiProcessLoaderEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry,IN BOOLEAN Insert){
    KIRQL OldIrql;

    /* Acquire module list lock */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);

    /* Acquire the spinlock too as we will insert or remove the entry */
    OldIrql = KeAcquireSpinLockRaiseToSynch(&PsLoadedModuleSpinLock);

    /* Insert or remove from the list */
    if (Insert)
        InsertTailList(&PsLoadedModuleList, &LdrEntry->InLoadOrderLinks);
    else
        RemoveEntryList(&LdrEntry->InLoadOrderLinks);

    /* Release locks */
    KeReleaseSpinLock(&PsLoadedModuleSpinLock, OldIrql);
    ExReleaseResourceLite(&PsLoadedModuleResource);
    KeLeaveCriticalRegion();
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unload!");
}

void DriverHiding(PDRIVER_OBJECT DriverObject) {
    LARGE_INTEGER times;
    times.QuadPart = -50 * 1000 * 1000;  // 5s
    KeDelayExecutionThread(KernelMode, FALSE, &times);

    DriverObject->DriverSection = NULL;

}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

    PLDR_DATA_TABLE_ENTRY pldr = (PLDR_DATA_TABLE_ENTRY)(DriverObject->DriverSection);
    

    // method 0
  
    // __try {
    //     RemoveEntryList(&pldr->InLoadOrderLinks);
    //     HANDLE hThread;
    //     PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)DriverHiding, DriverObject);
    // }
    // __except (EXCEPTION_EXECUTE_HANDLER){
    //     DbgPrint("0x%x\n", GetExceptionCode());
    //     return GetExceptionCode();
    // }
    
    // method 1 based on MiProcessLoaderEntry

    pMiProcessLoaderEntry myMiProcessLoaderEntry = NULL;
    PLIST_ENTRY sysList = &pldr->InLoadOrderLinks;
    PLIST_ENTRY current = sysList->Flink;
    UNICODE_STRING ntoskrnl = { 0 };
    RtlInitUnicodeString(&ntoskrnl, L"ntoskrnl.exe");

    // get MiProcessLoaderEntry Function
    while (current != sysList) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;
        if (RtlCompareUnicodeString(&entry->BaseDllName, &ntoskrnl, TRUE) == 0) {
            myMiProcessLoaderEntry = (pMiProcessLoaderEntry)((DWORD_PTR)entry->DllBase + 0x7bb37);
            break;
        }
        current = current->Flink;
    }

    __try{
        HANDLE hThread;
        DbgBreakPoint();
        //MiProcessLoaderEntry(pldr, 0);
        if (myMiProcessLoaderEntry) {
            myMiProcessLoaderEntry(pldr, 0);
        }
        PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)DriverHiding, DriverObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("0x%x\n", GetExceptionCode());
        return GetExceptionCode();
    }
    
    DriverObject->DriverUnload = UnloadDriver;

    return STATUS_SUCCESS;
}