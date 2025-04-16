#include "InstRtlGetNativeSystemInformation.h"

static CallContext* RtlGetNativeSystemInformationCallContext;
static VOID (*RtlGetNativeSystemInformationPrintFcn)(const std::string&);

VOID printParentProcess(DWORD parentProcessId) {
    using namespace WindowsAPI;

    // Abrir o processo pai para obter o nome
    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentProcessId);
    if (hParentProcess) {

        WCHAR parentProcessName[MAX_PATH] = { 0 };
        if (GetModuleBaseName(hParentProcess, nullptr, parentProcessName, MAX_PATH)) {
            std::wstring ppName(parentProcessName);
            std::string pName = WStringToString(ppName);
            if (ppName == L"pin.exe") {
                std::cout << "[CONTRADEF] Instrumentador PIN detectado. (nome do processo pai: " << pName << ")" << std::endl;
            }
            else {
                std::cout << "[CONTRADEF] Instrumentador PIN não detectado. (nome do processo pai: " << pName << ")" << std::endl;
            }
        }
        else {
            std::cerr << "[CONTRADEF] Erro ao obter o nome do processo pai.\n";
        }
        CloseHandle(hParentProcess);
    }
    else {
        std::cerr << "[CONTRADEF] Erro ao abrir o processo pai.\n";
    }
}

VOID InstRtlGetNativeSystemInformation::CallbackBefore(THREADID tid, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT SystemInformationClass, ADDRINT SystemInformation, ADDRINT SystemInformationLength, ADDRINT ReturnLength) {

    if (!IsMainExecutable(returnAddress)) {
        return;
    }

    RtlGetNativeSystemInformationArgs* args = new RtlGetNativeSystemInformationArgs;
    args->SystemInformationClass = SystemInformationClass;
    args->SystemInformation = SystemInformation;
    args->SystemInformationLength = SystemInformationLength;
    args->ReturnLength = ReturnLength;

    RtlGetNativeSystemInformationCallContext = new CallContext(tid, instAddress, &args);

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = RtlGetNativeSystemInformationCallContext->stringStream;

    stringStream << std::endl << "[+] RtlGetNativeSystemInformation..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        SystemInformationClass: " << SystemInformationClass << std::endl;
    stringStream << "        SystemInformation: " << std::hex << SystemInformation << std::dec << std::endl;
    stringStream << "        SystemInformationLength: " << SystemInformationLength << " bytes" << std::endl;
    stringStream << "        ReturnLength (Endereço): " << std::hex << ReturnLength << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da obtenção de informações do sistema" << std::endl;

}

VOID InstRtlGetNativeSystemInformation::CallbackAfter(THREADID tid, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT ReturnLength) {

    if (!IsMainExecutable(returnAddress)) {
        return;
    }
    PIN_LockClient();
    std::stringstream stringStream;
    const RtlGetNativeSystemInformationArgs* args = reinterpret_cast<const RtlGetNativeSystemInformationArgs*>(RtlGetNativeSystemInformationCallContext->functionArgs);

    ULONG returnLengthValue = 0;
    if (ReturnLength != 0) {
        PIN_SafeCopy(&returnLengthValue, reinterpret_cast<ULONG*>(args->ReturnLength), sizeof(ULONG));
    }

    stringStream << "    Valor de retorno: " << std::hex << returnAddress << std::dec << std::endl;
    if (ReturnLength != 0) {
        stringStream << "    ReturnLength: " << returnLengthValue << " bytes" << std::endl;
    }
    stringStream << "  [-] Obtenção de informações do sistema concluída" << std::endl;

    // CONTRAMEDIDA
    if (args->SystemInformationClass == 5) {
        using namespace WindowsAPI;
        DWORD currentProcessId = GetCurrentProcessId();

        PSYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(args->SystemInformation);
        while (processInfo) {
            if (reinterpret_cast<DWORD>(processInfo->UniqueProcessId) == currentProcessId) {
                stringStream << "  [-] Aplicando contramedida" << std::endl;

                DWORD* parentProcessId = reinterpret_cast<DWORD*>(&(processInfo->Reserved2));
                DWORD fakePID = GetProcessIdByName("explorer.exe");
                stringStream << "    Substituindo o PID do processo pai (pin.exe - " << *parentProcessId << ") pelo do explorer.exe (" << fakePID << ")" << std::endl;
                *parentProcessId = fakePID;
                stringStream << "  [-] Contramedida aplicada" << std::endl;

                break;
            }

            // Avançar para o próximo processo
            if (processInfo->NextEntryOffset == 0) {
                break;
            }
            processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset
                );
        }
    }
    /////

    stringStream << "[*] Concluído" << std::endl << std::endl;

    RtlGetNativeSystemInformationPrintFcn(stringStream.str());

    delete reinterpret_cast<RtlGetNativeSystemInformationArgs*>(RtlGetNativeSystemInformationCallContext->functionArgs);
    PIN_UnlockClient();
}

VOID InstRtlGetNativeSystemInformation::InstrumentFunction(RTN rtn, VOID* printFcn) {

    std::string rtnName = RTN_Name(rtn);
    RtlGetNativeSystemInformationPrintFcn = reinterpret_cast<void(*)(const std::string&)>(printFcn);

    if (rtnName == "RtlGetNativeSystemInformation") {

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // SystemInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // SystemInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // SystemInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // ReturnLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // ReturnLength
            IARG_END);

        RTN_Close(rtn);
    }
}
