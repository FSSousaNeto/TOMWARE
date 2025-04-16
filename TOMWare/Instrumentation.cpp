#include "Instrumentation.h"

PIN_LOCK lock;

static std::ofstream MainOutFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "tomware", "specify file name for output logs ");

std::map<std::string, RTNFunction> strategyMap;

void InitStrategies() {
    strategyMap["RtlGetNativeSystemInformation"] = &InstRtlGetNativeSystemInformation::InstrumentFunction;
}

VOID printFcn(const std::string& outputText) {
    MainOutFile << outputText;
    MainOutFile.flush();  // Esvazia o buffer de saída
}

VOID InstrumentFunctions(IMG img, VOID* v) {
    std::string moduleName = IMG_Name(img);
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
        if (RTN_Valid(rtn)) {
            std::string funcName = RTN_Name(rtn);

            for (const auto& pair : strategyMap) {
                std::string strategyName = pair.first.c_str();
                if (strategyName == funcName) {
                    RTNFunction func = pair.second;
                    func(rtn, &printFcn);
                }
            }

        }
    }
}

VOID configOutput() {
    using namespace WindowsAPI;
    std::setlocale(LC_ALL, "en_US.UTF-8"); // Definir o local adequado
    SetConsoleOutputCP(CP_UTF8); // Configura o console para UTF-8
    std::wcout.imbue(std::locale("")); // Configura a sa�da wide para usar a codifica��o local
    std::cout.imbue(std::locale("")); // Configura a sa�da wide para usar a codifica��o local
    MainOutFile.imbue(std::locale(""));
    MainOutFile << "\xEF\xBB\xBF"; // Adiciona BOM para indicar UTF-8
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v) {
    std::cerr << "Exce��o detectada no thread " << tid << ": "
        << PIN_ExceptionToString(pExceptInfo) << std::endl;
    exit(1);
    return EXCEPT_HANDLING_RESULT::EHR_HANDLED;
    // Pode-se modificar o contexto ou apenas registrar o erro
}

int InitInstrumentation()
{

    // Obter o PID do Processo
    string pid = decstr(WindowsAPI::getpid());


    // Log Principal
    string logsName = KnobOutputFile.Value();
    string logfilename = logsName + "." + pid + ".log.cdf";
    MainOutFile.open(logfilename.c_str(), std::ios::binary);


    // Iniciar o PIN e instrumenta��o
    PIN_InitLock(&lock);
    PIN_InitSymbols();

    IMG_AddInstrumentFunction(InstrumentFunctions, 0);

    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    PIN_StartProgram();
    return 0;
}