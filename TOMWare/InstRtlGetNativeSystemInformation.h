#pragma once
#ifndef INST_RTL_GET_NATIVE_SYSTEM_INFORMATION_H
#define INST_RTL_GET_NATIVE_SYSTEM_INFORMATION_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <deque>
#include <queue>
#include "utils.h"
#include "Instrumentation.h"
#include "InstrumentationStrategy.h"
#include "NtStructures.h"

struct RtlGetNativeSystemInformationArgs {
    ADDRINT SystemInformationClass;
    ADDRINT SystemInformation;
    ADDRINT SystemInformationLength;
    ADDRINT ReturnLength;
};

class InstRtlGetNativeSystemInformation : public InstrumentationStrategy {
public:
    static VOID InstrumentFunction(RTN rtn, VOID* printFcn);

private:
    static VOID CallbackBefore(THREADID tid, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
        ADDRINT SystemInformationClass, ADDRINT SystemInformation, ADDRINT SystemInformationLength, ADDRINT ReturnLength);
    static VOID CallbackAfter(THREADID tid, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT retVal, ADDRINT ReturnLength);
};

#endif // INST_RTL_GET_NATIVE_SYSTEM_INFORMATION_H
