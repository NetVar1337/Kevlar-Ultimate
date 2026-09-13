#pragma once
#include "include/common.h"

// REGHANDLE: typedef from evntprov.h; defined locally to avoid the SDK header.
#ifndef _REGHANDLE_DEFINED
typedef ULONG64 REGHANDLE;
#define _REGHANDLE_DEFINED
#endif

NTSTATUS h_EtwRegister(const GUID* ProviderId, void* EnableCallback, void* CallbackContext, REGHANDLE* RegHandle);
NTSTATUS h_EtwUnregister(REGHANDLE RegHandle);
NTSTATUS h_EtwWrite(REGHANDLE RegHandle, void* EventDescriptor, ULONG UserDataCount, void* UserData);
NTSTATUS h_EtwWriteTransfer(REGHANDLE RegHandle, void* EventDescriptor, const GUID* ActivityId, const GUID* RelatedActivityId, ULONG UserDataCount, void* UserData);
