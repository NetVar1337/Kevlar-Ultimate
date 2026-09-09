#pragma once

#include "include/common.h"

BOOLEAN h_RtlInitWeakEnumerationHashTable(PVOID HashTable, PVOID Enumerator);
PVOID h_RtlWeaklyEnumerateEntryHashTable(PVOID HashTable, PVOID Enumerator);
void h_RtlEndWeakEnumerationHashTable(PVOID HashTable, PVOID Enumerator);
