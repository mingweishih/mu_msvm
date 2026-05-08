/** @file
  Header for the OpenHCL paravisor SEV-SNP CC blob handoff.

  POC contract - replace with proper BiosConfig handoff before upstreaming.
  See the matching crate at
  vm/devices/firmware/openhcl_uefi_handoff/src/lib.rs in the OpenHCL repo
  for the canonical schema; this header MUST stay in sync.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef OPENHCL_SNP_CC_BLOB_HANDOFF_H
#define OPENHCL_SNP_CC_BLOB_HANDOFF_H

#include <Base.h>

//
// Magic value identifying a SnpCcBlobHandoff. ASCII "OHSNPCCB" little-endian.
//
#define OPENHCL_SNP_CC_BLOB_HANDOFF_MAGIC   0x424343504E53484FULL // 'OHSNPCCB'

//
// Schema version. Must match SNP_CC_BLOB_HANDOFF_VERSION on the host side.
//
#define OPENHCL_SNP_CC_BLOB_HANDOFF_VERSION 1U

//
// Fixed GPA where the OpenHCL paravisor plants the handoff struct.
// Lives inside the 0x709000-0x800000 UEFI-config window the paravisor
// already pre-validates for VTL0.
//
#define OPENHCL_SNP_CC_BLOB_HANDOFF_GPA     0x70F000ULL

//
// Page size of one secrets/CPUID page referenced by the handoff.
//
#define OPENHCL_SNP_CC_BLOB_PAGE_SIZE       0x1000ULL

//
// Flag bits for OPENHCL_SNP_CC_BLOB_HANDOFF.Flags.
//
#define OPENHCL_SNP_CC_BLOB_HANDOFF_FLAG_PRESENT   BIT0

#pragma pack(1)

typedef struct {
  UINT64    Magic;        // OPENHCL_SNP_CC_BLOB_HANDOFF_MAGIC
  UINT32    Version;      // OPENHCL_SNP_CC_BLOB_HANDOFF_VERSION
  UINT32    Flags;        // see *_FLAG_* above
  UINT64    SecretsGpa;   // page-aligned
  UINT64    SecretsSize;  // OPENHCL_SNP_CC_BLOB_PAGE_SIZE
  UINT64    CpuidGpa;     // page-aligned
  UINT64    CpuidSize;    // OPENHCL_SNP_CC_BLOB_PAGE_SIZE
  UINT8     Reserved[16]; // zero
} OPENHCL_SNP_CC_BLOB_HANDOFF;

#pragma pack()

STATIC_ASSERT (
  sizeof (OPENHCL_SNP_CC_BLOB_HANDOFF) == 64,
  "OPENHCL_SNP_CC_BLOB_HANDOFF must be 64 bytes"
  );

#endif // OPENHCL_SNP_CC_BLOB_HANDOFF_H
