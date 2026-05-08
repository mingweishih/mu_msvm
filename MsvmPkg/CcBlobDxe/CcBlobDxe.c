/** @file
  CC Blob DXE driver.

  Reads the OpenHCL paravisor's SEV-SNP CC blob handoff (planted at the
  fixed GPA OPENHCL_SNP_CC_BLOB_HANDOFF_GPA) and, if it is present and
  valid, builds a CONFIDENTIAL_COMPUTING_BLOB_LOCATION (Linux
  LINUX_EFI_CC_BLOB_GUID) and installs it as an EFI configuration table
  before BDS so an upstream sev-guest-aware kernel can find the SNP
  secrets and CPUID pages.

  This driver is a no-op on:
    * non-SNP isolation,
    * SNP partitions where the OpenHCL paravisor has not enabled the
      "expose to VTL0" mode (handoff page magic does not match), and
    * SNP partitions without a paravisor (a hardware-enlightened guest
      will already have its own CC blob path; not our problem here).

  POC contract - replace the fixed-GPA handoff with proper BiosConfig
  selectors before upstreaming. See OpenhclSnpCcBlobHandoff.h.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/HostVisibilityLib.h>
#include <Library/PcdLib.h>

#include <Hv/HvGuestCpuid.h>
#include <IsolationTypes.h>
#include <OpenhclSnpCcBlobHandoff.h>

//
// EFI configuration table GUID consumed by the Linux kernel
// (drivers/firmware/efi/coco.c). Equal to LINUX_EFI_CC_BLOB_GUID.
//
STATIC EFI_GUID  mEfiCcBlobGuid = {
  0x067B1F5F, 0xCF26, 0x44C5, { 0x85, 0x54, 0x93, 0xD7, 0x77, 0x91, 0x2D, 0x42 }
};

//
// Linux's struct cc_blob_sev_info, layout per upstream
// arch/x86/include/asm/sev.h.
//
#pragma pack(1)
typedef struct {
  UINT32    Magic;          // CC_BLOB_SEV_INFO_MAGIC = 0x45444d41 ("AMDE")
  UINT16    Version;        // 1
  UINT16    Reserved;       // 0
  UINT64    SecretsPhys;    // GPA
  UINT32    SecretsLen;     // bytes
  UINT32    Rsvd1;
  UINT64    CpuidPhys;      // GPA
  UINT32    CpuidLen;       // bytes
  UINT32    Rsvd2;
} CC_BLOB_SEV_INFO;
#pragma pack()

#define CC_BLOB_SEV_INFO_MAGIC    0x45444d41U  // 'AMDE'
#define CC_BLOB_SEV_INFO_VERSION  1U

/**
  Walk the EFI memory map and PVALIDATE every EfiConventionalMemory range
  at the firmware's running VMPL (=VMPL2 in the OpenHCL paravisor model).

  Background: when the OpenHCL paravisor exposes SEV-SNP CPUID to VTL0,
  Linux's SNP-aware kernel needs every page it executes from to be
  validated at its current VMPL. The paravisor at VMPL0 cannot do this
  on the firmware/guest behalf because PVALIDATE is per-VMPL. So mu_msvm
  (running at VMPL2) must do it before BDS hands off to the OS image.

  Returns the number of distinct ranges processed and writes diagnostic
  output via DEBUG.
**/
STATIC
VOID
PvalidateConventionalMemoryAtCurrentVmpl (
  VOID
  )
{
  EFI_STATUS                Status;
  UINTN                     MemoryMapSize;
  UINTN                     MapKey;
  UINTN                     DescriptorSize;
  UINT32                    DescriptorVersion;
  EFI_MEMORY_DESCRIPTOR     *MemoryMap;
  EFI_MEMORY_DESCRIPTOR     *Desc;
  UINTN                     RangeCount;
  UINTN                     OkCount;
  UINTN                     FailCount;
  UINT64                    TotalPages;

  //
  // First call to learn required size; bump to leave room for changes.
  //
  MemoryMap     = NULL;
  MemoryMapSize = 0;
  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((
      DEBUG_ERROR,
      "OPENHCL_SNP_VTL0: GetMemoryMap (size probe) status=%r\n",
      Status
      ));
    return;
  }

  MemoryMapSize += 8 * DescriptorSize;
  MemoryMap     = AllocatePool (MemoryMapSize);
  if (MemoryMap == NULL) {
    DEBUG ((DEBUG_ERROR, "OPENHCL_SNP_VTL0: GetMemoryMap AllocatePool failed\n"));
    return;
  }

  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "OPENHCL_SNP_VTL0: GetMemoryMap status=%r\n",
      Status
      ));
    FreePool (MemoryMap);
    return;
  }

  RangeCount = 0;
  OkCount    = 0;
  FailCount  = 0;
  TotalPages = 0;

  for (Desc = MemoryMap;
       (UINT8 *)Desc < (UINT8 *)MemoryMap + MemoryMapSize;
       Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Desc + DescriptorSize))
  {
    if (Desc->Type != EfiConventionalMemory) {
      continue;
    }
    if (Desc->NumberOfPages == 0) {
      continue;
    }
    RangeCount++;
    TotalPages += Desc->NumberOfPages;

    DEBUG ((
      DEBUG_ERROR,
      "OPENHCL_SNP_VTL0: pvalidate range %u: gpa=0x%lx pages=0x%lx\n",
      (UINT32)RangeCount,
      Desc->PhysicalStart,
      Desc->NumberOfPages
      ));

    Status = EfiUpdatePageRangeAcceptance (
               GetIsolationType (),
               (VOID *)PcdGet64 (PcdSvsmCallingArea),
               Desc->PhysicalStart / EFI_PAGE_SIZE,
               Desc->NumberOfPages,
               TRUE
               );
    if (EFI_ERROR (Status)) {
      FailCount++;
      DEBUG ((
        DEBUG_ERROR,
        "OPENHCL_SNP_VTL0:   pvalidate FAILED status=%r gpa=0x%lx pages=0x%lx\n",
        Status,
        Desc->PhysicalStart,
        Desc->NumberOfPages
        ));
    } else {
      OkCount++;
    }
  }

  DEBUG ((
    DEBUG_ERROR,
    "OPENHCL_SNP_VTL0: pvalidate summary ranges=%u ok=%u fail=%u total_pages=0x%lx\n",
    (UINT32)RangeCount,
    (UINT32)OkCount,
    (UINT32)FailCount,
    TotalPages
    ));

  FreePool (MemoryMap);
}

/**
  Entry point for the CC Blob DXE driver.
**/
EFI_STATUS
EFIAPI
CcBlobDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                         Status;
  OPENHCL_SNP_CC_BLOB_HANDOFF        Handoff;
  CC_BLOB_SEV_INFO                   *Blob;

  DEBUG ((
    DEBUG_ERROR,
    "OPENHCL_SNP_VTL0: CcBlobDxe entry iso=%u paravisor=%u\n",
    (UINT32)GetIsolationType (),
    (UINT32)IsParavisorPresent ()
    ));

  //
  // Only meaningful when the firmware is running in an SNP guest with a
  // paravisor; bail out cleanly otherwise.
  //
  if ((GetIsolationType () != UefiIsolationTypeSnp) || !IsParavisorPresent ()) {
    DEBUG ((
      DEBUG_INFO,
      "CcBlobDxe: skipping (isolation=%u paravisor=%u)\n",
      GetIsolationType (),
      IsParavisorPresent ()
      ));
    return EFI_SUCCESS;
  }

  //
  // Locate the OpenHCL handoff page by scanning low VTL0 memory for the
  // OPENHCL_SNP_CC_BLOB_HANDOFF_MAGIC value at every 4 KiB boundary.
  //
  // Earlier revisions used a hardcoded GPA inside the UEFI configuration
  // window (0x709000-0x800000), but that collided with PEI's own runtime
  // config layout and caused PEI fail-fasts. Scanning is robust to any
  // future changes in the OpenHCL loader's page allocation order.
  //
  // We scan the range [0x1000 .. 0x100000) (above the measured config
  // page, below the UEFI image) for the magic. The OpenHCL loader places
  // the handoff in one of the lowest free pages, well below 0x100000.
  //
  OPENHCL_SNP_CC_BLOB_HANDOFF *FoundHandoff = NULL;
  UINTN  ScanGpa;
  for (ScanGpa = 0x1000; ScanGpa < 0x100000; ScanGpa += 0x1000) {
    OPENHCL_SNP_CC_BLOB_HANDOFF *Candidate =
      (OPENHCL_SNP_CC_BLOB_HANDOFF *)(UINTN)ScanGpa;
    if (Candidate->Magic == OPENHCL_SNP_CC_BLOB_HANDOFF_MAGIC) {
      FoundHandoff = Candidate;
      break;
    }
  }

  if (FoundHandoff != NULL) {
    DEBUG ((
      DEBUG_ERROR,
      "OPENHCL_SNP_VTL0: CcBlobDxe found handoff at 0x%lx\n",
      (UINT64)(UINTN)FoundHandoff
      ));
  }

  if (FoundHandoff == NULL) {
    DEBUG ((
      DEBUG_ERROR,
      "OPENHCL_SNP_VTL0: CcBlobDxe no SnpCcBlobHandoff magic found in low memory; skipping\n"
      ));
    return EFI_SUCCESS;
  }

  CopyMem (&Handoff, FoundHandoff, sizeof (Handoff));

  if (Handoff.Version != OPENHCL_SNP_CC_BLOB_HANDOFF_VERSION) {
    DEBUG ((
      DEBUG_WARN,
      "CcBlobDxe: handoff version mismatch (got %u want %u); skipping\n",
      Handoff.Version,
      OPENHCL_SNP_CC_BLOB_HANDOFF_VERSION
      ));
    return EFI_SUCCESS;
  }

  if ((Handoff.Flags & OPENHCL_SNP_CC_BLOB_HANDOFF_FLAG_PRESENT) == 0) {
    DEBUG ((DEBUG_INFO, "CcBlobDxe: handoff present-bit clear; skipping\n"));
    return EFI_SUCCESS;
  }

  if ((Handoff.SecretsSize != OPENHCL_SNP_CC_BLOB_PAGE_SIZE) ||
      (Handoff.CpuidSize != OPENHCL_SNP_CC_BLOB_PAGE_SIZE) ||
      ((Handoff.SecretsGpa & (OPENHCL_SNP_CC_BLOB_PAGE_SIZE - 1)) != 0) ||
      ((Handoff.CpuidGpa & (OPENHCL_SNP_CC_BLOB_PAGE_SIZE - 1)) != 0))
  {
    DEBUG ((
      DEBUG_ERROR,
      "CcBlobDxe: handoff fields invalid: secrets=%lx/%lx cpuid=%lx/%lx\n",
      Handoff.SecretsGpa,
      Handoff.SecretsSize,
      Handoff.CpuidGpa,
      Handoff.CpuidSize
      ));
    return EFI_SUCCESS;
  }

  //
  // Allocate AcpiReclaimMemory so the blob survives ExitBootServices and
  // the kernel can touch it during early boot. AllocatePool is fine for
  // a struct this small; the GPAs it points at are owned by the
  // paravisor and live in regular VTL0 RAM the kernel will see.
  //
  Status = gBS->AllocatePool (
                  EfiACPIReclaimMemory,
                  sizeof (CC_BLOB_SEV_INFO),
                  (VOID **)&Blob
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "CcBlobDxe: AllocatePool failed: %r\n", Status));
    return Status;
  }

  ZeroMem (Blob, sizeof (*Blob));
  Blob->Magic       = CC_BLOB_SEV_INFO_MAGIC;
  Blob->Version     = CC_BLOB_SEV_INFO_VERSION;
  Blob->SecretsPhys = Handoff.SecretsGpa;
  Blob->SecretsLen  = (UINT32)Handoff.SecretsSize;
  Blob->CpuidPhys   = Handoff.CpuidGpa;
  Blob->CpuidLen    = (UINT32)Handoff.CpuidSize;

  Status = gBS->InstallConfigurationTable (&mEfiCcBlobGuid, Blob);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "CcBlobDxe: InstallConfigurationTable failed: %r\n",
      Status
      ));
    gBS->FreePool (Blob);
    return Status;
  }

  DEBUG ((
    DEBUG_ERROR,
    "OPENHCL_SNP_VTL0: CcBlobDxe installed LINUX_EFI_CC_BLOB secrets=%lx cpuid=%lx\n",
    Handoff.SecretsGpa,
    Handoff.CpuidGpa
    ));

  //
  // Now PVALIDATE all conventional memory at our current VMPL so an
  // SNP-aware kernel can execute from any page BDS hands it.
  //
  PvalidateConventionalMemoryAtCurrentVmpl ();

  return EFI_SUCCESS;
}
