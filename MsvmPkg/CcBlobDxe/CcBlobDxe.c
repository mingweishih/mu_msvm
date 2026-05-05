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
  // Read the OpenHCL handoff page from its well-known fixed GPA. The
  // paravisor pre-validates this page; the contents may still be all
  // zero if the paravisor was built without expose_snp_to_vtl0 support
  // or the partition mode was not enabled.
  //
  CopyMem (
    &Handoff,
    (VOID *)(UINTN)OPENHCL_SNP_CC_BLOB_HANDOFF_GPA,
    sizeof (Handoff)
    );

  if (Handoff.Magic != OPENHCL_SNP_CC_BLOB_HANDOFF_MAGIC) {
    DEBUG ((DEBUG_INFO, "CcBlobDxe: no handoff present (magic mismatch)\n"));
    return EFI_SUCCESS;
  }

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
    DEBUG_INFO,
    "CcBlobDxe: installed LINUX_EFI_CC_BLOB secrets=%lx cpuid=%lx\n",
    Handoff.SecretsGpa,
    Handoff.CpuidGpa
    ));

  return EFI_SUCCESS;
}
