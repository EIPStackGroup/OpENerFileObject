/*******************************************************************************
 * Copyright (c) 2020, Rockwell Automation, Inc.
 * All rights reserved.
 *
 ******************************************************************************/

#ifndef OPENER_CIPFILE_H_
#define OPENER_CIPFILE_H_

#include <stdio.h>

#include "ciptypes.h"

static const CipUint kCipFileObjectClassCode = 0x37U;

#define CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE 100U
#define CIP_FILE_MAX_SIZE_IN_KB 10U
#define CIP_FILE_MAX_TRANSFERABLE_SIZE (1024U * CIP_FILE_MAX_SIZE_IN_KB) /* 1024 = 1kByte, times CIP_FILE_MAX_SIZE_IN_KB */

static const CipUint kCipFileObjectInitiateUploadServiceCode = 0x4BU;
static const CipUint kCipFileObjectUploadTransferServiceCode = 0x4FU;
static const CipUint kCipFileObjectInitiateDownloadServiceCode = 0x4CU;
static const CipUint kCipFileObjectDownloadTransferServiceCode = 0x50U;
static const CipUint kCipFileObjectClearFileServiceCode = 0x51U;

typedef struct cip_file_object_file_revision {
  CipUsint major_revision;
  CipUsint minor_revision;
} CipFileObjectFileRevision;

typedef enum cip_file_object_invokation_method_values {
  kCipFileInvocationMethodNoAction = 0,
  kCipFileInvocationMethodResetToIdentityObject,
  kCipFileInvocationMethodPowerCycleOnDevice,
  kCipFileInvocationMethodStartServiceRequestRequired,
  kCipFileInvocationMethodApplicationObjectInternalRequestRequired,
  kCipFileInvocationMethodNotApplicable = 255
} CipFileObjectInvokationMethodValues;

typedef enum cip_file_object_file_access_rule {
  kCipFileObjectFileAccessRuleReadWrite = 0,
  kCipFileObjectFileAccessRuleReadOnly,
} CipFileObjectFileAccessRule;

typedef enum cip_file_object_file_encoding_format {
  kCipFileObjectFileEncodingFormatBinary = 0,
  kCipFileObjectFileEncodingFormatCompressedFile = 1, /*<< ZLIB compression */
  kCipFileObjectFileEncodingFormatPEMEncodedCertificate = 2,
  kCipFileObjectFileEncodingFormatPKCS7EncodedCertificate = 3,
  kCipFileObjectFileEncodingFormatPEMEncodedCRL = 4,
  kCipFileObjectFileEncodingFormatPKS7EncodedCRL = 5,
  kCipFileObjectFileEncodingFormatASCIIText = 11,
  kCipFileObjectFileEncodingFormatWord = 12, /*<< doc, docx */
  kCipFileObjectFileEncodingFormatExcel = 13, /*<< xls, xlsx */
  kCipFileObjectFileEncodingFormatPDF = 14, /*<< pdf */
  kCipFileObjectFileEncodingFormatUnkown = 255
} CipFileObjectFileEncodingFormat;

typedef enum cip_file_transfer_packet_type {
  kCipFileTransferPacketTypeFirstTransferPacket = 0,
  kCipFileTransferPacketTypeMiddleTransferPacket = 1,
  kCipFileTransferPacketTypeLastTransferPacket = 2,
  kCipFileTransferPacketTypeAbortTransfer = 3,
  kCipFileTransferPacketTypeFirstAndLastPacket = 4
} CipFileTransferPacketType;

typedef struct cip_file_upload_session CipFileObjectUploadSession;

typedef struct cip_file_object_values {
  CipUsint state;   /**< Valid values are the ones in @ref CipFileStateValue*/
  CipStringI instance_name;
  CipUint file_format_version;
  CipStringI file_name;
  CipFileObjectFileRevision file_revision;
  CipUdint file_size;
  CipUint file_checksum;
  CipUsint invocation_method;
  CipByte file_save_parameters;
  CipUsint file_access_rule;
  CipUsint file_encoding_format;
  CipUsint file_transfer_timeout;
  /* Non CIP values */
  FILE *file_handle;   /* TODO: Make platform independent */
  CipFileObjectUploadSession *aquired_session;

  /* Function pointers if an object supports Download/Clear or not! */
  CipServiceFunction initiate_download;
  CipServiceFunction download_transfer;
  CipServiceFunction clear_file;
  CipServiceFunction delete_instance_data;
  CipOctet data[CIP_FILE_MAX_TRANSFERABLE_SIZE];
} CipFileObjectValues;

EipStatus CipFileInit(void);

void CipFileSessionTimerCheck(const MilliSeconds elapsed_time);

CipInstance CipFileCreateInstance(char *instance_name_string);

#endif /* OPENER_CIPFILE_H_ */
