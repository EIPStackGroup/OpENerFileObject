/*******************************************************************************
 * Copyright (c) 2020, Rockwell Automation, Inc.
 * All rights reserved.
 *
 ******************************************************************************/

#include <stdio.h>

#include <string.h>

#include "cipfile.h"

#include "endianconv.h"
#include "cipcommon.h"
#include "opener_api.h"
#include "trace.h"
#include "cipstring.h"
#include "cipstringi.h"

#define STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES 1
#define CIP_FILE_OBJECT_DEFAULT_TIMEOUT 10U

static CipClass *file_object_class = NULL;

static CipFileObjectValues file_object_values[
  STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES];

static CipFileObjectValues *eds_file_instance = &file_object_values[0]; /* EDS file instance*/

static CipBool dummy_attribute;

static const CipUint kCipFileEDSAndIconFileInstanceNumber = 0xC8U; //200

typedef struct cip_file_upload_session {
  bool inUse;
  CipFileObjectValues *associated_instance;
  size_t last_send_size;
  CipUsint negotiated_transfer_size;
  CipUsint transfer_number;
  uint_fast64_t session_timeout_milliseconds;
} CipFileObjectUploadSession;

#define CIP_FILE_UPLOAD_SESSIONS 1
static CipFileObjectUploadSession upload_sessions[CIP_FILE_UPLOAD_SESSIONS];

typedef struct cip_file_download_session {
  bool inUse;
  CipFileObjectValues *associated_instance;
  CipUdint file_size;
  CipUint file_format_version;
  CipRevision file_revision;
  CipStringI file_name;
  CipOctet data[CIP_FILE_MAX_TRANSFERABLE_SIZE];
  CipOctet *current_data_position;
  CipUsint negotiated_transfer_size;
  CipUsint transfer_number;
} CipFileDownloadSession;

#define CIP_FILE_MAX_FILE_TRANSFER_SESSIONS 1
CipFileDownloadSession download_sessions[CIP_FILE_MAX_FILE_TRANSFER_SESSIONS];

typedef enum cip_file_initiate_general_status_code {
  kCipFileInitiateGeneralStatusFileNameTooLong = 0x15U,
  kCipFileInitiateGeneralStatusTooManyLanguagesInFileName = 0x15U,
  kCipFileInitiateGeneralStatusFileEmpty = 0x0CU,
  kCipFileInitiateGeneralStatusFileOffsetOutOfRange = 0x20U,
  kCipFileInitiateGeneralStatusReadWriteSizeGoesBeyondEndOfFile = 0x20U
} CipFileInitiateGeneralStatusCode;

typedef enum cip_file_initiate_extended_status_code {
  kCipFileInitiateExtendedStatusFileSizeTooLarge = 0x0004U,
  kCipFileInitiateExtendedStatusFileFormatVersionNotCompatible = 0x0005U,
  kCipFileInitiateExtendedStatusFailOnTransferZeroSize = 0x0008U,
  kCipFileInitiateExtendedStatusFileNameEmpty = 0x000AU,
  kCipFileInitiateExtendedStatusFileNameTooLong = 0x0001U,
  kCipFileInitiateExtendedStatusTooManyLanguagesInFileName = 0x0002U,
  kCipFileInitiateExtendedStatusFileEmpty = 0x0000U, /**< Dummy code indicating no additional code required */
  kCipFileInitiateExtendedStatusFileOffsetOutOfRange = 0x0002U,
  kCipFileInitiateExtendedStatusReadWriteSizeGoesBeyondEndOfFile = 0x0003U
} CipFileInitiateExtendedStatusCode;

typedef enum cip_file_transfer_general_status_code {
  kCipFileTransferGeneralStatusFailOnTransferOutOfSequence = 0x20U,
  kCipFileTransferGeneralStatusFailOnTransferOther = 0x20U,
  kCipFileTransferGeneralStatusFailOnTransferZeroSize = 0x20U,
  kCipFileTransferGeneralStatusFailOnTransferDuplicate = 0x20U,
  kCipFileTransferGeneralStatusTransferAlreadyInitiatedOrInProgress = 0x0CU, /**< additional status state attribute */
  kCipFileTransferGeneralStatusFailOnChecksum = 0xD0U, /**< Fail on checksum */
  kCipFileTransferGeneralStatusFailOnSaveToNonVolatileMemory = 0x0019U /**< Dummy code indicating no additional code required */
} CipFileTransferGeneralStatusCode;

typedef enum cip_file_transfer_extended_status_code {
  kCipFileTransferExtendedStatusFailOnTransferOutOfSequence = 0x0006U,
  kCipFileTransferExtendedStatusFailOnTransferOther = 0x0007U,
  kCipFileTransferExtendedStatusFailOnTransferZeroSize = 0x0008U,
  kCipFileTransferExtendedStatusFailOnTransferDuplicate = 0x000BU,
  kCipFileTransferExtendedStatusFileNameTooLong = 0x0001U,
  kCipFileTransferExtendedStatusFailOnChecksum = 0x0000U, /**< Dummy code indicating no additional code required */
  kCipFileTransferExtendedStatusFailOnSaveToNonVolatileMemory = 0x0000U /**< Dummy code indicating no additional code required */
} CipFileTransferExtendedStatusCode;

/** @brief Valid values for CIP File Object State
 *
 */
typedef enum cip_file_object_state {
  kCipFileObjectStateNonExistent = 0,
  kCipFileObjectStateFileEmpty,
  kCipFileObjectStateFileLoaded,
  kCipFileObjectStateTransferUploadInitiated,
  kCipFileObjectStateTransferDownloadInitiated,
  kCipFileObjectStateTransferUploadInProgress,
  kCipFileObjectStateTransferDownloadInProgress,
  kCipFileObjectStateStoring
} CipFileObjectState;

void CipFileSetDownloadAndClearSupported(
  CipFileObjectValues *const file_instance);

CipFileObjectUploadSession *CipFileGetUnusedUploadSession() {
  for(size_t i = 0; i < CIP_FILE_UPLOAD_SESSIONS; ++i) {
    if(false == upload_sessions[i].inUse) {
      return &upload_sessions[i];
    }
  }
  return NULL;
}

void CipFileInitializeUploadSessions() {
  memset(upload_sessions,
         0,
         sizeof(CipFileObjectUploadSession) * CIP_FILE_UPLOAD_SESSIONS);
}

void CipFileResetTimeout(CipFileObjectUploadSession *const session) {
  session->session_timeout_milliseconds =
    session->associated_instance->file_transfer_timeout * 1000ULL;                                       /* seconds to milliseconds */
}

void CipFileReleaseUploadSession(CipFileObjectValues *const struct_to_instance)
{
  if(NULL != struct_to_instance->aquired_session) {
    memset( struct_to_instance->aquired_session, 0,
            sizeof(CipFileObjectUploadSession) );
    struct_to_instance->aquired_session = NULL;
  }
}

void CipFileTimeoutSession(CipFileObjectUploadSession *const session) {
  CipFileObjectValues *const struct_to_instance = session->associated_instance;
  OPENER_TRACE_INFO("Upload session timed out\n");
  if(NULL != struct_to_instance->file_handle) {
    rewind(struct_to_instance->file_handle);
  }
  CipFileReleaseUploadSession(struct_to_instance);
  struct_to_instance->state = kCipFileObjectStateFileLoaded;
}

void CipFileSessionTimerCheck(const MilliSeconds elapsed_time) {
  for(size_t i = 0; i < CIP_FILE_UPLOAD_SESSIONS; ++i) {
    if(upload_sessions[i].inUse) {
      if(elapsed_time > upload_sessions[i].session_timeout_milliseconds) {
        CipFileTimeoutSession(&upload_sessions[i]);
      } else {
        upload_sessions[i].session_timeout_milliseconds -= elapsed_time;
      } OPENER_TRACE_INFO("CipFile: Time left %" PRIu64 "\n",
                          upload_sessions[i].session_timeout_milliseconds);
    }
  }
}

void CipFileTakeUploadSession(CipFileObjectValues *const struct_to_instance,
                              CipFileObjectUploadSession *const session) {
  struct_to_instance->aquired_session = session;
  session->inUse = true;
  session->associated_instance = struct_to_instance;
  CipFileResetTimeout(session);
}

void CipFileEncodeFileRevision(const void *const data,
                               ENIPMessage *const outgoing_message) {
  const CipFileObjectFileRevision *const file_revision = data;
  EncodeCipUsint(&(file_revision->major_revision), outgoing_message);
  EncodeCipUsint(&(file_revision->minor_revision), outgoing_message);
}

void EncodeCipFileObjectDirectory(const void *const data,
                                  ENIPMessage *const outgoing_message) {

  CipClass *const class = GetCipClass(kCipFileObjectClassCode);
  CipInstance *instances = class->instances; /* pointer to first instance */
  while (NULL != instances)  /* as long as pointer in not NULL */
  {
    EncodeCipUint(&instances->instance_number, outgoing_message);
    CipAttributeStruct *instance_name = GetCipAttribute(instances, 2);
    EncodeCipStringI( (CipStringIStruct *) instance_name->data,
                      outgoing_message );
    CipAttributeStruct *file_name = GetCipAttribute(instances, 4);
    EncodeCipStringI( (CipStringIStruct *) file_name->data, outgoing_message );

    instances = instances->next;
  }

}

void GenerateResponseHeader(
  const CipFileInitiateGeneralStatusCode general_status,
  const CipUsint additional_status_size,
  const CipUint additional_status_code,
  const CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response) {
  InitializeENIPMessage(&message_router_response->message);
  message_router_response->reply_service =
    (0x80 | message_router_request->service);
  message_router_response->general_status = general_status;
  message_router_response->additional_status[0] = additional_status_code;
  message_router_response->size_of_additional_status = additional_status_size;
}

static CipFileObjectValues *CipFileObjectGetDataStruct(
  const CipInstance *RESTRICT const instance) {
  return instance->data;
}

CipUint CipFileCalculateChecksumFromArray(const CipUdint file_size,
                                          const CipOctet *file_content) {
  CipUint checksum = 0;
  for(size_t i = 0; i < file_size; ++i) {
    checksum += file_content[i];
  }
  return (CipUint) (0x10000UL - (CipUdint) checksum);
}

CipUint CipFileCalculateChecksumFromFile(const CipUdint file_size,
                                         FILE *file_handle) {
  CipUint checksum = 0;
  for(size_t i = 0; i < file_size; ++i) {
    CipOctet byte = 0;
    if( 1 != fread(&byte, sizeof(CipOctet), 1, file_handle) ) {
      OPENER_TRACE_ERR("File read error in checksum creation!\n");
    }
    checksum += byte;
  }
  return (CipUint) (0x10000UL - (CipUdint) checksum);
}

static CipFileObjectState InitiateUpload(CipInstance *RESTRICT const instance,
                                         CipMessageRouterRequest *const message_router_request,
                                         CipMessageRouterResponse *const message_router_response)
{

  CipFileObjectUploadSession *upload_session = CipFileGetUnusedUploadSession();

  if(NULL == upload_session) {
    message_router_response->general_status = kCipErrorResourceUnavailable;
    message_router_response->size_of_additional_status = 0;
    message_router_response->additional_status[0] = 0;
    return kCipFileObjectStateFileLoaded;
  }

  CipUsint client_maximum_transfer_size = GetUsintFromMessage(
    &message_router_request->data);

  CipUsint chosen_transfer_size = (client_maximum_transfer_size <
                                   CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE) ?
                                  client_maximum_transfer_size :
                                  CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE;

  CipAttributeStruct *file_size_attribute = GetCipAttribute(instance, 6);
  CipUdint *file_size = (CipUdint *) file_size_attribute->data;
  EncodeCipUdint(file_size, &message_router_response->message);
  EncodeCipUsint(&chosen_transfer_size, &message_router_response->message);
  CipFileObjectValues *const struct_to_instance = CipFileObjectGetDataStruct(
    instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  rewind(struct_to_instance->file_handle);
  upload_session->negotiated_transfer_size = chosen_transfer_size;
  upload_session->transfer_number = 0;

  if(0U == client_maximum_transfer_size) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFailOnTransferZeroSize;
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }

  CipFileTakeUploadSession(struct_to_instance, upload_session);

  return kCipFileObjectStateTransferUploadInitiated;
}

static CipFileObjectState TransferUploadFromInitiateUpload(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response) {

  CipFileObjectValues *const struct_to_instance = CipFileObjectGetDataStruct(
    instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  CipFileObjectUploadSession *upload_session =
    struct_to_instance->aquired_session;

  CipUsint received_transfer_number = GetSintFromMessage(
    &message_router_request->data);
  if(0 != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kCipFileObjectStateTransferUploadInProgress;
  }

  CipFileResetTimeout(upload_session);

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);
  upload_session->transfer_number = 1; // Had to start with 0, so the next must be 1

  CipUsint transfer_packet_type = kCipFileTransferPacketTypeFirstTransferPacket;
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size = upload_session->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send,
                                        sizeof(CipOctet),
                                        negotiated_transfer_size,
                                        struct_to_instance->file_handle);
  if( ferror(struct_to_instance->file_handle) ) {
    perror("Error occurred in TransferUploadFromInitiateUpload");
  }
  if(negotiated_transfer_size > data_send_length) {
    transfer_packet_type = kCipFileTransferPacketTypeFirstAndLastPacket;
  }

  EncodeCipUsint(&transfer_packet_type, &message_router_response->message);
  memcpy(message_router_response->message.current_message_position,
         data_to_send,
         data_send_length);
  message_router_response->message.current_message_position += data_send_length;
  message_router_response->message.used_message_length += data_send_length;

  if(kCipFileTransferPacketTypeFirstAndLastPacket == transfer_packet_type) {
    EncodeCipUint(&struct_to_instance->file_checksum,
                  &message_router_response->message);
    rewind(struct_to_instance->file_handle);
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }
  return kCipFileObjectStateTransferUploadInProgress;

}

static CipFileObjectState TransferUpload(CipInstance *RESTRICT const instance,
                                         CipMessageRouterRequest *const message_router_request,
                                         CipMessageRouterResponse *const message_router_response)
{

  CipFileObjectValues *struct_to_instance =
    CipFileObjectGetDataStruct(instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  CipFileObjectUploadSession *upload_session =
    struct_to_instance->aquired_session;

  CipUsint received_transfer_number = GetSintFromMessage(
    &message_router_request->data);
  if(upload_session->transfer_number != received_transfer_number &&
     upload_session->transfer_number - 1 != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kCipFileObjectStateTransferUploadInProgress;
  }

  CipFileResetTimeout(upload_session); //Only update on correct sequence number

  if(upload_session->transfer_number - 1 == received_transfer_number) {
    upload_session->transfer_number--;
    fseek(struct_to_instance->file_handle,
          -1 * (long) upload_session->last_send_size,
          SEEK_CUR);
  }

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);

  CipUsint transfer_packet_type = (
    upload_session->transfer_number !=
    0 ? kCipFileTransferPacketTypeMiddleTransferPacket :
    kCipFileTransferPacketTypeFirstTransferPacket);
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size = upload_session->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send,
                                        sizeof(CipOctet),
                                        negotiated_transfer_size,
                                        struct_to_instance->file_handle);
  upload_session->last_send_size = data_send_length;

  if(negotiated_transfer_size > data_send_length) {
    transfer_packet_type = kCipFileTransferPacketTypeLastTransferPacket;
  }

  EncodeCipUsint(&transfer_packet_type, &message_router_response->message);
  memcpy(message_router_response->message.current_message_position,
         data_to_send,
         data_send_length);
  message_router_response->message.current_message_position += data_send_length;
  message_router_response->message.used_message_length += data_send_length;

  if(kCipFileTransferPacketTypeLastTransferPacket == transfer_packet_type) {
    OPENER_TRACE_INFO("Last transfer packet\n");
    EncodeCipUint(&struct_to_instance->file_checksum,
                  &message_router_response->message);
    rewind(struct_to_instance->file_handle);
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }

  upload_session->transfer_number++;
  return kCipFileObjectStateTransferUploadInProgress;

}

EipStatus CipFileInitiateUpload(CipInstance *RESTRICT const instance,
                                CipMessageRouterRequest *const message_router_request,
                                CipMessageRouterResponse *const message_router_response,
                                const struct sockaddr *originator_address,
                                const int encapsulation_session) {
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint *) state_attribute->data;
  switch(*state) {
    case kCipFileObjectStateNonExistent:
      GenerateResponseHeader(kCipErrorObjectDoesNotExist,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = InitiateUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state %d in File Object instance: %d",
                       *state,
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

EipStatus CipFileUploadTransfer(CipInstance *RESTRICT const instance,
                                CipMessageRouterRequest *const message_router_request,
                                CipMessageRouterResponse *const message_router_response,
                                const struct sockaddr *originator_address,
                                const int encapsulation_session) {
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint *) state_attribute->data;
  switch(*state) {
    case kCipFileObjectStateNonExistent:
      GenerateResponseHeader(kCipErrorObjectDoesNotExist,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = TransferUploadFromInitiateUpload(instance,
                                                message_router_request,
                                                message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = TransferUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state %d in File Object instance: %d",
                       *state,
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

static CipFileObjectState InitiateDownload(CipInstance *RESTRICT const instance,
                                           CipMessageRouterRequest *const message_router_request,
                                           CipMessageRouterResponse *const message_router_response)
{
  /* received parameters */
  download_sessions[0].file_size = GetUdintFromMessage(
    &message_router_request->data);
  download_sessions[0].file_format_version = GetUintFromMessage(
    &message_router_request->data);
  download_sessions[0].file_revision.major_revision = GetUsintFromMessage(
    &message_router_request->data);
  download_sessions[0].file_revision.minor_revision = GetUsintFromMessage(
    &message_router_request->data);
  //get filename from message
  CipStringIDecodeFromMessage(&download_sessions[0].file_name,
                              message_router_request);

  /* Check for errors */
  if(CIP_FILE_MAX_TRANSFERABLE_SIZE < download_sessions[0].file_size) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFileSizeTooLarge;
    return kCipFileObjectStateFileEmpty;
  }

  if(1 > download_sessions[0].file_format_version ||
     1 < download_sessions[0].file_format_version) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFileFormatVersionNotCompatible;
    return kCipFileObjectStateFileEmpty;
  }

  if( 0 == download_sessions[0].file_name.number_of_strings ||
      CipStringIsAnyStringEmpty( &(download_sessions[0].file_name) ) ) {
    OPENER_TRACE_INFO("Number of strings: %d\n",
                      download_sessions[0].file_name.number_of_strings);
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFileNameEmpty;
    return kCipFileObjectStateFileEmpty;
  }

  /* Checks done */

  /* returned parameters */
  CipUdint incremental_burn = 0;
  CipUint incremetal_burn_time = 0;
  CipUsint transfer_size = CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE;
  EncodeCipUdint(&incremental_burn, &message_router_response->message);
  EncodeCipUint(&incremetal_burn_time, &message_router_response->message);
  EncodeCipUsint(&transfer_size, &message_router_response->message);

  return kCipFileObjectStateTransferDownloadInitiated;
}

EipStatus CipFileResetDownloadTransferSession(
  CipFileDownloadSession *const session) {
  session->file_format_version = 0;
  session->file_revision.major_revision = 0;
  session->file_revision.minor_revision = 0;
  session->file_size = 0;
  CipStringIDelete(&session->file_name);
  session->current_data_position = session->data;
  session->transfer_number = 0;
  memset(session->data, 0, CIP_FILE_MAX_TRANSFERABLE_SIZE);
  return kEipStatusOk;
}

static CipFileObjectState TransferDownloadFromInitiateDownload(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response) {

  /* Get transfer number and packet type*/
  CipUsint transfer_number = GetUsintFromMessage(&message_router_request->data);
  CipUsint transfer_packet_type = GetUsintFromMessage(
    &message_router_request->data);

  if(kCipFileTransferPacketTypeAbortTransfer == transfer_packet_type) {
    CipFileResetDownloadTransferSession(&download_sessions[0]);
    message_router_response->general_status = kCipErrorSuccess;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateFileEmpty;
  }

  /* If middle or last packet type, return error, as this is not possible here */
  if(kCipFileTransferPacketTypeMiddleTransferPacket == transfer_packet_type ||
     kCipFileTransferPacketTypeLastTransferPacket == transfer_packet_type) {
    OPENER_TRACE_ERR(
      "CIP File: On switch from InitiateDownload to Download Transfer, first packet expected but not received\n");
    message_router_response->general_status = kCipErrorObjectStateConflict;
    message_router_response->size_of_additional_status = 1;
    CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
    CipUsint *state = (CipUsint *) state_attribute->data;
    message_router_response->additional_status[0] = *state;
    return kCipFileObjectStateTransferDownloadInitiated;
  }

  /* If the transfer number is not zero, return error. This has to be the first packet */
  if(0 != transfer_number) {
    OPENER_TRACE_ERR(
      "CIP File: On switch from InitiateDownload to Download Transfer, transfer number 0 expected, but not received\n");
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->additional_status[0] =
      kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    message_router_response->size_of_additional_status = 1;
    return kCipFileObjectStateTransferDownloadInitiated;
  }

  /* Calculate payload length */
  size_t payload_length = message_router_request->request_data_size -
                          sizeof(CipUsint) - sizeof(CipUsint)
                          - (kCipFileTransferPacketTypeFirstAndLastPacket ==
                             transfer_packet_type ? sizeof(CipUint) : 0);
  if(CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE < payload_length) { /* payload has to be smaller than maximum transfer size */
    OPENER_TRACE_ERR("CIP File: Payload greater than maximum transfer size\n");
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFileSizeTooLarge;
    message_router_response->size_of_additional_status = 1;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateFileEmpty;
  }

  if(kCipFileTransferPacketTypeFirstAndLastPacket == transfer_packet_type) {
    //size_t data_payload_length = payload_length - sizeof(CipUint); /* Last 16-bits are checksum */
    const CipUint calculated_checksum = CipFileCalculateChecksumFromArray(
      payload_length,
      message_router_request->data);
    const CipUint received_checksum =
      *(CipUint *) (message_router_request->data + payload_length);
    EncodeCipUsint(&transfer_number, &message_router_response->message);

    if(calculated_checksum != received_checksum) {
      message_router_response->general_status =
        kCipFileTransferGeneralStatusFailOnChecksum;
      CipFileResetDownloadTransferSession(&download_sessions[0]);
      return kCipFileObjectStateFileEmpty;
    }
    memcpy(download_sessions[0].data,
           message_router_request->data,
           payload_length);
    return kCipFileObjectStateStoring;
  }

  if(kCipFileTransferPacketTypeFirstTransferPacket == transfer_packet_type) {
    size_t data_payload_length = payload_length; /* No checksum */
    memcpy(download_sessions[0].current_data_position,
           message_router_request->data,
           data_payload_length);
    download_sessions[0].current_data_position += data_payload_length;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateTransferDownloadInProgress;
  }

  return kCipFileObjectStateTransferDownloadInitiated;
}

static CipFileObjectState TransferDownload(CipInstance *RESTRICT const instance,
                                           CipMessageRouterRequest *const message_router_request,
                                           CipMessageRouterResponse *const message_router_response)
{

  /* Get transfer number and packet type*/
  CipUsint transfer_number = GetUsintFromMessage(&message_router_request->data);
  CipUsint transfer_packet_type = GetUsintFromMessage(
    &message_router_request->data);

  if(kCipFileTransferPacketTypeAbortTransfer == transfer_packet_type) {
    CipFileResetDownloadTransferSession(&download_sessions[0]);
    message_router_response->general_status = kCipErrorSuccess;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateFileEmpty;
  }

  /* First Packet has already been processed in TransferDownloadFromInitiateDownload */
  if(kCipFileTransferPacketTypeFirstTransferPacket == transfer_packet_type ||
     kCipFileTransferPacketTypeFirstAndLastPacket == transfer_packet_type) {
    message_router_response->general_status = kCipErrorObjectStateConflict;
    message_router_response->size_of_additional_status = 1;
    CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
    CipUsint *state = (CipUsint *) state_attribute->data;
    message_router_response->additional_status[0] = *state;
    return kCipFileObjectStateTransferDownloadInProgress;
  }

  /* If the transfer number is not zero, return error. This has to be the first packet */
  if(download_sessions[0].transfer_number + 1 != transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    if(download_sessions[0].transfer_number == transfer_number) {
      message_router_response->additional_status[0] =
        kCipFileTransferExtendedStatusFailOnTransferDuplicate;
    } else {
      message_router_response->additional_status[0] =
        kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    }
    return kCipFileObjectStateTransferDownloadInProgress;
  }

  /* transfer number ok */
  download_sessions[0].transfer_number = transfer_number;

  /* Calculate payload length */
  size_t payload_length = message_router_request->request_data_size -
                          sizeof(CipUsint) - sizeof(CipUsint);
  if(CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE < payload_length) { /* payload has to be smaller than maximum transfer size */
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFileSizeTooLarge;
    message_router_response->size_of_additional_status = 1;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateFileEmpty;
  }

  if(kCipFileTransferPacketTypeMiddleTransferPacket == transfer_packet_type) {
    size_t data_payload_length = payload_length; /* No checksum */
    memcpy(download_sessions[0].current_data_position,
           message_router_request->data,
           data_payload_length);
    download_sessions[0].current_data_position += data_payload_length;
    EncodeCipUsint(&transfer_number, &message_router_response->message);
    return kCipFileObjectStateTransferDownloadInProgress;
  }

  if(kCipFileTransferPacketTypeLastTransferPacket == transfer_packet_type) {
    size_t data_payload_length = payload_length - sizeof(CipUint); /* Last 16-bits are checksum */
    /* Get last bits of data */
    memcpy(download_sessions[0].current_data_position,
           message_router_request->data,
           data_payload_length);
    download_sessions[0].current_data_position += data_payload_length;
    EncodeCipUsint(&transfer_number, &message_router_response->message);

    /* Calculate checksum */
    const CipUint calculated_checksum = CipFileCalculateChecksumFromArray(
      download_sessions[0].current_data_position - download_sessions[0].data,
      download_sessions[
        0].data);
    const CipUint received_checksum =
      *(CipUint *) (message_router_request->data + data_payload_length);

    OPENER_TRACE_INFO(
      "Download Transfer calculated checksum: %x - received checksum: %x\n",
      calculated_checksum,
      received_checksum);

    if(calculated_checksum != received_checksum) {
      message_router_response->general_status =
        kCipFileTransferGeneralStatusFailOnChecksum;
      CipFileResetDownloadTransferSession(&download_sessions[0]);
      return kCipFileObjectStateFileEmpty;
    }
    /* Currently no save to non-volatile storage */
    return kCipFileObjectStateStoring;
  }
  return kCipFileObjectStateTransferDownloadInProgress; //TODO: What to do if nothing matches? Check this again
}

static CipFileObjectState CipFileStore(CipInstance *RESTRICT const instance) {

  OPENER_TRACE_INFO("CIP File: Storing instance %d\n",
                    instance->instance_number);
  CipFileObjectValues *struct_to_instance;
  if( NULL == ( struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }

  /* copy data to file object instance*/
  struct_to_instance->file_size = download_sessions[0].file_size;
  memcpy(struct_to_instance->data,
         download_sessions[0].data,
         struct_to_instance->file_size);
  struct_to_instance->file_format_version =
    download_sessions[0].file_format_version;
  struct_to_instance->file_revision.major_revision =
    download_sessions[0].file_revision.major_revision;
  struct_to_instance->file_revision.minor_revision =
    download_sessions[0].file_revision.minor_revision;
  struct_to_instance->file_checksum = CipFileCalculateChecksumFromArray(
    struct_to_instance->file_size,
    struct_to_instance->data);

  CipStringIDelete(&struct_to_instance->file_name);
  CipStringICopy(&struct_to_instance->file_name,
                 &download_sessions[0].file_name);

  return kCipFileObjectStateFileLoaded;
}

EipStatus CipFileInitiateDownload(CipInstance *RESTRICT const instance,
                                  CipMessageRouterRequest *const message_router_request,
                                  CipMessageRouterResponse *const message_router_response,
                                  const struct sockaddr *originator_address,
                                  const int encapsulation_session) {

  CipFileObjectValues *struct_to_instance;
  if( NULL == ( struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }

  return struct_to_instance->initiate_download(instance,
                                               message_router_request,
                                               message_router_response,
                                               originator_address,
                                               encapsulation_session);
}

EipStatus CipFileInitiateDownloadImplementation(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response,
  const struct sockaddr *originator_address,
  const int encapsulation_session) {
  CipAttributeStruct *file_access_attribute = GetCipAttribute(instance, 10);
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint *) state_attribute->data;
  if(kCipFileObjectFileAccessRuleReadOnly ==
     *(CipUsint *) file_access_attribute->data) {
    GenerateResponseHeader(kCipErrorObjectStateConflict,
                           1,
                           *state,
                           message_router_request,
                           message_router_response);
    return kEipStatusOkSend;
  }
  switch(*state) {
    case kCipFileObjectStateNonExistent:
      GenerateResponseHeader(kCipErrorObjectDoesNotExist,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = InitiateDownload(instance,
                                message_router_request,
                                message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      /* File object in invalid state for this operation */
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorSuccess,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      CipFileResetDownloadTransferSession(&download_sessions[0]);
      //*state = ClearFileDataAndAttrributes();
      *state = InitiateDownload(instance,
                                message_router_request,
                                message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state %d in File Object instance: %d",
                       *state,
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

EipStatus CipFileDownloadTransfer(CipInstance *RESTRICT const instance,
                                  CipMessageRouterRequest *const message_router_request,
                                  CipMessageRouterResponse *const message_router_response,
                                  const struct sockaddr *originator_address,
                                  const int encapsulation_session) {
  CipFileObjectValues *struct_to_instance;
  if( NULL == ( struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }
  return struct_to_instance->download_transfer(instance,
                                               message_router_request,
                                               message_router_response,
                                               originator_address,
                                               encapsulation_session);
}

EipStatus CipFileDownloadTransferImplementation(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response,
  const struct sockaddr *originator_address,
  const int encapsulation_session) {
  CipAttributeStruct *const state_attribute = GetCipAttribute(instance, 1);
  CipUsint *const state = (CipUsint *) state_attribute->data;

  CipAttributeStruct *const file_save_parameters_struct = GetCipAttribute(
    instance,
    9);
  const CipByte file_save_parameters =
    *(CipByte *) file_save_parameters_struct->data;                                   /* shall not be modified */
  CipAttributeStruct *const file_access_attribute =
    GetCipAttribute(instance, 10);
  if(kCipFileObjectFileAccessRuleReadOnly ==
     *(CipUsint *) file_access_attribute->data) {
    GenerateResponseHeader(kCipErrorObjectStateConflict,
                           1,
                           *state,
                           message_router_request,
                           message_router_response);
    return kEipStatusOkSend;
  }
  switch(*state) {
    case kCipFileObjectStateNonExistent:
      GenerateResponseHeader(kCipErrorObjectDoesNotExist,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = TransferDownloadFromInitiateDownload(instance,
                                                    message_router_request,
                                                    message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      *state = TransferDownload(instance,
                                message_router_request,
                                message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             1,
                             *state,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state %d in File Object instance: %d",
                       *state,
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }

  OPENER_TRACE_INFO("CIP File: Instance %d in DownloadTransfer - State: %d\n",
                    instance->instance_number,
                    *state);
  if( kCipFileObjectStateStoring == *state &&
      ( (file_save_parameters & 0x0F) == 0 ) ) {                                     /* e.g. download is finished, then the data has to be saved (autosave) */
    *state = CipFileStore(instance);
  }

  return kEipStatusOkSend;
}

EipStatus CipFileClearFile(CipInstance *RESTRICT const instance,
                           CipMessageRouterRequest *const message_router_request,
                           CipMessageRouterResponse *const message_router_response,
                           const struct sockaddr *originator_address,
                           const int encapsulation_session) {

  CipFileObjectValues *struct_to_instance;
  if( NULL == ( struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }
  return struct_to_instance->clear_file(instance,
                                        message_router_request,
                                        message_router_response,
                                        originator_address,
                                        encapsulation_session);
}

EipStatus CipFileServiceNotSupportedForSpecifiedPath(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response,
  const struct sockaddr *originator_address,
  const int encapsulation_session) {
  OPENER_TRACE_INFO("Service on selected path not supported!\n");
  GenerateResponseHeader(kCipErrorServiceNotSupportedForSpecifiedPath,
                         0,
                         0,
                         message_router_request,
                         message_router_response);
  return kEipStatusOkSend;
}

CipFileObjectState CipFileObjectDeleteFileData(CipInstance *const instance) {
  CipFileObjectValues *struct_to_instance;
  if( NULL == ( struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }
  CipStringIDelete(&struct_to_instance->file_name);

  struct_to_instance->state = kCipFileObjectStateFileEmpty;
  struct_to_instance->file_size = 0;
  struct_to_instance->file_checksum = 0;
  struct_to_instance->file_revision.major_revision = 0;
  struct_to_instance->file_revision.minor_revision = 0;

  struct_to_instance->file_format_version = 0;
  struct_to_instance->invocation_method = kCipFileInvocationMethodNotApplicable;
  struct_to_instance->file_save_parameters = 0;
  struct_to_instance->file_access_rule = kCipFileObjectFileAccessRuleReadWrite;
  struct_to_instance->file_encoding_format =
    kCipFileObjectFileEncodingFormatBinary;
  memset(struct_to_instance->data, 0, CIP_FILE_MAX_TRANSFERABLE_SIZE);

  return kCipFileObjectStateFileEmpty;
}

EipStatus CipFileClearFileImplementation(CipInstance *RESTRICT const instance,
                                         CipMessageRouterRequest *const message_router_request,
                                         CipMessageRouterResponse *const message_router_response,
                                         const struct sockaddr *originator_address,
                                         const int encapsulation_session) {
  CipAttributeStruct *file_access_attribute = GetCipAttribute(instance, 10);
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint *) state_attribute->data;
  if(kCipFileObjectFileAccessRuleReadOnly ==
     *(CipUsint *) file_access_attribute->data) {
    GenerateResponseHeader(kCipErrorObjectStateConflict,
                           1,
                           *state,
                           message_router_request,
                           message_router_response);
    return kEipStatusOkSend;
  }
  switch(*state) {
    case kCipFileObjectStateNonExistent:
      GenerateResponseHeader(kCipErrorObjectDoesNotExist,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      /*clear all data and transition to Empty File <- Not necessary right now, as we do not expose the Storing service*/
      *state = kCipFileObjectStateFileEmpty;
      break;
    case kCipFileObjectStateFileLoaded:
      GenerateResponseHeader(kCipErrorSuccess,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      /*clear all data and transition to Empty File*/
      *state = CipFileObjectDeleteFileData(instance);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      /*clear all data and transition to Empty File*/
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      /* Insert Happy Path */
      GenerateResponseHeader(kCipErrorObjectStateConflict,
                             0,
                             0,
                             message_router_request,
                             message_router_response);
      /*clear all data and transition to Empty File*/
      break;
    default:
      OPENER_TRACE_ERR("Unknown state %d in File Object instance: %d",
                       *state,
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

EipStatus CreateFileObject(unsigned int instance_nr,
                           CipFileObjectValues *const instance_values,
                           bool file_access_setable) {
  CipInstance *instance = GetCipInstance(file_object_class, instance_nr);

  InsertAttribute(instance,
                  1,
                  kCipUsint,
                  EncodeCipUsint,
                  NULL,
                  &instance_values->state,
                  kGetableSingle);
  InsertAttribute(instance,
                  2,
                  kCipStringI,
                  EncodeCipStringI,
                  NULL,
                  &instance_values->instance_name,
                  kGetableSingle);
  InsertAttribute(instance,
                  3,
                  kCipUint,
                  EncodeCipUint,
                  NULL,
                  &instance_values->file_format_version,
                  kGetableSingle);
  InsertAttribute(instance,
                  4,
                  kCipAny,
                  EncodeCipStringI,
                  NULL,
                  &instance_values->file_name,
                  kGetableSingle);
  InsertAttribute(instance,
                  5,
                  kCipAny,
                  CipFileEncodeFileRevision,
                  NULL,
                  &instance_values->file_revision,
                  kGetableSingle);
  InsertAttribute(instance,
                  6,
                  kCipUdint,
                  EncodeCipUdint,
                  NULL,
                  &instance_values->file_size,
                  kGetableSingle);
  InsertAttribute(instance,
                  7,
                  kCipUint,
                  EncodeCipUint,
                  NULL,
                  &instance_values->file_checksum,
                  kGetableSingle);
  InsertAttribute(instance,
                  8,
                  kCipUsint,
                  EncodeCipUsint,
                  NULL,
                  &instance_values->invocation_method,
                  kGetableSingle);
  InsertAttribute(instance,
                  9,
                  kCipByte,
                  EncodeCipByte,
                  NULL,
                  &instance_values->file_save_parameters,
                  kGetableSingle);
  InsertAttribute(instance,
                  10,
                  kCipUsint,
                  EncodeCipUsint,
                  NULL,
                  &instance_values->file_access_rule,
                  file_access_setable ? kSetAndGetAble : kGetableSingle);
  InsertAttribute(instance,
                  11,
                  kCipUsint,
                  EncodeCipUsint,
                  NULL,
                  &instance_values->file_encoding_format,
                  kGetableSingle);
  InsertAttribute(instance,
                  12,
                  kCipUsint,
                  EncodeCipUsint,
                  NULL,
                  &instance_values->file_transfer_timeout,
                  kSetAndGetAble);
  /* Default values*/
  instance_values->file_transfer_timeout = CIP_FILE_OBJECT_DEFAULT_TIMEOUT;
  return kEipStatusOk;
}

/** @brief File Object Delete Instance Data
 *
 *  Used for common Delete service to delete instance struct before instance is deleted
 */
EipStatus CipFileDeleteInstanceData(CipInstance *RESTRICT const instance) {

  /*get struct and free elements*/
  CipFileObjectValues *instance_data_struct = CipFileObjectGetDataStruct(
    instance);

  CipStringIDelete(&instance_data_struct->instance_name);
  CipStringIDelete(&instance_data_struct->file_name);

  CipFree(instance_data_struct);
  instance_data_struct = NULL;

  return kEipStatusOk;
}

/** @brief File Object PreCreateCallback
 *
 *  Used for common Create service before new instance is created
 *  @See Vol.1, Chapter 5A-42.4.1
 */
EipStatus CipFilePreCreateCallback(CipInstance *RESTRICT const instance,
                                   CipMessageRouterRequest *const message_router_request,
                                   CipMessageRouterResponse *const message_router_response)
{

  if (message_router_request->request_data_size > 0) {       //check if message contains data

    //check if instance_name is already in use
    CipOctet *message_data = message_router_request->data;             //get message data pointer

    CipStringI *new_instance_name = CipCalloc( 1, sizeof(CipStringI) );
    CipStringIDecodeFromMessage(new_instance_name, message_router_request);

    message_router_request->data = message_data;             //reset message data pointer

    CipInstance *instances = file_object_class->instances;

    while (NULL != instances) {
      CipAttributeStruct *attribute = GetCipAttribute(instances, 2);                   //instance_name
      CipStringI *name = (CipStringI *) attribute->data;

      if ( CipStringICompare(new_instance_name, name) ) {
        // string exists
        OPENER_TRACE_INFO("Error: instance_name exists already \n");
        message_router_response->general_status =
          kCipErrorInvalidParameter;
        CipStringIDelete(new_instance_name);
        return kEipStatusError;
      }
      instances = instances->next;
    }
    CipStringIDelete(new_instance_name);
    return kEipStatusOk;
  } else {
    message_router_response->general_status = kCipErrorNotEnoughData;
    return kEipStatusError;
  }
}

/** @brief File Object PostCreateCallback
 *
 *  Used for common Create service after new instance is created
 *  @See Vol.1, Chapter 5A-42.4.1
 */
EipStatus CipFilePostCreateCallback(CipInstance *RESTRICT const new_instance,
                                    CipMessageRouterRequest *const message_router_request,
                                    CipMessageRouterResponse *const message_router_response)
{

  //create new file object struct
  CipFileObjectValues *file_instance =
    CipCalloc( 1, sizeof(CipFileObjectValues) );

  //get instance_name StringI from message - param 1
  CipStringIDecodeFromMessage(&file_instance->instance_name,
                              message_router_request);

  //get Encoding format from message - param 2
  file_instance->file_encoding_format = GetUsintFromMessage(
    &message_router_request->data);

  //default values
  file_instance->state = kCipFileObjectStateFileEmpty;
  file_instance->file_revision.major_revision = 0;
  file_instance->file_revision.minor_revision = 0;
  file_instance->file_name.number_of_strings = 0;       //empty file name
  file_instance->invocation_method = kCipFileInvocationMethodNotApplicable;

  EipStatus internal_state = CreateFileObject(new_instance->instance_number,
                                              file_instance, false);

  new_instance->data = file_instance;
  CipFileSetDownloadAndClearSupported(file_instance);
  file_instance->delete_instance_data = &CipFileDeleteInstanceData;

  AddIntToMessage( new_instance->instance_number,
                   &(message_router_response->message) );
  AddSintToMessage( file_instance->invocation_method,
                    &(message_router_response->message) );

  return internal_state;
}


/** @brief File Object PreDeleteCallback
 *
 *  Used for common Delete service before instance is deleted
 */
EipStatus CipFilePreDeleteCallback(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response
  ) {

  EipStatus internal_state = kEipStatusOk;

  CipFileObjectValues *file_instance = instance->data;

  if (NULL == file_instance->delete_instance_data) {
    message_router_response->general_status = kCipErrorInstanceNotDeletable;
    internal_state =  kEipStatusError;
  }
  else{
    internal_state = CipFileDeleteInstanceData(instance);
  }
  return internal_state;
}

void CipFileInitializeClassSettings(CipClass *cip_class) {
  CipClass *meta_class = cip_class->class_instance.cip_class;

  InsertAttribute( (CipInstance *) cip_class, 1, kCipUint, EncodeCipUint, NULL,
                   (void *) &cip_class->revision, kGetableSingleAndAll );                                                          /* revision */
  InsertAttribute( (CipInstance *) cip_class, 2, kCipUint, EncodeCipUint, NULL,
                   (void *) &cip_class->max_instance, kGetableSingleAndAll );                                                          /*  largest instance number */
  InsertAttribute( (CipInstance *) cip_class, 3, kCipUint, EncodeCipUint, NULL,
                   (void *) &cip_class->number_of_instances,
                   kGetableSingleAndAll );                                                                                                    /* number of instances currently existing*/
  InsertAttribute( (CipInstance *) cip_class, 4, kCipUint, EncodeCipUint, NULL,
                   (void *) &kCipUintZero, kGetableAll );                                                          /* optional attribute list - default = 0 */
  InsertAttribute( (CipInstance *) cip_class, 5, kCipUint, EncodeCipUint, NULL,
                   (void *) &kCipUintZero, kNotSetOrGetable );                                                          /* optional service list - default = 0 */
  InsertAttribute( (CipInstance *) cip_class, 6, kCipUint, EncodeCipUint, NULL,
                   (void *) &meta_class->highest_attribute_number,
                   kGetableSingle );                                                                                                          /* max class attribute number*/
  InsertAttribute( (CipInstance *) cip_class, 7, kCipUint, EncodeCipUint, NULL,
                   (void *) &cip_class->highest_attribute_number,
                   kGetableSingle );                                                                                                         /* max instance attribute number*/
  InsertAttribute( (CipInstance *) cip_class, 32, kCipAny,
                   EncodeCipFileObjectDirectory, NULL, &dummy_attribute,
                   kGetableSingle );

  InsertService(meta_class,
                kGetAttributeSingle,
                &GetAttributeSingle,
                "GetAttributeSingle");
  InsertService(meta_class, kCreate, &CipCreateService, "Create");

  // add Callback function pointers
  cip_class->PreCreateCallback = &CipFilePreCreateCallback;
  cip_class->PostCreateCallback = &CipFilePostCreateCallback;
  cip_class->PreDeleteCallback = &CipFilePreDeleteCallback;

  cip_class->number_of_instances = 0;
  cip_class->max_instance = kCipFileEDSAndIconFileInstanceNumber; /* Predefined instance for EDS File and Icon File */
}

void CipFileSetFileLength(CipFileObjectValues *const eds_file_instance) {
  fseek(eds_file_instance->file_handle, 0L, SEEK_END);
  eds_file_instance->file_size = ftell(eds_file_instance->file_handle);
  rewind(eds_file_instance->file_handle);
}

void CipFileSetChecksum(CipFileObjectValues *const eds_file_instance) {
  CipUint checksum = 0;
  for(size_t i = 0; i < eds_file_instance->file_size; ++i) {
    CipOctet byte = 0;
    if( 1 !=
        fread(&byte, sizeof(CipOctet), 1, eds_file_instance->file_handle) ) {
      OPENER_TRACE_ERR("File read error in checksum creation!\n");
    }
    checksum += byte;
  }
  eds_file_instance->file_checksum =
    (CipUint) (0x10000UL - (CipUdint) checksum);
}

void CipFileSetInstanceName(CipFileObjectValues *const file_instance,
                            const char *const instance_name_string,
                            size_t instance_name_string_size) {
  file_instance->instance_name.number_of_strings = 1;
  file_instance->instance_name.array_of_string_i_structs = CipCalloc(
     file_instance->instance_name.number_of_strings, sizeof(CipStringIStruct) );
  file_instance->instance_name.array_of_string_i_structs[0].language_char_1 =
    'e';
  file_instance->instance_name.array_of_string_i_structs[0].language_char_2 =
    'n';
  file_instance->instance_name.array_of_string_i_structs[0].language_char_3 =
    'g';
  file_instance->instance_name.array_of_string_i_structs[0].character_set =
    kCipStringICharSet_ISO_8859_1_1987;
  file_instance->instance_name.array_of_string_i_structs[0].char_string_struct =
    kCipShortString;
  file_instance->instance_name.array_of_string_i_structs[0].string = CipCalloc(
     1, sizeof(CipShortString) );
  CipShortString *instance_name_short_string =
    (CipShortString *) (file_instance->instance_name.array_of_string_i_structs[0
                        ].
                        string);
  instance_name_short_string->length = instance_name_string_size - 1;
  instance_name_short_string->string = CipCalloc( instance_name_string_size,
                                                  sizeof(EipByte) );
  memcpy(instance_name_short_string->string,
         instance_name_string,
         instance_name_string_size);
}

void CipFileSetDownloadAndClearNotSupported(
  CipFileObjectValues *const file_instance) {
  /* Set Download and Clear File to not supported*/
  file_instance->initiate_download =
    &CipFileServiceNotSupportedForSpecifiedPath;
  file_instance->download_transfer =
    &CipFileServiceNotSupportedForSpecifiedPath;
  file_instance->clear_file = &CipFileServiceNotSupportedForSpecifiedPath;
}

void CipFileSetDownloadAndClearSupported(
  CipFileObjectValues *const file_instance) {
  /* Set Download and Clear File to supported*/
  file_instance->initiate_download = &CipFileInitiateDownloadImplementation;
  file_instance->download_transfer = &CipFileDownloadTransferImplementation;
  file_instance->clear_file = &CipFileClearFileImplementation;
}

EipStatus CipFileConfigureReadWriteInstance(
  CipFileObjectValues *const file_instance) {
  file_instance->state = kCipFileObjectStateFileEmpty;
  file_instance->file_size = 0;
  file_instance->file_checksum = 0;
  file_instance->file_revision.major_revision = 0;
  file_instance->file_revision.minor_revision = 0;

  file_instance->file_format_version = 0;
  file_instance->invocation_method = kCipFileInvocationMethodNotApplicable;
  file_instance->file_save_parameters = 0;
  file_instance->file_access_rule = kCipFileObjectFileAccessRuleReadWrite;
  file_instance->file_encoding_format = kCipFileObjectFileEncodingFormatBinary;
  return kEipStatusOk;
}

EipStatus CipFileCreateEDSAndIconFileInstance() {
  const char instance_name_string[] = "EDS and Icon Files";
  eds_file_instance->file_handle = fopen(FILE_OBJECT_EDS_FILE_LOCATION, "rb");
  if(NULL == eds_file_instance->file_handle) {
    OPENER_TRACE_ERR("File does not exist\n");
    return kEipStatusError;
  }
  eds_file_instance->state = kCipFileObjectStateFileLoaded;
  CipFileSetFileLength(eds_file_instance);
  CipFileSetChecksum(eds_file_instance);

  eds_file_instance->file_format_version = 1;
  eds_file_instance->invocation_method = kCipFileInvocationMethodNotApplicable;
  eds_file_instance->file_save_parameters = 0;
  eds_file_instance->file_access_rule = kCipFileObjectFileAccessRuleReadOnly;
  eds_file_instance->file_encoding_format =
    kCipFileObjectFileEncodingFormatBinary;

  CipFileSetInstanceName( eds_file_instance, instance_name_string,
                          sizeof(instance_name_string) );

  char file_name_string[] = "EDS.txt";
  eds_file_instance->file_name.number_of_strings = 1;
  eds_file_instance->file_name.array_of_string_i_structs = CipCalloc(
     eds_file_instance->file_name.number_of_strings, sizeof(CipStringIStruct) );
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_1 =
    'e';
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_2 =
    'n';
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_3 =
    'g';
  eds_file_instance->file_name.array_of_string_i_structs[0].character_set =
    kCipStringICharSet_ISO_8859_1_1987;
  eds_file_instance->file_name.array_of_string_i_structs[0].char_string_struct =
    kCipShortString;
  eds_file_instance->file_name.array_of_string_i_structs[0].string = CipCalloc(
     1, sizeof(CipShortString) );
  CipShortString *file_name_short_string =
    (CipShortString *) (eds_file_instance->file_name.array_of_string_i_structs[0
                        ].
                        string);
  file_name_short_string->length = sizeof(file_name_string) - 1;
  file_name_short_string->string =
    CipCalloc( sizeof(file_name_string), sizeof(EipByte) );
  memcpy( file_name_short_string->string, file_name_string,
          sizeof(file_name_string) );

  return kEipStatusOk;
}

/** @brief creates empty file object instance
 *
 * @param instance_name_string name of the created file object instance
 */
CipInstance CipFileCreateInstance(char *instance_name_string) {
  CipInstance *new_instance = AddCipInstances(file_object_class, 1);

  // create new file object struct
  CipFileObjectValues *file_instance =
    CipCalloc( 1, sizeof(CipFileObjectValues) );

  CipFileSetInstanceName(file_instance, instance_name_string,
                         strlen(instance_name_string) + 1);

  // default values
  file_instance->state = kCipFileObjectStateFileEmpty;
  file_instance->file_revision.major_revision = 0;
  file_instance->file_revision.minor_revision = 0;
  file_instance->file_name.number_of_strings = 0;  // empty file name
  file_instance->invocation_method = kCipFileInvocationMethodNotApplicable;
  file_instance->file_encoding_format = kCipFileObjectFileEncodingFormatBinary;

  CreateFileObject(new_instance->instance_number, file_instance, false);

  new_instance->data = file_instance;
  CipFileSetDownloadAndClearSupported(file_instance);
  file_instance->delete_instance_data = &CipFileDeleteInstanceData;

  return *new_instance;
}

EipStatus CipFileInit() {
  if( NULL == ( file_object_class = CreateCipClass(kCipFileObjectClassCode, 7, /* # class attributes */
                                                   32, /* # highest class attribute number */
                                                   2, /* # class services */
                                                   12, /* # instance attributes */
                                                   12, /* # highest instance attribute number */
                                                   7, /* # instance services */
                                                   0, /* # instances - zero to suppress creation */
                                                   "File Object", /* # debug name */
                                                   3, /* # class revision */
                                                   CipFileInitializeClassSettings /* # function pointer for initialization */
                                                   ) ) ) {
    /* Initialization failed */
    return kEipStatusError;
  }

  CipFileInitializeUploadSessions();

  InsertService(file_object_class,
                kGetAttributeSingle,
                &GetAttributeSingle,
                "GetAttributeSingle");
  InsertService(file_object_class,
                kCipFileObjectInitiateUploadServiceCode,
                &CipFileInitiateUpload,
                "CipFileObjectInitiateUpload");
  InsertService(file_object_class,
                kCipFileObjectUploadTransferServiceCode,
                &CipFileUploadTransfer,
                "CipFileObjectUploadTransfer");
  InsertService(file_object_class,
                kCipFileObjectInitiateDownloadServiceCode,
                &CipFileInitiateDownload,
                "CipFileObjectInitiateDownload");
  InsertService(file_object_class,
                kCipFileObjectDownloadTransferServiceCode,
                &CipFileDownloadTransfer,
                "CipFileObjectDownloadTransfer");
  InsertService(file_object_class,
                kCipFileObjectClearFileServiceCode,
                &CipFileClearFile,
                "CipFileObjectClearFile");
  InsertService(file_object_class, kDelete, &CipDeleteService, "Delete");

  /*Add static EDS File Instance 200*/
  CipInstance *new_instance = AddCipInstance(file_object_class,
                                             kCipFileEDSAndIconFileInstanceNumber);
  if( kEipStatusError ==
      CreateFileObject(kCipFileEDSAndIconFileInstanceNumber, eds_file_instance,
                       false) ) {
    return kEipStatusError;
  }
  CipFileSetDownloadAndClearNotSupported(eds_file_instance);
  eds_file_instance->delete_instance_data = NULL; // not deletable
  new_instance->data = eds_file_instance; // data struct pointer for instance

  /* Register timeout checker function in opener */
  RegisterTimeoutChecker(CipFileSessionTimerCheck);

  return CipFileCreateEDSAndIconFileInstance(); /* No instance number needed as this is fixed in the ENIP Spec */
}


