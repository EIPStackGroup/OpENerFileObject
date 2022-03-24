/*******************************************************************************
 * Copyright (c) 2020, Rockwell Automation, Inc.
 * All rights reserved.
 *
 ******************************************************************************/

#include <stdio.h>

#include "string.h"

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

static CipFileObjectValues file_object_values[STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES]; //TODO: change ??

static CipFileObjectValues *eds_file_instance = &file_object_values[0]; /* EDS file instance*/

static CipBool dummy_attribute;

static const CipUint kCipFileEDSAndIconFileInstanceNumber = 0xC8U; //200

#define CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE 100U
#define CIP_FILE_UPLOAD_SESSIONS 1

typedef struct cip_file_upload_session {
  bool inUse;
  CipFileObjectValues *associated_instance;
  size_t last_send_size;
  CipUsint negotiated_transfer_size;
  CipUsint transfer_number;
  uint_fast64_t session_timeout_milliseconds;
} CipFileObjectUploadSession;

static CipFileObjectUploadSession upload_sessions[CIP_FILE_UPLOAD_SESSIONS];

typedef enum cip_file_initiate_general_status_code {
  kCipFileInitiateGeneralStatusFileSizeTooLarge = 0x20U,
  kCipFileInitiateGeneralStatusFileFormatVersionNotCompatible = 0x20U,
  kCipFileInitiateGeneralStatusFailOnTransferZeroSize = 0x20U,
  kCipFileInitiateGeneralStatusFileNameEmpty = 0x20U,
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

CipFileObjectUploadSession* CipFileGetUnusedUploadSession() {
  for(size_t i = 0; i < CIP_FILE_UPLOAD_SESSIONS; ++i) {
    if(false == upload_sessions[i].inUse) {
      return &upload_sessions[i];
    }
  }
  return NULL;
}

void CipFileInitializeUploadSessions() {
  memset(upload_sessions, 0, sizeof(CipFileObjectUploadSession) * CIP_FILE_UPLOAD_SESSIONS);
}

void CipFileResetTimeout(CipFileObjectUploadSession *const session) {
  session->session_timeout_milliseconds = session->associated_instance->file_transfer_timeout * 1000ULL; /* seconds to milliseconds */
}

void CipFileReleaseUploadSession(CipFileObjectValues *const struct_to_instance) {
  if(NULL != struct_to_instance->aquired_session) {
    memset(struct_to_instance->aquired_session, 0, sizeof(CipFileObjectUploadSession));
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
        OPENER_TRACE_INFO("Time left %" PRIu64 "\n", upload_sessions[i].session_timeout_milliseconds);
        CipFileTimeoutSession(&upload_sessions[i]);
      } else {
        upload_sessions[i].session_timeout_milliseconds -= elapsed_time;
      }
    }
  }
}

void CipFileTakeUploadSession(CipFileObjectValues *const struct_to_instance, CipFileObjectUploadSession *const session) {
  struct_to_instance->aquired_session = session;
  session->inUse = true;
  session->associated_instance = struct_to_instance;
  CipFileResetTimeout(session);
}

void CipFileEncodeFileRevision(const void *const data, ENIPMessage *const outgoing_message) {
  const CipFileObjectFileRevision *const file_revision = data;
  EncodeCipUsint(&(file_revision->major_revision), outgoing_message);
  EncodeCipUsint(&(file_revision->minor_revision), outgoing_message);
}

void EncodeCipFileObjectDirectory(const void *const data, ENIPMessage *const outgoing_message) {
  const CipInstance *const class_instance = GetCipInstance(file_object_class, 0); /* Get class instance */
  CipAttributeStruct *instance_number = GetCipAttribute(class_instance, 3);
  CipUint number_of_instances = *(CipUint*) instance_number->data;
  for(CipUint i = 1; i <= number_of_instances; ++i) {
    CipInstance *instance = GetCipInstance(file_object_class, i); /* Get class instance */
    if(NULL == instance) {
      continue;
    }
    EncodeCipUint(&i, outgoing_message);
    CipAttributeStruct *instance_name = GetCipAttribute(instance, 2);
    EncodeCipStringI((CipStringIStruct*) instance_name->data, outgoing_message);
    CipAttributeStruct *file_name = GetCipAttribute(instance, 4);
    EncodeCipStringI((CipStringIStruct*) file_name->data, outgoing_message);
  }
}

void GenerateFileInitiateUploadHeader(const CipFileInitiateGeneralStatusCode general_status, const CipUsint additional_status_size,
    const CipUint additional_status_code, const CipMessageRouterRequest *const message_router_request, CipMessageRouterResponse *const message_router_response) {
  InitializeENIPMessage(&message_router_response->message);
  message_router_response->reply_service = (0x80 | message_router_request->service);
  message_router_response->general_status = general_status;
  message_router_response->additional_status[0] = additional_status_code;
  message_router_response->size_of_additional_status = additional_status_size;
}

static CipFileObjectValues* CipFileObjectGetDataStruct(const CipInstance *RESTRICT const instance) {
  for(size_t i = 0; i < STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES; ++i) {
    CipAttributeStruct *file_name_struct = GetCipAttribute(instance, 4);
    if(file_name_struct->data == &file_object_values[i].file_name) { /* Same string address = same instance object */
      return &file_object_values[i];
    }
  }
  return NULL;
}

static CipFileObjectState InitiateUpload(CipInstance *RESTRICT const instance, CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response) {

  CipFileObjectUploadSession *upload_session = CipFileGetUnusedUploadSession();

  if(NULL == upload_session) {
    message_router_response->general_status = kCipErrorResourceUnavailable;
    message_router_response->size_of_additional_status = 0;
    message_router_response->additional_status[0] = 0;
    return kCipFileObjectStateFileLoaded;
  }

  CipUsint client_maximum_transfer_size = GetUsintFromMessage(&message_router_request->data);

  CipUsint chosen_transfer_size = (client_maximum_transfer_size <
  CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE) ? client_maximum_transfer_size :
  CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE;

  CipAttributeStruct *file_size_attribute = GetCipAttribute(instance, 6);
  CipUdint *file_size = (CipUdint*) file_size_attribute->data;
  EncodeCipUdint(file_size, &message_router_response->message);
  EncodeCipUsint(&chosen_transfer_size, &message_router_response->message);
  CipFileObjectValues *const struct_to_instance = CipFileObjectGetDataStruct(instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  rewind(struct_to_instance->file_handle);
  upload_session->negotiated_transfer_size = chosen_transfer_size;
  upload_session->transfer_number = 0;

  if(0U == client_maximum_transfer_size) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] = kCipFileInitiateExtendedStatusFailOnTransferZeroSize;
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }

  CipFileTakeUploadSession(struct_to_instance, upload_session);

  return kCipFileObjectStateTransferUploadInitiated;
}

static CipFileObjectState TransferUploadFromInitiateUpload(CipInstance *RESTRICT const instance, CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response) {

  CipFileObjectValues *const struct_to_instance = CipFileObjectGetDataStruct(instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  CipFileObjectUploadSession *upload_session = struct_to_instance->aquired_session;

  CipUsint received_transfer_number = GetSintFromMessage(&message_router_request->data);
  if(0 != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] = kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kCipFileObjectStateTransferUploadInProgress;
  }

  CipFileResetTimeout(upload_session);

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);
  upload_session->transfer_number = 1; // Had to start with 0, so the next must be 1

  CipUsint transfer_packet_type = kCipFileTransferPacketTypeFirstTransferPacket;
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size = upload_session->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send, sizeof(CipOctet), negotiated_transfer_size, struct_to_instance->file_handle);
  if(ferror(struct_to_instance->file_handle)) {
    perror("Error occurred in TransferUploadFromInitiateUpload");
  }
  if(negotiated_transfer_size > data_send_length) {
    transfer_packet_type = kCipFileTransferPacketTypeFirstAndLastPacket;
  }

  EncodeCipUsint(&transfer_packet_type, &message_router_response->message);
  memcpy(message_router_response->message.current_message_position, data_to_send, data_send_length);
  message_router_response->message.current_message_position += data_send_length;
  message_router_response->message.used_message_length += data_send_length;

  if(kCipFileTransferPacketTypeFirstAndLastPacket == transfer_packet_type) {
    EncodeCipInt(&struct_to_instance->file_checksum, &message_router_response->message);
    rewind(struct_to_instance->file_handle);
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }
  return kCipFileObjectStateTransferUploadInProgress;

}

static CipFileObjectState TransferUpload(CipInstance *RESTRICT const instance, CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response) {

  CipFileObjectValues *struct_to_instance = CipFileObjectGetDataStruct(instance);
  OPENER_ASSERT(NULL != struct_to_instance);

  CipFileObjectUploadSession *upload_session = struct_to_instance->aquired_session;

  CipUsint received_transfer_number = GetSintFromMessage(&message_router_request->data);
  if(upload_session->transfer_number != received_transfer_number && upload_session->transfer_number - 1 != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] = kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kCipFileObjectStateTransferUploadInProgress;
  }

  CipFileResetTimeout(upload_session); //Only update on correct sequence number

  if(upload_session->transfer_number - 1 == received_transfer_number) {
    upload_session->transfer_number--;
    fseek(struct_to_instance->file_handle, -1 * (long) upload_session->last_send_size, SEEK_CUR);
  }

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);

  CipUsint transfer_packet_type = (
      upload_session->transfer_number != 0 ? kCipFileTransferPacketTypeMiddleTransferPacket : kCipFileTransferPacketTypeFirstTransferPacket);
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size = upload_session->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send, sizeof(CipOctet), negotiated_transfer_size, struct_to_instance->file_handle);
  upload_session->last_send_size = data_send_length;

  if(negotiated_transfer_size > data_send_length) {
    transfer_packet_type = kCipFileTransferPacketTypeLastTransferPacket;
  }

  EncodeCipUsint(&transfer_packet_type, &message_router_response->message);
  memcpy(message_router_response->message.current_message_position, data_to_send, data_send_length);
  message_router_response->message.current_message_position += data_send_length;
  message_router_response->message.used_message_length += data_send_length;

  if(kCipFileTransferPacketTypeLastTransferPacket == transfer_packet_type) {
    OPENER_TRACE_INFO("Last transfer packet\n");
    EncodeCipInt(&struct_to_instance->file_checksum, &message_router_response->message);
    rewind(struct_to_instance->file_handle);
    CipFileReleaseUploadSession(struct_to_instance);
    return kCipFileObjectStateFileLoaded;
  }

  upload_session->transfer_number++;
  return kCipFileObjectStateTransferUploadInProgress;

}

EipStatus CipFileInitiateUpload(CipInstance *RESTRICT const instance, CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response, const struct sockaddr *originator_address, const int encapsulation_session) {
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint*) state_attribute->data;
  switch(*state){
    case kCipFileObjectStateNonExistent:
      GenerateFileInitiateUploadHeader(kCipErrorObjectDoesNotExist, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorSuccess, 0, 0, message_router_request, message_router_response);
      *state = InitiateUpload(instance, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 1, *state, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 1, *state, message_router_request, message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state in File Object instance: %d", instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

EipStatus CipFileUploadTransfer(CipInstance *RESTRICT const instance, CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response, const struct sockaddr *originator_address, const int encapsulation_session) {
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint*) state_attribute->data;
  switch(*state){
    case kCipFileObjectStateNonExistent:
      GenerateFileInitiateUploadHeader(kCipErrorObjectDoesNotExist, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateFileEmpty:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInitiated:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferDownloadInProgress:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateStoring:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateFileLoaded:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict, 0, 0, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInitiated:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorSuccess, 0, 0, message_router_request, message_router_response);
      *state = TransferUploadFromInitiateUpload(instance, message_router_request, message_router_response);
      break;
    case kCipFileObjectStateTransferUploadInProgress:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorSuccess, 0, 0, message_router_request, message_router_response);
      *state = TransferUpload(instance, message_router_request, message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state in File Object instance: %d", instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

/** @brief File Object PreCreateCallback
 *
 *  Used for common Create service before new instance is created
 *  @See Vol.1, Chapter 5A-42.4.1
 */
EipStatus CipFilePreCreateCallback(
    CipInstance *RESTRICT const instance,
    CipMessageRouterRequest *const message_router_request,
    CipMessageRouterResponse *const message_router_response
) {

  if (message_router_request->request_data_size > 0) {
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
		CipMessageRouterResponse *const message_router_response) {

	//TODO: check if instance_name is already in use

	//create new file object struct
	CipFileObjectValues *file_instance = CipCalloc(1, sizeof(CipFileObjectValues));

	//get instance_name StringI from message - param 1
	CipStringIDecodeFromMessage(&file_instance->instance_name,
			message_router_request);

	//get Encoding format from message - param 2
	file_instance->file_encoding_format = GetUsintFromMessage(&message_router_request->data);

	//default values
	file_instance->state = kCipFileObjectStateFileEmpty;
	file_instance->file_revision.major_revision = 0;
	file_instance->file_revision.minor_revision = 0;
	file_instance->file_name.number_of_strings = 0; //empty file name
	file_instance->invocation_method = kCipFileInvocationMethodNotApplicable; //TODO: check

	file_instance->file_transfer_timeout = CIP_FILE_OBJECT_DEFAULT_TIMEOUT;

	InsertAttribute(new_instance, 1, kCipUsint, EncodeCipUsint, NULL,
			&file_instance->state, kGetableSingle);
	InsertAttribute(new_instance, 2, kCipStringI, EncodeCipStringI, NULL,
			&file_instance->instance_name, kGetableSingle);
	InsertAttribute(new_instance, 3, kCipUint, EncodeCipUint, NULL,
			&file_instance->file_format_version, kGetableSingle);
	InsertAttribute(new_instance, 4, kCipAny, EncodeCipStringI, NULL,
			&file_instance->file_name, kGetableSingle);
	InsertAttribute(new_instance, 5, kCipAny, CipFileEncodeFileRevision, NULL,
			&file_instance->file_revision, kGetableSingle);
	InsertAttribute(new_instance, 6, kCipUdint, EncodeCipUdint, NULL,
			&file_instance->file_size, kGetableSingle);
	InsertAttribute(new_instance, 7, kCipUint, EncodeCipUint, NULL,
			&file_instance->file_checksum, kGetableSingle);
	InsertAttribute(new_instance, 8, kCipUsint, EncodeCipUsint, NULL,
			&file_instance->invocation_method, kGetableSingle);
	InsertAttribute(new_instance, 9, kCipByte, EncodeCipByte, NULL,
			&file_instance->file_save_parameters, kGetableSingle);
	InsertAttribute(new_instance, 10, kCipUsint, EncodeCipUsint, NULL,
			&file_instance->file_access_rule, kGetableSingle);
	InsertAttribute(new_instance, 11, kCipUsint, EncodeCipUsint, NULL,
			&file_instance->file_encoding_format, kGetableSingle);
	InsertAttribute(new_instance, 12, kCipUsint, EncodeCipUsint, NULL,
			&file_instance->file_transfer_timeout, kSetAndGetAble);

	AddIntToMessage(new_instance->instance_number,
			&(message_router_response->message));
	AddSintToMessage(file_instance->invocation_method,
			&(message_router_response->message));
	return kEipStatusOk;
}

EipStatus CreateFileObject(unsigned int instance_nr) {
  CipInstance *instance = GetCipInstance(file_object_class, instance_nr);

  InsertAttribute(instance, 1, kCipUsint, EncodeCipUsint, NULL, &eds_file_instance->state, kGetableSingle);
  InsertAttribute(instance, 2, kCipStringI, EncodeCipStringI, NULL, &eds_file_instance->instance_name, kGetableSingle);
  InsertAttribute(instance, 3, kCipUint, EncodeCipUint, NULL, &eds_file_instance->file_format_version, kGetableSingle);
  InsertAttribute(instance, 4, kCipAny, EncodeCipStringI, NULL, &eds_file_instance->file_name, kGetableSingle);
  InsertAttribute(instance, 5, kCipAny, CipFileEncodeFileRevision, NULL, &eds_file_instance->file_revision, kGetableSingle);
  InsertAttribute(instance, 6, kCipUdint, EncodeCipUdint, NULL, &eds_file_instance->file_size, kGetableSingle);
  InsertAttribute(instance, 7, kCipUint, EncodeCipUint, NULL, &eds_file_instance->file_checksum, kGetableSingle);
  InsertAttribute(instance, 8, kCipUsint, EncodeCipUsint, NULL, &eds_file_instance->invocation_method, kGetableSingle);
  InsertAttribute(instance, 9, kCipByte, EncodeCipByte, NULL, &eds_file_instance->file_save_parameters, kGetableSingle);
  InsertAttribute(instance, 10, kCipUsint, EncodeCipUsint, NULL, &eds_file_instance->file_access_rule, kGetableSingle);
  InsertAttribute(instance, 11, kCipUsint, EncodeCipUsint, NULL, &eds_file_instance->file_encoding_format, kGetableSingle);
  InsertAttribute(instance, 12, kCipUsint, EncodeCipUsint, NULL, &eds_file_instance->file_transfer_timeout, kSetAndGetAble);
  /* Default values*/
  eds_file_instance->file_transfer_timeout = CIP_FILE_OBJECT_DEFAULT_TIMEOUT;
  return kEipStatusOk;
}

void CipFileInitializeClassSettings(CipClass *cip_class) {
  CipClass *meta_class = cip_class->class_instance.cip_class;

  InsertAttribute((CipInstance*) cip_class, 1, kCipUint, EncodeCipUint, NULL, (void*) &cip_class->revision, kGetableSingleAndAll); /* revision */
  InsertAttribute((CipInstance*) cip_class, 2, kCipUint, EncodeCipUint, NULL, (void*) &cip_class->max_instance, kGetableSingleAndAll); /*  largest instance number */
  InsertAttribute((CipInstance*) cip_class, 3, kCipUint, EncodeCipUint, NULL, (void*) &cip_class->number_of_instances, kGetableSingleAndAll); /* number of instances currently existing*/
  InsertAttribute((CipInstance*) cip_class, 4, kCipUint, EncodeCipUint, NULL, (void*) &kCipUintZero, kGetableAll); /* optional attribute list - default = 0 */
  InsertAttribute((CipInstance*) cip_class, 5, kCipUint, EncodeCipUint, NULL, (void*) &kCipUintZero, kNotSetOrGetable); /* optional service list - default = 0 */
  InsertAttribute((CipInstance*) cip_class, 6, kCipUint, EncodeCipUint, NULL, (void*) &meta_class->highest_attribute_number, kGetableSingle); /* max class attribute number*/
  InsertAttribute((CipInstance*) cip_class, 7, kCipUint, EncodeCipUint, NULL, (void*) &cip_class->highest_attribute_number, kGetableSingle); /* max instance attribute number*/
  InsertAttribute((CipInstance*) cip_class, 32, kCipAny, EncodeCipFileObjectDirectory, NULL, &dummy_attribute, kGetableSingle);

  InsertService(meta_class, kGetAttributeSingle, &GetAttributeSingle, "GetAttributeSingle");
  InsertService(meta_class, kCreate, &CipCreateService, "Create");

  // add Callback function pointers
  cip_class->PreCreateCallback = &CipFilePreCreateCallback;
  cip_class->PostCreateCallback = &CipFilePostCreateCallback;

  cip_class->number_of_instances = 0;//kCipFileEDSAndIconFileInstanceNumber; /* Predefined instance for EDS File and Icon File */ //TODO: check
  cip_class->max_instance = kCipFileEDSAndIconFileInstanceNumber; /* Predefined instance for EDS File and Icon File */
  AddCipInstance(cip_class, kCipFileEDSAndIconFileInstanceNumber);
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
    if(1 != fread(&byte, sizeof(CipOctet), 1, eds_file_instance->file_handle)) {
      OPENER_TRACE_ERR("File read error in checksum creation!\n");
    }
    checksum += byte;
  }
  eds_file_instance->file_checksum = (CipUint) (0x10000UL - (CipUdint) checksum);
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
  eds_file_instance->file_encoding_format = kCipFileObjectFileEncodinfFormatBinary;

  eds_file_instance->instance_name.number_of_strings = 1;
  eds_file_instance->instance_name.array_of_string_i_structs = CipCalloc(eds_file_instance->instance_name.number_of_strings, sizeof(CipStringIStruct));
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_1 = 'e';
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_2 = 'n';
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_3 = 'g';
  eds_file_instance->instance_name.array_of_string_i_structs[0].character_set = kCipStringICharSet_ISO_8859_1_1987;
  eds_file_instance->instance_name.array_of_string_i_structs[0].char_string_struct = kCipShortString;
  eds_file_instance->instance_name.array_of_string_i_structs[0].string = CipCalloc(1, sizeof(CipShortString));
  CipShortString *instance_name_short_string = (CipShortString*) (eds_file_instance->instance_name.array_of_string_i_structs[0].string);
  instance_name_short_string->length = sizeof(instance_name_string) - 1;
  instance_name_short_string->string = CipCalloc(sizeof(instance_name_string), sizeof(EipByte));
  memcpy(instance_name_short_string->string, instance_name_string, sizeof(instance_name_string));

  char file_name_string[] = "EDS.txt";
  eds_file_instance->file_name.number_of_strings = 1;
  eds_file_instance->file_name.array_of_string_i_structs = CipCalloc(eds_file_instance->file_name.number_of_strings, sizeof(CipStringIStruct));
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_1 = 'e';
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_2 = 'n';
  eds_file_instance->file_name.array_of_string_i_structs[0].language_char_3 = 'g';
  eds_file_instance->file_name.array_of_string_i_structs[0].character_set = kCipStringICharSet_ISO_8859_1_1987;
  eds_file_instance->file_name.array_of_string_i_structs[0].char_string_struct = kCipShortString;
  eds_file_instance->file_name.array_of_string_i_structs[0].string = CipCalloc(1, sizeof(CipShortString));
  CipShortString *file_name_short_string = (CipShortString*) (eds_file_instance->file_name.array_of_string_i_structs[0].string);
  file_name_short_string->length = sizeof(file_name_string) - 1;
  file_name_short_string->string = CipCalloc(sizeof(file_name_string), sizeof(EipByte));
  memcpy(file_name_short_string->string, file_name_string, sizeof(file_name_string));

  InsertService(file_object_class, kGetAttributeSingle, &GetAttributeSingle, "GetAttributeSingle");
  InsertService(file_object_class, kCipFileObjectInitiateUploadServiceCode, &CipFileInitiateUpload, "CipFileObjectInitiateUploadServiceCode");
  InsertService(file_object_class, kCipFileObjectUploadTransferServiceCode, &CipFileUploadTransfer, "CipFileObjectUploadTransferServiceCode");

  return kEipStatusOk;
}

EipStatus CipFileInit() {
  if(NULL == (file_object_class = CreateCipClass(kCipFileObjectClassCode, 7, /* # class attributes */
  32, /* # highest class attribute number */
  2, /* # class services */ //TODO: check
  12, /* # instance attributes */
  12, /* # highest instance attribute number */
  3, /* # instance services */
  0, /* # instances - zero to suppress creation */
  "File Object", /* # debug name */
  3, /* # class revision */
  CipFileInitializeClassSettings /* # function pointer for initialization */
  ))) {
    /* Initialization failed */
    return kEipStatusError;
  }

  CipFileInitializeUploadSessions();

  if(kEipStatusError == CreateFileObject(kCipFileEDSAndIconFileInstanceNumber)) {
    return kEipStatusError;
  }

  return CipFileCreateEDSAndIconFileInstance(); /* No instance number needed as this is fixed in the ENIP Spec */
}


