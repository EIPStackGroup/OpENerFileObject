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

#define STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES 1

static CipClass *file_object_class = NULL;

static CipFileObjectValues file_object_values[
  STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES];

static CipFileObjectValues *eds_file_instance = &file_object_values[0]; /* EDS file instance*/

static CipBool dummy_attribute;

static const CipUint kCipFileEDSAndIconFileInstanceNumber = 0xC8U;

#define CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE 100U

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
  kCipFileTransferExtendedStatusFailOnChecksum = 0x0000U,  /**< Dummy code indicating no additional code required */
  kCipFileTransferExtendedStatusFailOnSaveToNonVolatileMemory = 0x0000U  /**< Dummy code indicating no additional code required */
} CipFileTransferExtendedStatusCode;

typedef enum cip_file_object_state {
  kCipFileObjectStateNonexistent = 0,
  kCipFileObjectStateFileEmpty,
  kCipFileObjectStateFileLoaded,
  kCipFileObjectStateTransferUploadInitiated,
  kCipFileObjectStateTransferDownloadInitiated,
  kCipFileObjectStateTransferUploadInProgress,
  kCipFileObjectStateTransferDownloadInProgress,
  kCipFileObjectStateStoring
} CipFileObjectState;

void CipFileEncodeFileRevision(const void *const data,
                               ENIPMessage *const outgoing_message) {
  const CipFileObjectFileRevision *const file_revision = data;
  EncodeCipUsint(&(file_revision->major_revision), outgoing_message);
  EncodeCipUsint(&(file_revision->minor_revision), outgoing_message);
}

void EncodeCipFileObjectDirectory(const void *const data,
                                  ENIPMessage *const outgoing_message) {
  const CipInstance *const class_instance =
    GetCipInstance(file_object_class, 0);                                         /* Get class instance */
  CipAttributeStruct *instace_number = GetCipAttribute(class_instance, 3);
  CipUint number_of_instances = *(CipUint *)instace_number->data;
  for(size_t i = 1; i <= number_of_instances; ++i) {
    CipInstance *instance = GetCipInstance(file_object_class, i); /* Get class instance */
    if(NULL == instance) {
      continue;
    }
    EncodeCipUint(&i, outgoing_message);
    CipAttributeStruct *instance_name = GetCipAttribute(instance, 2);
    EncodeCipStringI( (CipStringIStruct *)instance_name->data,
                      outgoing_message );
    CipAttributeStruct *file_name = GetCipAttribute(instance, 4);
    EncodeCipStringI( (CipStringIStruct *)file_name->data, outgoing_message );
  }
}

void GenerateFileInitiateUploadHeader(
  const CipFileInitiateGeneralStatusCode general_status,
  const CipUsint additional_status_size,
  const CipUint additional_status_code,
  const CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response) {
  InitializeENIPMessage(&message_router_response->message);
  message_router_response->reply_service =
    (0x80 | message_router_request->service);
  message_router_response->general_status =
    kCipFileInitiateExtendedStatusFileEmpty;
  message_router_response->additional_status[0] = additional_status_code;
  message_router_response->size_of_additional_status = additional_status_size;
}

static CipFileObjectValues *CipFileObjectGetDataStruct(
  const CipInstance *RESTRICT const instance) {
  for(size_t i = 0; i < STATIC_FILE_OBJECT_NUMBER_OF_INSTANCES; ++i) {
    CipAttributeStruct *file_name_struct = GetCipAttribute(instance, 4);
    if(file_name_struct->data == &file_object_values[i].file_name) { /* Same string address = same instance object */
      return &file_object_values[i];
    }
  }
  return NULL;
}

static CipFileObjectState InitiateUpload(CipInstance *RESTRICT const instance,
                                         CipMessageRouterRequest *const message_router_request,
                                         CipMessageRouterResponse *const message_router_response)
{
  CipUsint client_maximum_transfer_size = GetUsintFromMessage(
    &message_router_request->data);

  CipUsint chosen_transfer_size =
    (client_maximum_transfer_size <
     CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE) ? client_maximum_transfer_size :
    CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE;

  CipAttributeStruct *file_size_attribute = GetCipAttribute(instance, 6);
  CipUdint *file_size = (CipUdint *)file_size_attribute->data;
  EncodeCipUdint(file_size, &message_router_response->message);
  EncodeCipUsint(&chosen_transfer_size, &message_router_response->message);
  CipFileObjectValues *struct_to_instance;
  if(NULL == (struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }
  rewind(struct_to_instance->file_handle);
  struct_to_instance->negotiated_transfer_size = chosen_transfer_size;
  struct_to_instance->transfer_number = 0;

  if(0U == client_maximum_transfer_size) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileInitiateExtendedStatusFailOnTransferZeroSize;
    return kCipFileObjectStateFileLoaded;
  }
  return kCipFileObjectStateTransferUploadInitiated;
}

static CipFileObjectState TransferUploadFromInitiateUpload(
  CipInstance *RESTRICT const instance,
  CipMessageRouterRequest *const message_router_request,
  CipMessageRouterResponse *const message_router_response) {

  CipFileObjectValues *struct_to_instance;
  if(NULL == (struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }

  CipUsint received_transfer_number = GetSintFromMessage(
    &message_router_request->data);
  if(struct_to_instance->transfer_number != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kEipStatusOkSend;
  }

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);
  struct_to_instance->transfer_number++;

  CipUsint transfer_packet_type = kCipFileTransferPacketTypeFirstTransferPacket;
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size =
    struct_to_instance->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send,
                                        sizeof(CipOctet),
                                        negotiated_transfer_size,
                                        struct_to_instance->file_handle);
  if (ferror (struct_to_instance->file_handle) ) {
    perror("Error occurred in TransferUploadFromInitiateUpload");
  }
  if(negotiated_transfer_size > data_send_length) {
    transfer_packet_type = kCipFileTransferPacketTypeFirstAndLastPacket;
    rewind(struct_to_instance->file_handle);
  }
  EncodeCipUsint(&transfer_packet_type, &message_router_response->message);
  memcpy(message_router_response->message.current_message_position,
         data_to_send,
         data_send_length);
  message_router_response->message.current_message_position += data_send_length;
  message_router_response->message.used_message_length += data_send_length;

  if(kCipFileTransferPacketTypeFirstAndLastPacket == transfer_packet_type) {
    EncodeCipInt(&struct_to_instance->file_checksum,
                 &message_router_response->message);
    return kCipFileObjectStateFileLoaded;
  }
  return kCipFileObjectStateTransferUploadInProgress;

}

static CipFileObjectState TransferUpload(CipInstance *RESTRICT const instance,
                                         CipMessageRouterRequest *const message_router_request,
                                         CipMessageRouterResponse *const message_router_response)
{

  CipFileObjectValues *struct_to_instance;
  if(NULL == (struct_to_instance = CipFileObjectGetDataStruct(instance) ) ) {
    /*No entry found - not possible as instance was found */
    OPENER_ASSERT(false);
  }

  CipUsint received_transfer_number = GetSintFromMessage(
    &message_router_request->data);
  if(struct_to_instance->transfer_number != received_transfer_number &&
     struct_to_instance->transfer_number - 1 != received_transfer_number) {
    message_router_response->general_status = kCipErrorInvalidParameter;
    message_router_response->size_of_additional_status = 1;
    message_router_response->additional_status[0] =
      kCipFileTransferExtendedStatusFailOnTransferOutOfSequence;
    return kCipFileObjectStateFileLoaded;
  }

  if(struct_to_instance->transfer_number - 1 == received_transfer_number) {
    struct_to_instance->transfer_number--;
    fseek(struct_to_instance->file_handle,
          -1 * (long)struct_to_instance->last_send_size,
          SEEK_CUR);
  }

  EncodeCipUsint(&received_transfer_number, &message_router_response->message);
  struct_to_instance->transfer_number++;

  CipUsint transfer_packet_type =
    kCipFileTransferPacketTypeMiddleTransferPacket;
  CipOctet data_to_send[CIP_FILE_OBJECT_MAXIMUM_TRANSFER_SIZE] = { 0 };
  CipUsint negotiated_transfer_size =
    struct_to_instance->negotiated_transfer_size;
  const size_t data_send_length = fread(data_to_send,
                                        sizeof(CipOctet),
                                        negotiated_transfer_size,
                                        struct_to_instance->file_handle);
  struct_to_instance->last_send_size = data_send_length;
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
    EncodeCipInt(&struct_to_instance->file_checksum,
                 &message_router_response->message);
    rewind(struct_to_instance->file_handle);
    return kCipFileObjectStateFileLoaded;
  }
  return kCipFileObjectStateTransferUploadInProgress;

}

EipStatus CipFileInitiateUpload(CipInstance *RESTRICT const instance,
                                CipMessageRouterRequest *const message_router_request,
                                CipMessageRouterResponse *const message_router_response,
                                const struct sockaddr *originator_address,
                                const int encapsulation_session) {
  CipAttributeStruct *state_attribute = GetCipAttribute(instance, 1);
  CipUsint *state = (CipUsint *)state_attribute->data;
  switch(*state) {
    case kCipFileStateNonExistent:
      GenerateFileInitiateUploadHeader(kCipErrorObjectDoesNotExist,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateFileEmpty:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateTransferDownloadInitiated:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateTransferDownloadInProgress:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateStoring:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateFileLoaded:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      *state = InitiateUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    case kCipFileStateTransferUploadedInitiated:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      *state = InitiateUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    case kCipFileStateTransferUploadInProgress:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      *state = InitiateUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state in File Object instance: %d",
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
  CipUsint *state = (CipUsint *)state_attribute->data;
  switch(*state) {
    case kCipFileStateNonExistent:
      GenerateFileInitiateUploadHeader(kCipErrorObjectDoesNotExist,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateFileEmpty:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateTransferDownloadInitiated:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateTransferDownloadInProgress:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateStoring:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateFileLoaded:
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      break;
    case kCipFileStateTransferUploadedInitiated:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      *state = TransferUploadFromInitiateUpload(instance,
                                                message_router_request,
                                                message_router_response);
      break;
    case kCipFileStateTransferUploadInProgress:
      /* Insert Happy Path */
      GenerateFileInitiateUploadHeader(kCipErrorObjectStateConflict,
                                       0,
                                       0,
                                       message_router_request,
                                       message_router_response);
      *state = TransferUpload(instance,
                              message_router_request,
                              message_router_response);
      break;
    default:
      OPENER_TRACE_ERR("Unknown state in File Object instance: %d",
                       instance->instance_number);
      OPENER_ASSERT(false);
      break;
  }
  return kEipStatusOkSend;
}

EipStatus CreateFileObject(unsigned int instance_nr) {
  CipInstance *instance = GetCipInstance(file_object_class, instance_nr);

  InsertAttribute(instance,
                  1,
                  kCipUsint,
                  EncodeCipUsint,
                  &eds_file_instance->state,
                  kGetableSingle);
  InsertAttribute(instance,
                  2,
                  kCipStringI,
                  EncodeCipStringI,
                  &eds_file_instance->instance_name,
                  kGetableSingle);
  InsertAttribute(instance,
                  3,
                  kCipUint,
                  EncodeCipUint,
                  &eds_file_instance->file_format_version,
                  kGetableSingle);
  InsertAttribute(instance,
                  4,
                  kCipAny,
                  EncodeCipStringI,
                  &eds_file_instance->file_name,
                  kGetableSingle);
  InsertAttribute(instance,
                  5,
                  kCipAny,
                  CipFileEncodeFileRevision,
                  &eds_file_instance->file_revision,
                  kGetableSingle);
  InsertAttribute(instance,
                  6,
                  kCipUdint,
                  EncodeCipUdint,
                  &eds_file_instance->file_size,
                  kGetableSingle);
  InsertAttribute(instance,
                  7,
                  kCipUint,
                  EncodeCipUint,
                  &eds_file_instance->file_checksum,
                  kGetableSingle);
  InsertAttribute(instance,
                  8,
                  kCipUsint,
                  EncodeCipUsint,
                  &eds_file_instance->invocation_method,
                  kGetableSingle);
  InsertAttribute(instance,
                  9,
                  kCipByte,
                  EncodeCipByte,
                  &eds_file_instance->file_save_parameters,
                  kGetableSingle);
  InsertAttribute(instance,
                  10,
                  kCipUsint,
                  EncodeCipUsint,
                  &eds_file_instance->file_access_rule,
                  kGetableSingle);
  InsertAttribute(instance,
                  11,
                  kCipUsint,
                  EncodeCipUsint,
                  &eds_file_instance->file_encoding_format,
                  kGetableSingle);
  return kEipStatusOk;
}

void CipFileInitializeClassSettings(CipClass *cip_class) {
  CipClass *meta_class = cip_class->class_instance.cip_class;

  InsertAttribute( (CipInstance *) cip_class, 1, kCipUint, EncodeCipUint,
                   (void *) &cip_class->revision, kGetableSingleAndAll ); /* revision */
  InsertAttribute( (CipInstance *) cip_class, 2, kCipUint, EncodeCipUint,
                   (void *) &cip_class->number_of_instances,
                   kGetableSingleAndAll );                        /*  largest instance number */
  InsertAttribute( (CipInstance *) cip_class, 3, kCipUint, EncodeCipUint,
                   (void *) &cip_class->number_of_instances,
                   kGetableSingleAndAll );                        /* number of instances currently existing*/
  InsertAttribute( (CipInstance *) cip_class, 4, kCipUint, EncodeCipUint,
                   (void *) &kCipUintZero, kGetableAll );         /* optional attribute list - default = 0 */
  InsertAttribute( (CipInstance *) cip_class, 5, kCipUint, EncodeCipUint,
                   (void *) &kCipUintZero, kNotSetOrGetable );    /* optional service list - default = 0 */
  InsertAttribute( (CipInstance *) cip_class, 6, kCipUint, EncodeCipUint,
                   (void *) &meta_class->highest_attribute_number,
                   kGetableSingle );                              /* max class attribute number*/
  InsertAttribute( (CipInstance *) cip_class, 7, kCipUint, EncodeCipUint,
                   (void *) &cip_class->highest_attribute_number,
                   kGetableSingle );                              /* max instance attribute number*/
  InsertAttribute( (CipInstance *) cip_class, 32, kCipAny,
                   EncodeCipFileObjectDirectory,
                   &dummy_attribute, kGetableSingle );

  InsertService(meta_class,
                kGetAttributeSingle,
                &GetAttributeSingle,
                "GetAttributeSingle");

  cip_class->number_of_instances = kCipFileEDSAndIconFileInstanceNumber; /* Predefined instance for EDS File and Icon File */
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
    if(1 !=
       fread(&byte, sizeof(CipOctet), 1, eds_file_instance->file_handle) ) {
      OPENER_TRACE_ERR("File read error in checksum creation!\n");
    }
    checksum += byte;
  }
  eds_file_instance->file_checksum = (CipUint)(0x10000UL - (CipUdint)checksum);
}

EipStatus CipFileCreateEDSAndIconFileInstance() {
  const char instance_name_string[] = "EDS and Icon Files";
  eds_file_instance->file_handle = fopen(FILE_OBJECT_EDS_FILE_LOCATION, "rb");
  if(NULL == eds_file_instance->file_handle) {
    OPENER_TRACE_ERR("File does not exist\n");
    return kEipStatusError;
  }
  eds_file_instance->state = kCipFileStateFileLoaded;
  CipFileSetFileLength(eds_file_instance);
  CipFileSetChecksum(eds_file_instance);

  eds_file_instance->file_format_version = 1;
  eds_file_instance->invocation_method = kCipFileInvocationMethodNotApplicable;
  eds_file_instance->file_save_parameters = 0;
  eds_file_instance->file_access_rule = kCipFileObjectFileAccessRuleReadOnly;
  eds_file_instance->file_encoding_format =
    kCipFileObjectFileEncodinfFormatBinary;

  eds_file_instance->instance_name.number_of_strings = 1;
  eds_file_instance->instance_name.array_of_string_i_structs = CipCalloc(
    eds_file_instance->instance_name.number_of_strings,
    sizeof(CipStringIStruct) );
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_1
    = 'e';
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_2
    = 'n';
  eds_file_instance->instance_name.array_of_string_i_structs[0].language_char_3
    = 'g';
  eds_file_instance->instance_name.array_of_string_i_structs[0].character_set =
    kCipStringICharSet_ISO_8859_1_1987;
  eds_file_instance->instance_name.array_of_string_i_structs[0].
  char_string_struct = kCipShortString;
  eds_file_instance->instance_name.array_of_string_i_structs[0].string =
    CipCalloc(1, sizeof(CipShortString) );
  CipShortString *instance_name_short_string =
    (CipShortString *)(eds_file_instance->instance_name.
                       array_of_string_i_structs[
                         0].string);
  instance_name_short_string->length = sizeof(instance_name_string) - 1;
  instance_name_short_string->string = CipCalloc(sizeof(instance_name_string),
                                                 sizeof(EipByte) );
  memcpy(instance_name_short_string->string, instance_name_string,
         sizeof(instance_name_string) );

  char file_name_string[] = "EDS.txt";
  eds_file_instance->file_name.number_of_strings = 1;
  eds_file_instance->file_name.array_of_string_i_structs = CipCalloc(
    eds_file_instance->file_name.number_of_strings,
    sizeof(CipStringIStruct) );
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
    1,
    sizeof(CipShortString) );
  CipShortString *file_name_short_string =
    (CipShortString *)(eds_file_instance->file_name.array_of_string_i_structs[0]
                       .
                       string);
  file_name_short_string->length = sizeof(file_name_string) - 1;
  file_name_short_string->string =
    CipCalloc(sizeof(file_name_string), sizeof(EipByte) );
  memcpy(file_name_short_string->string, file_name_string,
         sizeof(file_name_string) );

  InsertService(file_object_class,
                kGetAttributeSingle,
                &GetAttributeSingle,
                "GetAttributeSingle");
  InsertService(file_object_class,
                kCipFileObjectInitiateUploadServiceCode,
                &CipFileInitiateUpload,
                "CipFileObjectGetAttributeSingleClass");
  InsertService(file_object_class,
                kCipFileObjectUploadTransferServiceCode,
                &CipFileUploadTransfer,
                "CipFileObjectGetAttributeSingleClass");

  return kEipStatusOk;
}

EipStatus CipFileInit() {
  if( NULL == ( file_object_class = CreateCipClass(kCipFileObjectClassCode,
                                                   7, /* # class attributes */
                                                   32, /* # highest class attribute number */
                                                   1, /* # class services */
                                                   11, /* # instance attributes */
                                                   11, /* # highest instance attribute number */
                                                   3, /* # instance services */
                                                   0, /* # instances - zero to supress creation */
                                                   "File Object",
                                                   2, /* # class revision */
                                                   CipFileInitializeClassSettings                 /* # function pointer for initialization */
                                                   ) ) ) {
    /* Initialization failed */
    return kEipStatusError;
  }

  if(kEipStatusError ==
     CreateFileObject(kCipFileEDSAndIconFileInstanceNumber) ) {
    return kEipStatusError;
  }

  return CipFileCreateEDSAndIconFileInstance(); /* No instance number needed as this is fixed in the ENIP Spec */
}

