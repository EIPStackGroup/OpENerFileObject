######################################################
#                                                    #
# Copyright (c) 2020, Rockwell Automation, Inc.      #
# All rights reserved.                               #
#                                                    #
######################################################

project(CIP_FILE_OBJECT LANGUAGES C VERSION 3.0) 
##################################
# File object class 0x37         #
##################################
opener_add_cip_object( ${PROJECT_NAME} "File Object (class 0x37)")

#######################################
# Add common includes                 #
#######################################
opener_common_includes()

#######################################
# Add platform-specific includes      #
#######################################
opener_platform_support("INCLUDES")

###############################################################
# Looking for OpENer.eds file for static File Object Instance #
###############################################################
set(OPENER_DATA_FOLDER "${OpENer_SOURCE_DIR}/../data")
find_file( FILE_OBJECT_EDS_FILE_LOCATION NAMES opener_sample_app.eds PATHS ${OPENER_DATA_FOLDER} NO_DEFAULT_PATH  DOC "EDS File to be provided by File Object Instance 0xC8" )
add_definitions(-DFILE_OBJECT_EDS_FILE_LOCATION=\"${FILE_OBJECT_EDS_FILE_LOCATION}\")

##################################
# Set source for library         #
##################################
set( ${PROJECT_NAME}_SOURCE cipfile.c )

include_directories(${${PROJECT_NAME}_SOURCE_DIR})

##################################
# Create library		         #
##################################
add_library( ${PROJECT_NAME} ${${PROJECT_NAME}_SOURCE})

##################################
# Add object to includes         #
##################################
string(STRIP "${OpENer_ADD_CIP_OBJECTS} ${PROJECT_NAME}" OpENer_TRIMMED_ADD_CIP_OBJECTS)
set(OpENer_ADD_CIP_OBJECTS "${OpENer_TRIMMED_ADD_CIP_OBJECTS}" CACHE INTERNAL STRING )

target_link_libraries( ${PROJECT_NAME} CIP )
