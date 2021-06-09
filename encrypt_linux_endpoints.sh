#!/bin/sh

#Copyright (c) 2021 Mapbox,  All rights reserved.

#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

#    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
#BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
#GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Title: Linux Endpoint Encryption Backup and Rotation Script

# Authors:
# Cole Johnson - Mapbox IT (https://www.linkedin.com/in/coleojohnson/) - 06-09-2021
# Vadim Lukin - Mapbox IT (https://www.linkedin.com/in/vadimlukin/) - 06-09-2021

## Purpose of this script:
## This script was developed by Mapbox IT in order to have a single script to implement, backup, and rotate encryption keys for Linux endpoints.
## It also provides a platform to lock an endpoint in the event it is lost or stolen.
## The end result should feel as unobtrusive to users as macOS FileVault or Windows 10 Bitlocker.

## Components used:
## - LUKS (Standardized Linux Encryption Method)
## - Clevis (Handles encryption implementation across different Linux distributions)
## - Automox (Endpoint Configuration Tool - Where keys are backed up to and recalled from via the Automox API)

## Requirements:
## You must encrypt your Linux volume using LUKS encryption _before_ running this script. This is normally done during the Ubuntu OS installer setup wizard.
## You must include 4 files as dependencies in your Automox encryption policy (listed below). These include your encryption passphrase key in an encrypted format, your API tokens, and your encrypted passphrase files that are used to decrypt these files.
## Provide the name of your default automox server group id in the variable " default_automox_server_group_id='' "
## This script is designed to be deployed via Automox and utilizes the Automox API for encryption key backups and rotations. However, it should be able to be re-factored to support any other Linux configuration management system.


# These files should be uploaded as dependencies into your automox policy. Doing this causes them to be stored in the same directory as the executing script once they are downloaded onto an endpoint
# This script assumes you have your api credentials and encryption passphrase encrypted as hidden files with the following names:
#.atmxapicredenc (Automox API Credentials - Encrypted)
#.atmxapicredkey (Automox API Credentials - Encryption passphrase)
#.psphrsencstring (Encryption passphrase string used to decrypt the encryption passphrase key)
#.psphrskey (Encryption passphrase key - encrypted)

# Example of how to encrypt credentials for your hidden file dependencies:
# echo 'encryption_password_used_during_OS_installation' | openssl enc -base64 -aes-256-cbc -pbkdf2 -salt -pass pass:encryption_signing_password

## High level concept of the script:
## The idea of this script is to keep the endpoint users from knowing any of their encryption tokens (aside from the initial encryption key... unless IT performs the initial encryption steps as well).
## IT or the end-user may setup their own machine, thereby bootstrapping themselves into the start of the encryption process.
## However, once this script runs, it removes that initial token, replacing it with one key stored on the volume and one key stored in the TPM.
## The encryption key on the volume is backed up to Automox, and is never exposed to the end user.
## The TPM encryption key is also never exposed to the end user. Since the volume key is already backed up, it is unnecessary to also back up the TPM key. (This also allows the script to forego the additional complexities of uploading a file's contents via an API call.)
## From this point onwards, the endpoint user is unaware of any encryption token values.
## Only in the event that the user must input a recovery key (after the laptop is lost or stolen) will a user be exposed to an organizational encryption key. In this event, IT should work quickly to re-run this script and rotate that encryption key.

## How the lock process works:
## In the event a laptop is lost or stolen, the TPM is cleared, erasing the encryption key stored in the TPM.

## Automox security:
## Automox randomizes the directory name of the directory it deploys this script and its associated dependencies to.
## The directory, which requires altering permissions for regular users to view, is deleted once the script is done executing.

## Additional context:
## This script does not initially encrypt the volume. The volume initial LUKS encryption is taken care of via the Ubuntu OS intial installation setup wizard.

## Tips:
## After this script runs successfully, each subsequent reboot will cause the Lenovo to lag for about 10-15 seconds before the OS login screen appears. This is when the encryption key is being read from the TPM, so a slight delay is normal.

## Tested on:
## Operating Systems:
## Ubuntu 20.04
## Hardware:
## Manufactuer:
## Lenovo, Dell, Acer
## Models:
# Lenovo ThinkPad P15 Gen 1
# Lenovo ThinkPad P53
# Lenovo IdeaPad Duet 3
# Lenovo ThinkPad T14 Gen 1
# Lenovo V530-24ICB AIO
# Lenovo ThinkPad T15 Gen 1
# Dell XPS 9570
# Acer Predator PH317-52-78X1
# Lenovo X1 20QD
# Lenovo P1 20QT

# Sources referenced:
# luks key information: https://www.thegeekstuff.com/2016/03/cryptsetup-lukskey/
# how to setup lukscrypt add keys automatically with no user interaction: https://blog.sleeplessbeastie.eu/2019/02/20/how-to-non-interactively-manage-luks-passphrases/
# passphrase information: https://access.redhat.com/solutions/230993
# clevis walkthrough info: https://blog.dowhile0.org/2017/10/18/automatic-luks-volumes-unlocking-using-a-tpm2-chip/
# passphrase encryption source: http://www.cyberkeeda.com/2017/06/how-to-use-encrypted-password-in-bash.html

# LUKS Key Slot info (What key slot numbers are used through the script lifecycle)
# Initial LUKS encryption key from OS setup (gets erased) - keyslot 0
# Recovery key - keyslot 2
# TPM - keyslot 3

############################################### Functions

############################################### Upload recovery key to Automox
function upload_recovery_key_to_automox {

  ################################ CREATE RECOVERY KEY API UPLOAD URL
  # First get the local computer name. this will be used to find this computer against all other automox computers
  computer_name=$(hostname)
  echo "Local hostname to look for in the returned list of Automox computers: ${computer_name}" >>$combined_log_path

  curl -s -X GET 'https://console.automox.com/api/servers' -H "Authorization: Bearer ${decrypted_credentials}" >all_servers_response.json

  jq -c '.[]' all_servers_response.json | while read object; do
    echo "Comparing object names.." >>$combined_log_path
    echo "Original computer name" >>$combined_log_path
    echo $computer_name >>$combined_log_path
    name_to_check_against=$(echo $object | jq -r '.name')
    echo "name to check against:" >>$combined_log_path
    echo $name_to_check_against >>$combined_log_path

    if [ $name_to_check_against = $computer_name ]; then
      echo "Computer found!.." >>$combined_log_path
      echo "$object" >selected_computer.json
      break
    fi
  done

  # for debugging - to make sure the parsed json object is the one you intended to select from all the automox machines
  # echo "Selected object:"
  # cat selected_computer.json

  organization_id=$(cat selected_computer.json | jq -r '.organization_id')
  echo "Organization id:" >>$combined_log_path
  echo $organization_id >>$combined_log_path

  serial_number_of_selected_device=$(cat selected_computer.json | jq -r '.serial_number')
  echo "Serial number of selected device:" >>$combined_log_path
  echo $serial_number_of_selected_device >>$combined_log_path

  automox_id_of_selected_device=$(cat selected_computer.json | jq -r '.id')
  echo "Automox id of selected device:" >>$combined_log_path
  echo $automox_id_of_selected_device >>$combined_log_path

  # now formulate the outgoing API call to back up this new LUKS key
  automox_api_update_url="https://console.automox.com/api/servers/${automox_id_of_selected_device}?o=${organization_id}"

  echo "Automox server group id:" >>$combined_log_path
  echo $default_automox_server_group_id >>$combined_log_path
  echo "end automox server group id" >>$combined_log_path

  echo "Automox update url:" >>$combined_log_path
  echo "${automox_api_update_url}" >>$combined_log_path
  ################################ END CREATE RECOVERY KEY API UPLOAD URL

  # Now that you have the encryption key to use, create the outgoing API body
  body="{\"server_group_id\": \"${default_automox_server_group_id}\", \"tags\": [ \"Organization_Encryption_Key: ${key_to_backup_file_first_line}\" ] }"

  echo "Backing up the newly generated backup encryption key to automox.." >>$combined_log_path
  ## Upload encryption key to Automox as device tag for the machine that this script executes on. If this command fails (if backup unsuccessful), exit the script
  curl -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer ${decrypted_credentials}" -d "${body}" "${automox_api_update_url}" || exit 1
}
############################################### END - Upload recovery key to Automox

############################################### set_automox_recovery_key_to_current_passphrase_file
function set_automox_recovery_key_to_current_passphrase_file {
  # First get the local computer name. this will be used to find this computer against all other automox computers
  computer_name=$(hostname)

  echo "Local hostname to look for in the returned list of Automox computers: ${computer_name}" >>$combined_log_path

  curl -s -X GET 'https://console.automox.com/api/servers' -H "Authorization: Bearer ${decrypted_credentials}" >all_servers_response.json

  jq -c '.[]' all_servers_response.json | while read object; do
    echo "Comparing object names.." >>$combined_log_path
    echo "Original computer name" >>$combined_log_path
    echo $computer_name >>$combined_log_path
    name_to_check_against=$(echo $object | jq -r '.name')
    echo "name to check against:" >>$combined_log_path
    echo $name_to_check_against >>$combined_log_path

    if [ $name_to_check_against = $computer_name ]; then
      echo "Computer found!.." >>$combined_log_path
      # echo $object >> $combined_log_path
      echo "$object" >selected_computer.json
      break
    fi
  done

  organization_id=$(cat selected_computer.json | jq -r '.organization_id')
  echo "Organization id:" >>$combined_log_path
  echo $organization_id >>$combined_log_path

  automox_id_of_selected_device=$(cat selected_computer.json | jq -r '.id')
  echo "Automox id of selected device:" >>$combined_log_path
  echo $automox_id_of_selected_device >>$combined_log_path

  # now formulate the outgoing API call to back up this new LUKS key
  automox_api_retrieve_computer_details_url="https://console.automox.com/api/servers/${automox_id_of_selected_device}?o=${organization_id}"

  echo "Automox server group id:" #>> $combined_log_path
  echo $default_automox_server_group_id >>$combined_log_path
  echo "end automox server group id" >>$combined_log_path

  echo "Automox update url:" >>$combined_log_path
  echo "${automox_api_retrieve_computer_details_url}" >>$combined_log_path

  echo "Getting the specific device from automox.." >>$combined_log_path

  selected_computer_tags=$(cat selected_computer.json | jq .tags)

  # cycle through tags and select organization encryption tag
  tag_string_to_search_for='Organization_Encryption_Key'

  echo $selected_computer_tags | jq -c '.[]' | while read tag; do
    echo "Comparing tag names.." >>$combined_log_path
    echo "Tag string to search for:" >>$combined_log_path
    echo $tag_string_to_search_for >>$combined_log_path
    #tag_to_check_against=` echo $tag `
    # echo "checking against tag:" >> $combined_log_path
    # echo $tag >> $combined_log_path

    if [[ "$tag" == *"$tag_string_to_search_for"* ]]; then
      echo "Encryption tag found!.." >>$combined_log_path
      # echo $tag >> $combined_log_path
      echo "$tag" | jq -r >selected_tag.json
      break
    fi
  done

  selected_tag_variable=$(cat selected_tag.json)

  selected_tag_final=${selected_tag_variable#*: }

  echo "Organization recovery encryption key (slot 3)"
  printf "${selected_tag_final}" | tee current_passphrase

}
############################################### END - Set Automox recovery key to current passphrase file function

############################################### END - Functions

############################################################################################## Begin script work
# default automox group id (For "Default" group in the automox console, so we hardcode this value)
default_automox_server_group_id=''


############################################### SETUP LOGGING
# Directory for all automox linux script logs
log_directory='/var/log/organization_it/automox'
log_name='ENCRYPT-Bind_or_Recovery_Bind.log'
combined_log_path="${log_directory}/${log_name}"

# First check to see if the log directory exists. If it doesnt, create it
if [ ! -d $log_directory ]; then
  echo "Log directory \"$log_directory\" doesnt yet exist. Creating this directory.."
  mkdir -p "$log_directory"
fi

# Now that we know the log directory exists, check for this particular log file. If it doesnt exist, create it
if [ ! -f $combined_log_path ]; then
  echo "Log \"$log_name\" doesnt yet exist in directory \"$log_directory\". Creating log file.."
  touch "$combined_log_path"
fi

echo "Check log file: \"$combined_log_path\" for output"
echo "Starting LUKS encryption-check script.." >>$combined_log_path
echo "Date: $(date +"%Y-%b-%d %T")" >>$combined_log_path

############################################### END SETUP LOGGING

############################################### CHECK FOR LUKS ENCRYPTED VOLUME
echo "First checking to find an encrypted volume. This currently only supports LUKS encryption methods The volume must ALREADY have been encrypted for this script to work.." >>$combined_log_path

echo “Finding name of encrypted volume..” >>$combined_log_path
luks_encrypted_volumes=$(dmsetup ls | grep crypt | cut -f1 -d_)

if [ -z "$luks_encrypted_volumes" ]; then
  echo "Returned output: \"$luks_encrypted_volumes\"" >>$combined_log_path
  echo "No LUKS-encrypted volume found. Exiting with an error code." >>$combined_log_path
  exit 1
else
  echo "LUKS-encrypted volume(s) found! Proceeding.." >>$combined_log_path
  echo "LUKS encrypted volume(s): \"$luks_encrypted_volumes\"" >>$combined_log_path
fi

############################################### END CHECK FOR LUKS ENCRYPTED VOLUME

############################################### GET UPDATES - INSTALL PACKAGES

echo "Getting updates before installing tpm app.." >>$combined_log_path
apt-get update >>$combined_log_path

echo "Installing tpm2-tools, clevis libraries, curl, and JQ for JSON handling.." >>$combined_log_path
apt -y install tpm2-tools clevis clevis-luks clevis-udisks2 clevis-tpm2 clevis-dracut clevis-initramfs jq curl >>$combined_log_path

############################################### END GET UPDATES - INSTALL PACKAGES

############################################### GET ACTIVE LUKS KEYSLOTS
# output all current LUKS info to JSON formatted file
cryptsetup luksDump /dev/${luks_encrypted_volumes} --debug-json | tr -d '\n' | sed -E 's/^[^{]*//;s/[^}]*$//' >luksInfo.json

cat luksInfo.json | jq -r '.keyslots' | jq 'keys' >current_keyslots.json

jq '.[]' current_keyslots.json | while read object; do
  echo "Evaluating keyslot number:" >>$combined_log_path
  echo $object >>$combined_log_path
  key_to_check_against=$(echo $object | jq -r)
  if [ $key_to_check_against = 0 ]; then
    echo "Keyslot 0 found! Will run encryption initialization process. Proceeding to next steps.." >>$combined_log_path
    echo "true" >script_first_run
    break
  else
    echo "Keyslot 0 not found yet.. Setting script_first_run file to false until found.. " >>$combined_log_path
    echo "false" >script_first_run
  fi
done
############################################### END - GET ACTIVE LUKS KEYSLOTS
f = .

############################################### RETRIEVE AND DECRYPT CREDENTIALS

# retrieve credentials from encrypted store
encrypted_string=$(head -n 1 ./.atmxapicredenc)
encrypted_string_signing_pass=$(head -n 1 ./.atmxapicredkey)

decrypted_credentials=$(echo "${encrypted_string}" | openssl enc -base64 -aes-256-cbc -pbkdf2 -salt -pass pass:$encrypted_string_signing_pass -d)

############################################### END RETRIEVE AND DECRYPT CREDENTIALS

############################################### API RESPONSE TEST
echo "Testing api connection before proceeding by running a simple GET command to the automox api.." >>$combined_log_path
test_api_response=$(curl -o /dev/null -s -w "%{http_code}" 'https://console.automox.com/api/servers' -H "Authorization: Bearer ${decrypted_credentials}")
echo "${test_api_response}" >>$combined_log_path

if [[ $test_api_response = 20* ]]; then
  echo "contains success code!" >>$combined_log_path
else
  echo "error - does not contain success code. Exiting process." >>$combined_log_path
  exit 1
fi

############################################### END API RESPONSE TEST

############################################### CHECK IF SCRIPT FIRST RUN
# If machine has not been encrypted before, encrypt machine. Otherwise, securely re-encrypt the machine
# if contents of script_first_run eq "true" run the "initialize_encryption" function, else, run the "recovery_reactivation" function
script_first_run_boolean=$(cat script_first_run)

if [ $script_first_run_boolean == "true" ]; then
  # run first-pass encryption steps
  echo "LUKS keyslot 0 is occupied, meaning the encryption key the user set during OS installation still exists." >>$combined_log_path
  echo "Running first-time encryption setup.. This process will wipe the encryption key from keyslot 0 and replace this with IT-generated keys." >>$combined_log_path

  echo "Using initial-os-installation passphrase as current password to bind the TPM." >>$combined_log_path

  # decrypt the encrypted strings
  echo "decrypting encryption passphrase.." >>$combined_log_path
  # decrypted_passphrase=`echo "${passphrase_encrypted_string}" | openssl enc -base64 -aes-256-cbc -md md5 -pbkdf2 -salt -pass pass:$passphrase_signing_key -d`
  # INCLUDE A SPACE AFTER THE BACKTICK "`"
  # Do not separate the variable name and the "=" sign with a space
  # If you fail to follow these formatting steps, you will likely receive a "bad magic number" error
  decrypted_passphrase=$(cat .psphrsencstring | openssl enc -base64 -aes-256-cbc -pbkdf2 -salt -pass file:.psphrskey -d)

  # pass the decrypted string to the current_passphrase file
  echo "Writing encryption passphrase to file.." >>$combined_log_path
  printf "${decrypted_passphrase}" | tee current_passphrase # uncomment to debug the correct passphrase ending up in the current_passphrase file >> $combined_log_path

  echo "Passphrase value to try and use:" >>$combined_log_path
  echo $(cat ./current_passphrase) >>$combined_log_path

else
  echo "Running LUKS re-bind workflow" >>$combined_log_path
  echo "Current passphrase is the automox api encryption tag value. retrieve it and set it as the current_passphrase file" >>$combined_log_path
  set_automox_recovery_key_to_current_passphrase_file
fi

# set correct permissions for current passphrase file
chmod 400 current_passphrase >>$combined_log_path

############################################### END CHECK IF SCRIPT FIRST RUN

############################################### CREATE TPM ENCRYPTION KEY
echo "Seeing if TPM 2.0 is enabled first.. If not, exit script with error message - NOT YET EXITING AS OF 10-15-20 - CJ" >>$combined_log_path
tpm2_status=$(echo tpm2_nvdefine)
echo "tpm 2 status:" >>$combined_log_path
echo ${tpm2_status} >>$combined_log_path

echo "Clearing TPM first as a preliminary step.." >>$combined_log_path
tpm2_clear >>$combined_log_path

echo "Generating alphanumeric random 64 character TPM key.." >>$combined_log_path
cat /dev/urandom | tr -dc '[:alnum:]' | head -c 64 >tpm_key

echo "TPM key file generation complete. Proceeding.." >>$combined_log_path
############################################### END CREATE TPM ENCRYPTION KEY


############################################### BIND TPM ENCRYPTION KEY VIA CLEVIS
echo "Using clevis to write tpm_key into the TPM as a clevis secret.." >>$combined_log_path
cat tpm_key | clevis encrypt tpm2 '{}' >clevis_secret.jwe

echo "Binding the key now in your TPM to your LUKS encrypted volume" >>$combined_log_path
echo "What the luks encrypted volume path should be:" >>$combined_log_path
echo "/dev/${luks_encrypted_volumes}" >>$combined_log_path
############################################### END BIND TPM ENCRYPTION KEY VIA CLEVIS


############################################### CREATE AND BIND ENCRYPTION RECOVERY KEY
# Create backup key to later insert into LUKS keyslot 2
cat /dev/urandom | tr -dc '[:alnum:]' | head -c 30 >./key_to_backup
key_to_backup_file_first_line=$(head -n 1 ./key_to_backup)

if [ $script_first_run_boolean = "true" ]; then

  echo "Binding newly generated encryption key to the TPM using LUKS slot 3. Script will fail out if this is not successful" >>$combined_log_path
  clevis luks bind -s 3 -k ./current_passphrase -d "/dev/${luks_encrypted_volumes}" tpm2 '{"pcr_bank":"sha256","pcr_ids":"0,1"}' || exit 1
  echo "Successfully wrote key to TPM using LUKS slot 3." >>$combined_log_path

  # add the key to be backed up to luks. exit this script if the command fails
  echo "Adding newly-generated organization encryption recovery key to LUKS slot 2. Script will fail if unsuccessful.." >>$combined_log_path
  cryptsetup luksAddKey -S 2 --key-file ./current_passphrase /dev/${luks_encrypted_volumes} ./key_to_backup >>$combined_log_path || exit 1
  echo "Successfully wrote encryption recovery key to LUKS slot 2. Proceeding.. " >>$combined_log_path

  echo "Now that we've written a TPM key to LUKS, use this same backup key to remove old non-Clevis keys from LUKS slot 0.." >>$combined_log_path
  cryptsetup luksKillSlot /dev/${luks_encrypted_volumes} 0 --key-file ./key_to_backup || exit 1
  echo "Successfully removed LUKS key from key slot 0 (Should be the key that was used during initial Linux OS installation.)" >>$combined_log_path

else

  echo "Erasing previous TPM key Clevis metadata and deleting TPM recovery key to free it up for a new key. Script will fail out if this is not successful.." >>$combined_log_path
  # wipe associated clevis token metadata so you do not use unnecessary space and eventually exceed 10 header slots
  clevis luks unbind -d /dev/${luks_encrypted_volumes} -s 3 -f || exit 1

  echo "Binding newly generated encryption key to the TPM using LUKS slot 3. Script will fail out if this is not successful" >>$combined_log_path
  clevis luks bind -s 3 -k ./current_passphrase -d "/dev/${luks_encrypted_volumes}" tpm2 '{"pcr_bank":"sha256","pcr_ids":"0,1"}' || exit 1

  echo "Now that we've written a TPM key to LUKS, use this same backup key to rotate the previous Automox recovery key.." >>$combined_log_path
  echo "Rotate keyslot 2 with newly-generated organization encryption recovery key. Script will fail if unsuccessful.." >>$combined_log_path
  cryptsetup luksChangeKey -S 2 --key-file current_passphrase /dev/${luks_encrypted_volumes} ./key_to_backup >>$combined_log_path || exit 1
  echo "Successfully reset key slot 2 with new recovery key. Proceeding.." >>$combined_log_path

fi

############################################### END CREATE AND BIND ENCRYPTION RECOVERY KEY

# now upload your recovery key to automox
upload_recovery_key_to_automox

# For debugging
# echo "Double check that the key from the file matches the output of what you just stored in clevis:" >> $combined_log_path
# clevis decrypt < clevis_secret.jwe
# echo "Should match the root key file:" >> $combined_log_path
# cat tpm_key

# not sure if unliking is necessary
unlink current_passphrase >>$combined_log_path

# clean up passphrase file if still there
echo "Deleting the current passphrase file remnant. Script will exit if unsuccessful.." >>$combined_log_path
rm -rf ./current_passphrase || exit 1

echo "Script complete. Exiting." >>$combined_log_path

############################################################################################## End script work