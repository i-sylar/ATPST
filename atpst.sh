#!/bin/bash

# Color codes for better output visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display ASCII art banner
display_banner() {
    echo -e "${BLUE}"
    echo "     █████╗ ████████╗██████╗ ███████╗████████╗"
    echo "    ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝╚══██╔══╝"
    echo "    ███████║   ██║   ██████╔╝███████╗   ██║   "
    echo "    ██╔══██║   ██║   ██╔═══╝ ╚════██║   ██║   "
    echo "    ██║  ██║   ██║   ██║     ███████║   ██║   "
    echo "    ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝   ╚═╝   "
    echo -e "${NC}"
    echo -e "${YELLOW}Android Testing Platform Setup Tool V2 By @bionic_${NC}"
    echo ""
}

# Global variables for script state
CUSTOM_PHONE_UUID=""
SELECTED_VM_NAME=""
KILL_ADB_ON_EXIT="true"
SELECTED_PACKAGE=""

# Setup cleanup trap
trap cleanup_with_prompt INT
trap cleanup EXIT

# Function to print colored messages
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if Genymotion is running
check_genymotion_running() {
    # Check if Genymotion process is running
    if pgrep -x "Genymotion" > /dev/null || pgrep -f "Genymotion.app" > /dev/null; then
        return 0  # Genymotion is running
    else
        return 1  # Genymotion is not running
    fi
}

# Function to handle Ctrl+C and prompt for VM shutdown
cleanup_with_prompt() {
    echo ""
    print_info "Script interrupted by user (Ctrl+C)."
    
    # Ask user if they want to kill the VM
    if [ -n "$CUSTOM_PHONE_UUID" ] && [ -f "$GMTOOL_PATH" ]; then
        if check_genymotion_running; then
            VM_STATUS=$("$GMTOOL_PATH" admin list 2>/dev/null | grep -F "$CUSTOM_PHONE_UUID" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
            
            if [ "$VM_STATUS" = "Running" ] || [ "$VM_STATUS" = "On" ]; then
                echo ""
                read -p "Do you want to stop the running VM ($SELECTED_VM_NAME)? (y/n): " kill_vm_choice
                if [[ "$kill_vm_choice" =~ ^[Yy]$ ]]; then
                    print_info "Stopping VM ($SELECTED_VM_NAME)..."
                    "$GMTOOL_PATH" admin stop "$CUSTOM_PHONE_UUID" > /dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        print_success "VM stopped successfully."
                    else
                        print_warning "Failed to stop VM. You may need to stop it manually."
                    fi
                else
                    print_info "VM will continue running."
                fi
            fi
        fi
    fi
    
    cleanup
    exit 0
}

# Function to cleanup on exit
cleanup() {
    print_info "Performing cleanup..."
    
    # Kill the selected app if it was launched
    if [ -n "$SELECTED_PACKAGE" ]; then
        print_info "Stopping app: $SELECTED_PACKAGE"
        adb shell "am force-stop $SELECTED_PACKAGE" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "App stopped successfully."
        else
            print_warning "Failed to stop app or app was not running."
        fi
    fi
    
    # Clear proxy settings
    print_info "Clearing proxy settings..."
    adb shell "settings put global http_proxy :0" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Proxy settings cleared."
    else
        print_warning "Failed to clear proxy settings."
    fi
    
    # Kill any ADB connections
    print_info "Cleaning up ADB connections..."
    adb disconnect all > /dev/null 2>&1
    
    # Kill ADB server if requested
    if [ "$KILL_ADB_ON_EXIT" = "true" ]; then
        print_info "Stopping ADB server..."
        adb kill-server > /dev/null 2>&1
    fi
    
    # Clean up any temporary files
    if [ -d "$temp_dir" ]; then
        rm -rf "$temp_dir"
        print_info "Temporary files cleaned up."
    fi
    
    print_info "Cleanup completed. Exiting..."
}

# Function to check if Burp Suite is running
check_burpsuite() {
    print_info "Checking if Burp Suite is running..."
    
    # Check if port 8080 is in use (default Burp Suite proxy port)
    if lsof | grep -i "Burpsuite" > /dev/null 2>&1 || lsof | grep -i "Burp suite" > /dev/null 2>&1; then
        print_success "Burp Suite appears to be running on port 8080."
        return 0
    else
        print_error "Burp Suite does not appear to be running on port 8080. Please start Burp Suite before continuing."
        return 1
    fi
}

# Function to check if device has root access
check_device_root() {
    print_info "Checking device root access..."
    
    # Method 1: Try standard su command
    local root_check=$(adb shell "su -c 'echo root_available' 2>/dev/null" | tr -d '\r\n')
    if [[ "$root_check" == *"root_available"* ]]; then
        print_success "Root access confirmed via standard su command."
        return 0
    fi
    
    # Method 2: Check for su binary existence
    local su_exists=$(adb shell "which su 2>/dev/null || ls -la /system/bin/su 2>/dev/null || ls -la /system/xbin/su 2>/dev/null")
    if [ -n "$su_exists" ]; then
        print_info "Found su binary, attempting root access..."
        
        # Try different su invocation methods
        local root_test1=$(adb shell "su 0 echo root_test 2>/dev/null" | tr -d '\r\n')
        local root_test2=$(adb shell "su root echo root_test 2>/dev/null" | tr -d '\r\n')
        
        if [[ "$root_test1" == *"root_test"* ]] || [[ "$root_test2" == *"root_test"* ]]; then
            print_success "Root access confirmed via su binary."
            return 0
        fi
    fi
    
    # Method 3: Check if this is a Genymotion VM (they usually have root by default)
    local build_product=$(adb shell "getprop ro.product.device 2>/dev/null" | tr -d '\r\n')
    local build_model=$(adb shell "getprop ro.product.model 2>/dev/null" | tr -d '\r\n')
    
    if [[ "$build_product" == *"genymotion"* ]] || [[ "$build_model" == *"Genymotion"* ]]; then
        print_info "Detected Genymotion VM. Genymotion VMs typically have root access."
        
        # Try to enable root in Genymotion
        print_info "Attempting to verify/enable root access on Genymotion VM..."
        
        # Check if ADB already has root
        local adb_root_check=$(adb shell "id" 2>/dev/null | tr -d '\r\n')
        if [[ "$adb_root_check" == *"uid=0"* ]]; then
            print_success "ADB shell already has root privileges."
            return 0
        fi
        
        # Try to get root via adb root command
        print_info "Trying to enable ADB root mode..."
        adb root >/dev/null 2>&1
        sleep 2
        
        # Check again after adb root
        local post_root_check=$(adb shell "id" 2>/dev/null | tr -d '\r\n')
        if [[ "$post_root_check" == *"uid=0"* ]]; then
            print_success "Root access enabled via adb root command."
            return 0
        fi
        
        # Final attempt with su
        print_info "Attempting su access one more time..."
        local final_su_check=$(adb shell "su -c 'id' 2>/dev/null" | tr -d '\r\n')
        if [[ "$final_su_check" == *"uid=0"* ]]; then
            print_success "Root access confirmed via su command."
            return 0
        fi
        
        print_warning "Root access not available on this Genymotion VM."
        print_info "To enable root access:"
        print_info "1. In Genymotion, select your VM"
        print_info "2. Click Settings (gear icon)"
        print_info "3. Go to ADB section"
        print_info "4. Enable 'Use custom Android SDK tools'"
        print_info "5. Restart the VM"
        return 1
    fi
    
    # Method 4: Check for Magisk or other root solutions
    local magisk_check=$(adb shell "which magisk 2>/dev/null || ls -la /system/bin/magisk 2>/dev/null")
    if [ -n "$magisk_check" ]; then
        print_info "Found Magisk, attempting root access..."
        local magisk_su=$(adb shell "magisk su -c 'echo magisk_root' 2>/dev/null" | tr -d '\r\n')
        if [[ "$magisk_su" == *"magisk_root"* ]]; then
            print_success "Root access confirmed via Magisk."
            return 0
        fi
    fi
    
    print_warning "No root access detected. System certificate installation will not be available."
    return 1
}

# Function to install CA certificate as system certificate (requires root)
install_system_ca_cert() {
    local cert_path="$1"
    
    print_info "Installing PortSwigger CA certificate as system certificate..."
    
    # Don't check root access here since check_device_root already does it
    # and we want to use the root access that was already established
    print_info "Proceeding with system certificate installation..."
    
    # Convert DER to PEM if needed
    local pem_file="burp.pem"
    if [[ "$cert_path" == *.der ]] || [[ "$cert_path" == *.cer ]]; then
        print_info "Converting certificate from DER to PEM format..."
        openssl x509 -inform der -in "$cert_path" -out "$pem_file"
        if [ $? -ne 0 ]; then
            print_error "Failed to convert certificate to PEM format."
            return 1
        fi
    else
        # Assume it's already in PEM format or convert anyway to be sure
        print_info "Converting certificate to PEM format..."
        openssl x509 -in "$cert_path" -out "$pem_file" 2>/dev/null || cp "$cert_path" "$pem_file"
    fi
    
    # Generate the certificate hash for the filename
    print_info "Generating certificate hash for filename..."
    local cert_hash=$(openssl x509 -inform PEM -subject_hash_old -in "$pem_file" | head -1)
    if [ -z "$cert_hash" ]; then
        print_error "Failed to generate certificate hash."
        return 1
    fi
    
    local cert_filename="${cert_hash}.0"
    print_info "Certificate will be installed as: $cert_filename"
    
    # Convert PEM to DER format for system installation
    print_info "Converting certificate to DER format for system installation..."
    openssl x509 -in "$pem_file" -out "$cert_filename" -outform DER
    if [ $? -ne 0 ]; then
        print_error "Failed to convert certificate to DER format."
        return 1
    fi
    
    # Check if ADB already has root, if not try to get it
    local current_uid=$(adb shell "id -u" 2>/dev/null | tr -d '\r\n')
    
    if [ "$current_uid" != "0" ]; then
        print_info "Enabling ADB root access..."
        adb root >/dev/null 2>&1
        sleep 3
        
        # Check again after adb root
        current_uid=$(adb shell "id -u" 2>/dev/null | tr -d '\r\n')
        if [ "$current_uid" != "0" ]; then
            print_warning "ADB root command didn't work. Using su for subsequent commands."
            USE_SU="true"
        else
            print_success "ADB root access enabled."
            USE_SU="false"
        fi
    else
        print_success "ADB already has root access."
        USE_SU="false"
    fi
    
    # Remount system partition
    print_info "Remounting system partition as read-write..."
    if [ "$USE_SU" = "true" ]; then
        adb shell "su -c 'mount -o rw,remount /system'"
        remount_result=$?
    else
        adb remount >/dev/null 2>&1
        remount_result=$?
        if [ $remount_result -ne 0 ]; then
            # Try alternative method even with adb root
            adb shell "mount -o rw,remount /system" >/dev/null 2>&1
            remount_result=$?
        fi
    fi
    
    if [ $remount_result -ne 0 ]; then
        print_error "Failed to remount system partition as read-write."
        print_info "This could be due to:"
        print_info "1. System partition protection"
        print_info "2. Insufficient permissions"
        print_info "3. Read-only file system"
        return 1
    else
        print_success "System partition remounted as read-write."
    fi
    
    # Push certificate to system certificates directory
    print_info "Installing certificate to system certificates directory..."
    adb push "$cert_filename" "/system/etc/security/cacerts/"
    if [ $? -ne 0 ]; then
        print_error "Failed to push certificate to system directory."
        return 1
    fi
    
    # Set proper permissions
    print_info "Setting certificate permissions..."
    if [ "$USE_SU" = "true" ]; then
        adb shell "su -c 'chmod 644 /system/etc/security/cacerts/$cert_filename'"
    else
        adb shell "chmod 644 /system/etc/security/cacerts/$cert_filename"
    fi
    
    if [ $? -ne 0 ]; then
        print_error "Failed to set certificate permissions."
        return 1
    else
        print_success "Certificate permissions set successfully."
    fi
    
    # Verify the certificate was installed
    local cert_check=$(adb shell "ls /system/etc/security/cacerts/$cert_filename 2>/dev/null")
    if [[ "$cert_check" == *"$cert_filename"* ]]; then
        print_success "Certificate successfully installed in system certificate store."
    else
        print_error "Failed to verify certificate installation."
        return 1
    fi
    
    # Clean up temporary files
    rm -f "$pem_file" "$cert_filename"
    
    # Reboot the device for changes to take effect
    print_info "System certificate installation complete."
    print_warning "The device needs to reboot for the system certificate to take effect."
    read -p "Do you want to reboot the device now? (y/n): " reboot_choice
    
    if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
        print_info "Rebooting device..."
        adb reboot
        
        print_info "Waiting for device to reboot and reconnect..."
        sleep 10
        
        # Wait for device to come back online
        local reboot_wait_count=0
        while [ $reboot_wait_count -lt 30 ]; do
            if adb devices | grep -q "device$"; then
                print_success "Device reconnected after reboot."
                sleep 5  # Give it a bit more time to fully boot
                return 0
            fi
            sleep 5
            reboot_wait_count=$((reboot_wait_count + 1))
            print_info "Waiting for device to reconnect... ($((reboot_wait_count * 5))/150 seconds)"
        done
        
        print_warning "Device is taking longer than expected to reconnect."
        print_info "Please wait for the device to fully boot, then continue manually."
        read -p "Press Enter when the device is ready and connected... " -r
    else
        print_warning "Device reboot skipped. You'll need to reboot manually for the system certificate to take effect."
        print_info "You can reboot later with: adb reboot"
    fi
    
    return 0
}

# Function to install CA certificate as user certificate (manual process)
install_user_ca_cert() {
    local cert_path="$1"
    
    print_info "Installing PortSwigger CA certificate as user certificate..."
    
    # Convert to PEM format for user installation
    local pem_file="burp.pem"
    if [[ "$cert_path" == *.der ]] || [[ "$cert_path" == *.cer ]]; then
        print_info "Converting certificate from DER to PEM format..."
        openssl x509 -inform der -in "$cert_path" -out "$pem_file"
        if [ $? -ne 0 ]; then
            print_error "Failed to convert certificate to PEM format."
            return 1
        fi
        cert_to_push="$pem_file"
    else
        cert_to_push="$cert_path"
    fi
    
    # Create a readable filename
    local cert_filename=$(basename "$pem_file")
    local device_cert_path="/sdcard/Download/$cert_filename"
    
    # Push certificate to device
    print_info "Copying certificate to device..."
    adb push "$cert_to_push" "$device_cert_path"
    if [ $? -ne 0 ]; then
        print_error "Failed to copy certificate to device."
        return 1
    fi
    
    # For Android 7+, user needs to manually install the certificate
    print_info "Please follow these instructions on your device:"
    print_info "1. The Settings app should open automatically to the certificate installation page"
    print_info "2. If prompted, name the certificate 'Burp Suite PortSwigger'"
    print_info "3. Select 'VPN and apps' or 'CA Certificate' when prompted for certificate type"
    print_info "4. Confirm any security warnings"
    
    # Launch certificate installer on the device
    adb shell "am start -n com.android.settings/.security.InstallCaCertificateWarningActivity"
    sleep 2
    adb shell "am start -a android.settings.SECURITY_SETTINGS"
    sleep 2
    
    # Prompt user to confirm installation is complete
    read -p "Press Enter after you have completed the certificate installation on the device... " -r
    
    # Clean up temporary files
    if [ -f "$pem_file" ] && [ "$pem_file" != "$cert_path" ]; then
        rm -f "$pem_file"
    fi
    
    # Verify certificate installation
    print_info "Verifying certificate installation..."
    if check_portswigger_cert; then
        print_success "PortSwigger CA certificate installed successfully."
        return 0
    else
        print_warning "Could not verify PortSwigger certificate installation. Please check device manually."
        read -p "Did you complete the certificate installation on the device? (y/n): " cert_installed
        if [[ "$cert_installed" =~ ^[Yy]$ ]]; then
            return 0
        else
            return 1
        fi
    fi
}

# Main function to install CA certificate with user choice
install_ca_cert() {
    local cert_path="$1"
    
    if [ ! -f "$cert_path" ]; then
        print_error "Certificate file not found: $cert_path"
        return 1
    fi
    
    print_info "PortSwigger CA certificate installation options:"
    echo ""
    echo "1) User Certificate (Standard) - Installed in user certificate store"
    echo "   • Works for most apps"
    echo "   • Easier to install and manage"
    echo "   • May not work for apps with certificate pinning bypass detection"
    echo ""
    echo "2) System Certificate (Recommended) - Installed in system certificate store"
    echo "   • Works for all apps including those with advanced security"
    echo "   • Harder for apps to detect as 'user-added'"
    echo "   • Requires root access and device reboot"
    echo "   • Provides better coverage for security testing"
    echo ""
    
    # Check if device has root access to inform the user
    if check_device_root; then
        print_success "Root access detected - both options are available."
    else
        print_warning "No root access detected - only user certificate installation is available."
        print_info "If you want system certificate installation, ensure root access is available."
    fi
    
    echo ""
    read -p "Choose installation type (1 for User, 2 for System): " cert_type_choice
    
    case "$cert_type_choice" in
        1)
            print_info "Installing as user certificate..."
            install_user_ca_cert "$cert_path"
            return $?
            ;;
        2)
            print_info "Installing as system certificate..."
            if ! check_device_root; then
                print_error "System certificate installation requires root access."
                print_info "Falling back to user certificate installation..."
                install_user_ca_cert "$cert_path"
                return $?
            else
                install_system_ca_cert "$cert_path"
                return $?
            fi
            ;;
        *)
            print_error "Invalid choice. Please select 1 or 2."
            return 1
            ;;
    esac
}

# Function to check specifically for PortSwigger certificate
check_portswigger_cert() {
    # Check for PortSwigger certificate in system CA store
    local cert_check=$(adb shell "grep -i portswigger /system/etc/security/cacerts/* 2>/dev/null || echo ''")
    
    # Check for PortSwigger certificate in user CA store
    local user_cert_check=$(adb shell "grep -i portswigger /data/misc/user/0/cacerts-added/* 2>/dev/null || echo ''")
    
    # Try to check certificate list using security command
    local security_check=$(adb shell "security list 2>/dev/null | grep -i portswigger || echo ''")
    
    if [ -n "$cert_check" ] || [ -n "$user_cert_check" ] || [ -n "$security_check" ]; then
        return 0  # PortSwigger certificate found
    else
        return 1  # PortSwigger certificate not found
    fi
}

# Function to check if CA certificate is installed on device
check_ca_cert() {
    print_info "Checking if Burp Suite CA certificate is installed on the device..."
    
    # First verify we have ADB connection
    adb devices | grep -q "device$"
    if [ $? -ne 0 ]; then
        print_warning "Cannot verify CA certificate: No device connected via ADB."
        print_info "You will need to verify manually that the certificate is installed."
        read -p "Have you installed the Burp Suite CA certificate on the device? (y/n): " cert_installed
        if [[ ! "$cert_installed" =~ ^[Yy]$ ]]; then
            print_error "Please install the Burp Suite CA certificate on the device before continuing."
            print_info "To install the certificate:"
            print_info "1. In Burp Suite, go to Proxy > Options > Export CA certificate"
            print_info "2. Choose 'Certificate in DER format' and save it"
            print_info "3. Transfer the certificate to your device"
            print_info "4. Go to Settings > Security > Install from storage and select the certificate"
            return 1
        fi
        return 0
    fi
    
    # Specifically check for PortSwigger certificate
    print_info "Checking for PortSwigger CA certificate..."
    if check_portswigger_cert; then
        print_success "PortSwigger CA certificate is installed on the device."
        return 0
    else
        print_warning "PortSwigger CA certificate not found on the device."
        print_info "Would you like to install the PortSwigger CA certificate now?"
        read -p "Enter 'y' to install or 'n' to continue without installing (y/n): " install_cert
        
        if [[ "$install_cert" =~ ^[Yy]$ ]]; then
            print_info "Please drag and drop the PortSwigger CA certificate file (.cer or .der) to the terminal"
            print_info "Or enter the full path to the certificate file:"
            read -p "> " cert_path
            
            # Clean up the path (remove quotes and trailing spaces)
            cert_path=$(echo "$cert_path" | sed "s/^[ '\"]*//" | sed "s/[ '\"]*$//")
            
            if [ -f "$cert_path" ]; then
                install_ca_cert "$cert_path"
                return $?
            else
                print_error "Invalid certificate path: $cert_path"
                return 1
            fi
        else
            print_warning "Proceeding without PortSwigger CA certificate installation."
            print_warning "SSL interception with Burp Suite may not work correctly."
            read -p "Are you sure you want to continue? (y/n): " continue_without_cert
            if [[ "$continue_without_cert" =~ ^[Yy]$ ]]; then
                return 0
            else
                return 1
            fi
        fi
    fi
}

# Function to check if Genymotion is installed
check_genymotion() {
    print_info "Checking if Genymotion is installed..."
    
    # Check for Genymotion in the common macOS application location
    if [ -d "/Applications/Genymotion.app" ]; then
        print_success "Genymotion is installed."
        GMTOOL_PATH="/Applications/Genymotion.app/Contents/MacOS/gmtool"
        
        if [ ! -f "$GMTOOL_PATH" ] || [ ! -x "$GMTOOL_PATH" ]; then
            print_error "gmtool not found at $GMTOOL_PATH or not executable."
        fi
        
        return 0
    else
        print_error "Genymotion is not installed in /Applications. Please install Genymotion first."
        return 1
    fi
}

# Function to list all available VMs - pure data function
list_vms() {
    # Silently get VM list without any output messages
    local VM_LIST=$("$GMTOOL_PATH" admin list 2>/dev/null)
    if [ $? -ne 0 ]; then
        # Only return error code, no messages
        return 1
    fi
    
    # Only return the raw VM list data, no additional output
    printf "%s" "$VM_LIST"
    return 0
}

# Function to check for running VMs and offer to stop them
check_running_vms() {
    print_info "Checking for currently running VMs..."
    
    # Get the raw VM list
    local VM_LIST=$(list_vms)
    if [ $? -ne 0 ]; then
        print_warning "Failed to get VM list. Continuing anyway..."
        return 0
    fi
    
    # Arrays to store running VM info
    declare -a running_vm_names=()
    declare -a running_vm_uuids=()
    declare -a running_vm_states=()
    
    # Parse the VM list to find running VMs
    local running_count=0
    while IFS= read -r line; do
        # Skip empty lines and the header line
        if [ -n "$line" ] && ! echo "$line" | grep -q "State"; then
            # Parse fields
            local state=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
            local uuid=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3}')
            local name=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $4); print $4}')
            
            # Check if VM is running (Genymotion might report "Running" or "On")
            if [ -n "$uuid" ] && ([ "$state" = "Running" ] || [ "$state" = "On" ]); then
                running_vm_names+=("$name")
                running_vm_uuids+=("$uuid")
                running_vm_states+=("$state")
                running_count=$((running_count + 1))
            fi
        fi
    done <<< "$(echo "$VM_LIST" | grep -v '^$')"
    
    # If no running VMs found
    if [ "$running_count" -eq 0 ]; then
        print_success "No running VMs detected. Proceeding..."
        return 0
    fi
    
    # Display running VMs
    echo ""
    print_warning "Found $running_count running VM(s):"
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} NUM ${BLUE}│${NC} STATE  ${BLUE}│${NC} NAME                           ${BLUE}│${NC} UUID (truncated)     ${BLUE}│${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    
    for i in $(seq 0 $((running_count-1))); do
        # Truncate name if too long
        local display_name="${running_vm_names[$i]}"
        if [ ${#display_name} -gt 30 ]; then
            display_name="${display_name:0:27}..."
        fi
        
        # Truncate UUID for display
        local display_uuid="${running_vm_uuids[$i]:0:20}..."
        
        printf "${BLUE}│${NC} %3d ${BLUE}│${NC} %-6s ${BLUE}│${NC} %-30s ${BLUE}│${NC} %-20s ${BLUE}│${NC}\n" \
               $((i+1)) "${running_vm_states[$i]}" "${display_name}" "${display_uuid}"
    done
    
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Ask user what to do
    print_info "Running VMs may interfere with the script or cause ADB connection issues."
    echo "Options:"
    echo "1) Stop all running VMs (Recommended)"
    echo "2) Stop specific VMs"
    echo "3) Continue without stopping any VMs"
    echo ""
    
    while true; do
        read -p "Choose an option (1, 2, or 3): " vm_action_choice
        
        case "$vm_action_choice" in
            1)
                print_info "Stopping all running VMs..."
                for i in $(seq 0 $((running_count-1))); do
                    local vm_name="${running_vm_names[$i]}"
                    local vm_uuid="${running_vm_uuids[$i]}"
                    
                    print_info "Stopping VM: $vm_name"
                    "$GMTOOL_PATH" admin stop "$vm_uuid" > /dev/null 2>&1
                    
                    if [ $? -eq 0 ]; then
                        print_success "VM '$vm_name' stopped successfully."
                    else
                        print_warning "Failed to stop VM '$vm_name'. It may have stopped already."
                    fi
                done
                
                # Wait a moment for VMs to fully stop
                if [ "$running_count" -gt 0 ]; then
                    print_info "Waiting for VMs to fully stop..."
                    sleep 5
                fi
                
                print_success "All running VMs have been stopped."
                break
                ;;
            2)
                echo ""
                print_info "Select VMs to stop (enter numbers separated by spaces, e.g., '1 3'):"
                read -p "VM numbers to stop: " vm_numbers_to_stop
                
                if [ -z "$vm_numbers_to_stop" ]; then
                    print_info "No VMs selected for stopping. Continuing..."
                    break
                fi
                
                # Parse and validate the input
                for vm_num in $vm_numbers_to_stop; do
                    if [[ "$vm_num" =~ ^[0-9]+$ ]] && [ "$vm_num" -ge 1 ] && [ "$vm_num" -le "$running_count" ]; then
                        local index=$((vm_num-1))
                        local vm_name="${running_vm_names[$index]}"
                        local vm_uuid="${running_vm_uuids[$index]}"
                        
                        print_info "Stopping VM: $vm_name"
                        "$GMTOOL_PATH" admin stop "$vm_uuid" > /dev/null 2>&1
                        
                        if [ $? -eq 0 ]; then
                            print_success "VM '$vm_name' stopped successfully."
                        else
                            print_warning "Failed to stop VM '$vm_name'. It may have stopped already."
                        fi
                    else
                        print_warning "Invalid VM number: $vm_num (valid range: 1-$running_count)"
                    fi
                done
                
                print_info "Waiting for selected VMs to fully stop..."
                sleep 3
                print_success "Selected VMs have been processed."
                break
                ;;
            3)
                print_warning "Continuing with running VMs. This may cause ADB connection conflicts."
                print_info "If you experience issues, stop the running VMs manually and restart the script."
                break
                ;;
            *)
                print_warning "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    done
    
    return 0
}

# Function to select a VM from the list
select_vm() {
    print_info "Retrieving and listing available Genymotion VMs..."
    
    # Get the raw VM list without displaying anything
    local VM_LIST=$(list_vms)
    if [ $? -ne 0 ]; then
        print_error "Failed to list VMs. Please check if Genymotion is running properly."
    fi
    
    # Prepare arrays to store VM data
    declare -a vm_lines=()
    declare -a vm_states=()
    declare -a vm_names=()
    declare -a vm_uuids=()
    
    # Counter for VM numbering
    local VM_COUNT=0
    
    # First pass - just count VMs and store them
    while IFS= read -r line; do
        # Skip empty lines and the header line
        if [ -n "$line" ] && ! echo "$line" | grep -q "State"; then
            # Parse fields
            local state=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
            local uuid=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3}')
            local name=$(echo "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $4); print $4}')
            
            # Only process lines that have a valid UUID (to skip empty or header lines)
            if [ -n "$uuid" ]; then
                VM_COUNT=$((VM_COUNT + 1))
                vm_lines+=("$line")
                vm_states+=("$state")
                vm_names+=("$name")
                vm_uuids+=("$uuid")
            fi
        fi
    done <<< "$(echo "$VM_LIST" | grep -v '^$')"
    
    # If no VMs found
    if [ "$VM_COUNT" -eq 0 ]; then
        print_error "No Genymotion VMs found. Please create at least one VM in Genymotion before using this script."
    fi
    
    # Display the VM list with clean formatting
    echo ""
    print_info "Available Genymotion VMs:"
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} NUM ${BLUE}│${NC} STATE  ${BLUE}│${NC} NAME                      ${BLUE}│${NC} UUID                 ${BLUE}│${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────────────┤${NC}"
    
    # Display all VMs with proper padding and alignment
    for i in $(seq 0 $((VM_COUNT-1))); do
        # Truncate name if too long
        local display_name="${vm_names[$i]}"
        if [ ${#display_name} -gt 29 ]; then
            display_name="${display_name:0:23}..."
        fi
        
        # Truncate UUID if too long
        local display_uuid="${vm_uuids[$i]}"
        if [ ${#display_uuid} -gt 29 ]; then
            display_uuid="${display_uuid:0:23}..."
        fi
        
        # Format the row with proper spacing
        printf "${BLUE}│${NC} %3d ${BLUE}│${NC} %-6s ${BLUE}│${NC} %-25s ${BLUE}│${NC} %-29s ${BLUE}│${NC}\n" \
               $((i+1)) "${vm_states[$i]}" "${display_name}" "${display_uuid}"
    done
    
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Prompt for selection
    while true; do
        read -p "Enter the number of the VM you want to use (1-$VM_COUNT): " vm_selection
        
        # Validate input
        if [[ "$vm_selection" =~ ^[0-9]+$ ]] && [ "$vm_selection" -ge 1 ] && [ "$vm_selection" -le "$VM_COUNT" ]; then
            break
        else
            print_warning "Invalid selection. Please enter a number between 1 and $VM_COUNT."
        fi
    done
    
    # Get the selected VM info (1-based to 0-based indexing)
    local index=$((vm_selection-1))
    SELECTED_VM_INFO="${vm_lines[$index]}"
    SELECTED_VM_STATE="${vm_states[$index]}"
    SELECTED_VM_UUID="${vm_uuids[$index]}"
    SELECTED_VM_NAME="${vm_names[$index]}"
    
    # Extract ADB info from the selected VM info
    SELECTED_VM_ADB=$(echo "$SELECTED_VM_INFO" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}')
    
    # Validate that we got valid data
    if [ -z "$SELECTED_VM_UUID" ]; then
        print_error "Failed to extract VM UUID. Please try again."
    fi
    
    print_success "Selected VM: $SELECTED_VM_NAME (UUID: $SELECTED_VM_UUID)"
    
    # Store the selected VM info in global variables
    CUSTOM_PHONE_UUID="$SELECTED_VM_UUID"
    CUSTOM_PHONE_INFO="$SELECTED_VM_INFO"
    SELECTED_VM_NAME="$SELECTED_VM_NAME"
    
    return 0
}

# Function to start the selected VM
start_custom_phone_vm() {
    print_info "Checking VM status..."
    
    # Check if VM is already running - Genymotion might report "Running" or "On"
    VM_STATUS=$("$GMTOOL_PATH" admin list | grep -F "$CUSTOM_PHONE_UUID" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
    
    # VM is already running
    if [ "$VM_STATUS" = "Running" ] || [ "$VM_STATUS" = "On" ]; then
        print_success "$SELECTED_VM_NAME VM is already running."
        # Still need to ensure ADB is connected even if VM is already running
        wait_for_adb_connection
        return 0
    fi
    
    # VM needs to be started
    print_info "Starting $SELECTED_VM_NAME VM..."
    START_OUTPUT=$("$GMTOOL_PATH" admin start "$CUSTOM_PHONE_UUID" 2>&1)
    START_RESULT=$?
    
    # Check for both exit code and "already started" message
    if [ $START_RESULT -ne 0 ] && ! echo "$START_OUTPUT" | grep -q "already started"; then
        print_error "Failed to start $SELECTED_VM_NAME VM. Please check Genymotion setup."
    elif echo "$START_OUTPUT" | grep -q "already started"; then
        print_success "$SELECTED_VM_NAME VM is already running."
        # Still need to ensure ADB is connected even if VM is already started
        wait_for_adb_connection
        return 0
    fi
    
    # VM was just started, wait for it to boot and connect to ADB
    print_info "VM started successfully. Wai"
    # Initial delay to let VM start booting
    #sleep 10
    
    # Wait for ADB connection
    wait_for_adb_connection
}

# Note: This is kept for backward compatibility, but now uses the selected VM
get_custom_phone_vm() {
    print_info "Using selected VM: $SELECTED_VM_NAME"
    
    if [ -z "$CUSTOM_PHONE_UUID" ] || [ -z "$CUSTOM_PHONE_INFO" ]; then
        print_error "No VM selected. Please select a VM first."
    fi
    
    print_success "Using VM with UUID: $CUSTOM_PHONE_UUID"
    return 0
}

# Function to wait for ADB connection
wait_for_adb_connection() {
    print_info "Waiting for ADB connection to device (this may take a minute)..."
    
    # Wait for the VM to fully boot before attempting ADB connection
    print_info "Waiting for VM to fully boot..."
    sleep 5
    
    # Check if Genymotion is still running
    if ! check_genymotion_running; then
        print_warning "Genymotion was closed. Aborting ADB connection attempts."
        exit 1
    fi
    
    # Restart ADB server to ensure clean connection state
    print_info "Restarting ADB server..."
    adb kill-server
    sleep 2
    adb start-server
    sleep 3
    
    # Get ADB port from VM info
    ADB_PORT=$(echo "$CUSTOM_PHONE_INFO" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}' | cut -d':' -f2)
    
    # Common fallback ports to try
    declare -a FALLBACK_PORTS=("5555" "5556" "6555" "6556")
    
    # If ADB port wasn't detected, or looks invalid, prepare to try fallback ports
    if [ -z "$ADB_PORT" ] || [ "$ADB_PORT" -lt 1024 ] || [ "$ADB_PORT" -gt 65535 ]; then
        print_warning "Could not determine valid ADB port from VM info. Will try common ports."
        DETECTED_PORT="false"
    else
        print_info "Detected ADB port from VM info: $ADB_PORT"
        DETECTED_PORT="true"
    fi
    
    # Check for ADB availability with timeout
    MAX_ATTEMPTS=30
    ATTEMPT=0
    
    # Try the detected port first if available
    if [ "$DETECTED_PORT" = "true" ]; then
        print_info "Connecting to device at 127.0.0.1:$ADB_PORT..."
        adb connect 127.0.0.1:$ADB_PORT
        sleep 3
    fi
    
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        # Check if Genymotion is still running
        if ! check_genymotion_running; then
            print_warning "Genymotion was closed. Aborting ADB connection attempts."
            # Set flag to not kill ADB server on exit
            KILL_ADB_ON_EXIT="false"
            cleanup
            exit 1
        fi
        
        # Check both generic device connection and specific emulator connection
        DEVICE_CHECK=$(adb devices | grep -v "List" | grep -v "offline" | grep "device$")
        
        if [ -n "$DEVICE_CHECK" ]; then
            print_success "ADB is now connected to the device."
            print_info "Connected device(s):"
            adb devices | grep -v "List"
            
            # Additional wait to ensure system is fully booted
            sleep 5
            return 0
        fi
        
        # If no connection yet, try connecting again or try fallback ports
        if [ $((ATTEMPT % 5)) -eq 0 ] && [ $ATTEMPT -gt 0 ]; then
            # If using detected port
            if [ "$DETECTED_PORT" = "true" ]; then
                print_info "Retrying connection to 127.0.0.1:$ADB_PORT..."
                adb connect 127.0.0.1:$ADB_PORT
                
                # If first retry fails, start trying fallback ports
                if [ $ATTEMPT -eq 10 ]; then
                    print_warning "Still can't connect using detected port $ADB_PORT. Will try fallback ports."
                    DETECTED_PORT="false"
                fi
            else
                # Try each fallback port
                for PORT in "${FALLBACK_PORTS[@]}"; do
                    if [ "$PORT" != "$ADB_PORT" ]; then  # Skip if it's the already tried detected port
                        print_info "Trying fallback port 127.0.0.1:$PORT..."
                        adb connect 127.0.0.1:$PORT
                        sleep 2
                        
                        # Check if this port worked
                        if adb devices | grep -v "List" | grep -v "offline" | grep "device$" > /dev/null; then
                            print_success "Connected successfully using port $PORT"
                            ADB_PORT="$PORT"
                            return 0
                        fi
                    fi
                done
            fi
        fi
        
        ATTEMPT=$((ATTEMPT+1))
        print_info "Waiting for ADB connection... ($ATTEMPT/$MAX_ATTEMPTS)"
        sleep 2
    done
    
    print_error "Timed out waiting for ADB connection. Please check that:
    1. The VM is running properly in Genymotion
    2. ADB is working correctly
    3. The VM has Android Debug Bridge enabled
    
    You can try manually connecting with: adb connect 127.0.0.1:<PORT>"
}
#display banner
display_banner
sleep 1
# Automated Genymotion VM setup
print_info "Preparing Genymotion environment..."

# Check prerequisites
check_genymotion
check_burpsuite

# Check for running VMs and offer to stop them
check_running_vms

# Let user select a VM
select_vm

# Start the selected VM
start_custom_phone_vm

# Now that the VM is running, check if CA certificate is installed
check_ca_cert

print_success "Genymotion setup complete. Proceeding with the script..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check device connection
check_device_connection() {
    print_info "Checking for connected devices..."
    devices=$(adb devices | grep -v "List" | grep "device$")
    if [ -z "$devices" ]; then
        print_error "No devices connected. Please connect an Android device and try again."
    else
        print_success "Device found!"
        echo "$devices"
    fi
}

# Check if adb is installed and install if not
if ! command_exists adb; then
    print_info "ADB not found. Installing via Homebrew..."
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_error "Homebrew is not installed. Please install Homebrew first: https://brew.sh/"
    fi
    
    brew install android-platform-tools
    
    if ! command_exists adb; then
        print_error "Failed to install ADB. Please install it manually."
    else
        print_success "ADB installed successfully."
    fi
else
    print_success "ADB is already installed."
fi

# Check if pip is installed and install if not
if ! command_exists pip && ! command_exists pip3; then
    print_info "Python pip not found. Installing via Homebrew..."
    
    # Check if Python is installed via brew
    if brew list python &>/dev/null || brew list python3 &>/dev/null; then
        print_info "Python is installed but pip is not available. Trying to reinstall Python..."
        brew reinstall python
    else
        print_info "Installing Python via Homebrew..."
        brew install python
    fi
    
    # Determine which pip command to use
    if command_exists pip3; then
        PIP_CMD="pip3"
    elif command_exists pip; then
        PIP_CMD="pip"
    else
        print_error "Failed to install pip. Please install Python and pip manually."
    fi
else
    # Determine which pip command to use
    if command_exists pip3; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    print_success "Python pip is already installed."
fi

# Function to get Frida version
get_frida_version() {
    if command_exists frida; then
        frida --version 2>/dev/null | head -n1 | awk '{print $1}'
    elif $PIP_CMD show frida &>/dev/null; then
        $PIP_CMD show frida 2>/dev/null | grep "Version:" | awk '{print $2}'
    else
        echo ""
    fi
}

# Function to get latest Frida version from GitHub
get_latest_frida_version() {
    curl -s https://api.github.com/repos/frida/frida/releases/latest 2>/dev/null | \
        grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 || echo "17.2.0"
}

# Function to compare versions (returns 0 if first version >= second version)
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Check if frida is installed and check version
print_info "Checking Frida installation and version..."
current_frida_version=$(get_frida_version)
latest_frida_version=$(get_latest_frida_version)

if [ -z "$current_frida_version" ]; then
    print_info "Frida not found. Installing latest version ($latest_frida_version)..."
    $PIP_CMD install frida==$latest_frida_version
    
    if ! $PIP_CMD show frida &>/dev/null; then
        print_error "Failed to install Frida. Please install it manually with '$PIP_CMD install frida'."
    else
        print_success "Frida $latest_frida_version installed successfully."
        current_frida_version=$latest_frida_version
    fi
else
    print_success "Frida is already installed (version: $current_frida_version)."
    
    # Check if current version is older than latest
    if ! version_ge "$current_frida_version" "$latest_frida_version"; then
        print_info "Current Frida version ($current_frida_version) is older than latest ($latest_frida_version)."
        print_info "Updating Frida to latest version..."
        $PIP_CMD install --upgrade frida==$latest_frida_version
        
        if [ $? -eq 0 ]; then
            print_success "Frida updated to version $latest_frida_version."
            current_frida_version=$latest_frida_version
        else
            print_warning "Failed to update Frida. Continuing with current version."
        fi
    else
        print_success "Frida is up to date (version: $current_frida_version)."
    fi
fi

# Check for connected devices
check_device_connection

# Get the device architecture
print_info "Detecting device CPU architecture..."
arch=$(adb shell getprop ro.product.cpu.abi)
if [ -z "$arch" ]; then
    print_error "Failed to detect device architecture."
fi
print_success "Device architecture: $arch"

# Map Android architecture to Frida architecture
frida_arch=""
case $arch in
    "armeabi-v7a"|"armeabi")
        frida_arch="arm"
        ;;
    "arm64-v8a")
        frida_arch="arm64"
        ;;
    "x86")
        frida_arch="x86"
        ;;
    "x86_64")
        frida_arch="x86_64"
        ;;
    *)
        print_error "Unsupported architecture: $arch"
        ;;
esac

# Function to check Frida server version on device
check_frida_server_version() {
    local device_version=$(adb shell "/data/local/tmp/frida-server --version 2>/dev/null" | head -n1 | tr -d '\r\n' 2>/dev/null)
    echo "$device_version"
}

# Use the current Frida version
frida_version="$current_frida_version"
print_info "Using Frida version: $frida_version"

# Check if Frida server exists and version matches
print_info "Checking Frida server on device..."
frida_server_exists=$(adb shell "[ -f /data/local/tmp/frida-server ] && echo 'yes'" 2>/dev/null | grep -q "yes" && echo "true" || echo "false")

if [ "$frida_server_exists" = "true" ]; then
    device_frida_version=$(check_frida_server_version)
    print_info "Found Frida server on device (version: $device_frida_version)."
    
    if [ "$device_frida_version" = "$frida_version" ]; then
        print_success "Frida server version matches installed Frida version. No update needed."
        skip_download=true
    else
        print_info "Frida server version ($device_frida_version) doesn't match installed Frida version ($frida_version)."
        print_info "Updating Frida server on device..."
        skip_download=false
    fi
else
    print_info "Frida server not found on device. Downloading..."
    skip_download=false
fi

# Download and install Frida server only if needed
if [ "$skip_download" != "true" ]; then
    frida_server_file="frida-server-$frida_version-android-$frida_arch"
    frida_server_url="https://github.com/frida/frida/releases/download/$frida_version/$frida_server_file.xz"
    temp_dir=$(mktemp -d)
    
    print_info "Downloading Frida server from: $frida_server_url"
    curl -L -o "$temp_dir/$frida_server_file.xz" "$frida_server_url"
    
    if [ ! -f "$temp_dir/$frida_server_file.xz" ]; then
        print_error "Failed to download Frida server. Check your internet connection and the URL."
    fi
    
    # Extract Frida server
    print_info "Extracting Frida server..."
    xz -d "$temp_dir/$frida_server_file.xz"
    
    if [ ! -f "$temp_dir/$frida_server_file" ]; then
        print_error "Failed to extract Frida server."
    fi
    
    # Set permissions
    print_info "Setting permissions on Frida server..."
    chmod 755 "$temp_dir/$frida_server_file"
    
    # Push to device
    print_info "Uploading Frida server to device..."
    adb push "$temp_dir/$frida_server_file" /data/local/tmp/frida-server
    adb shell "chmod 755 /data/local/tmp/frida-server"
    
    # Check if upload was successful
    if adb shell "[ -f /data/local/tmp/frida-server ] && echo 'yes'" | grep -q "yes"; then
        print_success "Frida server uploaded successfully."
        
        # Verify version
        new_device_version=$(check_frida_server_version)
        if [ "$new_device_version" = "$frida_version" ]; then
            print_success "Frida server version verified: $new_device_version"
        else
            print_warning "Frida server version mismatch. Expected: $frida_version, Got: $new_device_version"
        fi
    else
        print_error "Failed to upload Frida server to the device."
    fi
else
    # Still create temp_dir for cleanup
    temp_dir=$(mktemp -d)
fi

# Start Frida server in the background
print_info "Starting Frida server on the device..."
adb shell "su -c 'killall frida-server 2>/dev/null || true'"
adb shell "su -c '/data/local/tmp/frida-server &'" &

# Give it a moment to start
sleep 2

# Configure proxy settings
print_info "Now let's configure proxy settings for the device."

# Get the host machine's IP address that's most likely connected to the same network
host_ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)

if [ -z "$host_ip" ]; then
    print_warning "Could not automatically detect host IP address."
    read -p "Please enter your host machine's IP address: " host_ip
fi

print_info "Detected host IP: $host_ip"
read -p "Is this correct? Press Enter to continue or type a new IP address: " user_ip
if [ -n "$user_ip" ]; then
    host_ip="$user_ip"
    print_info "Using custom IP: $host_ip"
fi

# Ask for proxy port
read -p "Enter the proxy port number (default: 8080): " proxy_port
proxy_port=${proxy_port:-8080}

print_info "Setting up proxy automatically..."
print_info "Host: $host_ip"
print_info "Port: $proxy_port"

# Set proxy using ADB
proxy_setting="$host_ip:$proxy_port"
print_info "Configuring proxy settings via ADB..."
adb shell "settings put global http_proxy $proxy_setting"

if [ $? -eq 0 ]; then
    print_success "Proxy command executed successfully."
    
    # Verify proxy settings
    sleep 2
    print_info "Verifying proxy configuration..."
    current_proxy=$(adb shell "settings get global http_proxy" 2>/dev/null | tr -d '\r\n')
    
    if [ "$current_proxy" = "$proxy_setting" ]; then
        print_success "Proxy successfully configured: $current_proxy"
        print_info "The device should now route HTTP traffic through your proxy."
    elif [ "$current_proxy" = "null" ] || [ -z "$current_proxy" ]; then
        print_warning "Proxy setting appears to be null or empty."
        print_info "This might be normal on some Android versions or if no proxy was previously set."
        print_info "Manual verification: Go to Settings -> Wi-Fi -> Your Network -> Proxy to check."
    else
        print_warning "Proxy verification returned unexpected value: '$current_proxy'"
        print_info "Expected: '$proxy_setting'"
        print_info "The proxy may still be working. Please verify manually if needed."
    fi
else
    print_error "Failed to set proxy via ADB command."
    print_info "You may need to set the proxy manually:"
    print_info "Go to Settings -> Network & Internet -> Wi-Fi -> [Your connected network] -> Edit -> Advanced options -> Proxy Manual"
    print_info "Host: $host_ip"
    print_info "Port: $proxy_port"
    read -p "Press Enter when you have configured the proxy settings manually... " -r
fi

print_info "Proxy configuration completed."

# List available packages
print_info "Listing available packages on the device..."
packages=$(adb shell pm list packages | cut -d: -f2)

# Filter packages containing "to-be-replaced-package-name"
theapp_packages=$(echo "$packages" | grep -i "my_package_name_here")

if [ -z "$theapp_packages" ]; then
    print_info "No packages containing 'my_package_name_here' found. Listing all packages instead."
    # List all packages and ask user to select
    package_array=()
    i=1
    while IFS= read -r line; do
        package_array+=("$line")
        echo "$i) $line"
        ((i++))
    done <<< "$packages"
else
    print_info "Found packages containing 'my_package_name_here':"
    package_array=()
    i=1
    while IFS= read -r line; do
        package_array+=("$line")
        echo "$i) $line"
        ((i++))
    done <<< "$theapp_packages"
fi

# Ask user to select a package
read -p "Enter the number of the package you want to target: " package_number

if ! [[ "$package_number" =~ ^[0-9]+$ ]] || [ "$package_number" -lt 1 ] || [ "$package_number" -gt ${#package_array[@]} ]; then
    print_error "Invalid selection. Please enter a number between 1 and ${#package_array[@]}."
fi

selected_package=${package_array[$((package_number-1))]}
print_info "Selected package: $selected_package"

# Store the selected package in global variable for cleanup
SELECTED_PACKAGE="$selected_package"

# Launch the selected app with Frida
print_info "Launching the app with Frida multiple unpinning script..."

# Check if frida CLI command is available
if ! command_exists frida; then
    print_warning "Frida CLI command not found, even though Frida packages are installed."
    print_info "This could be due to PATH issues. Please provide the path to the frida command."
    read -p "Enter the path to the frida command (or press Enter to continue with default): " frida_path
    
    if [ -n "$frida_path" ]; then
        if [ -f "$frida_path" ] && [ -x "$frida_path" ]; then
            FRIDA_CMD="$frida_path"
            print_success "Using provided Frida command: $FRIDA_CMD"
        else
            print_error "The provided path does not exist or is not executable: $frida_path"
        fi
    else
        print_info "Continuing with default 'frida' command. If this fails, run the script again and provide the correct path."
        FRIDA_CMD="frida"
    fi
else
    print_success "Frida CLI command is available."
    FRIDA_CMD="frida"
fi

# Prepare script paths
default_script_option="akabe1/frida-multiple-unpinning"
custom_script_dir="frida_scripts"
custom_script_file="multiple_bypasses.js"
custom_script_path="$custom_script_dir/$custom_script_file"

# Check if custom script directory exists, create it if not
if [ ! -d "$custom_script_dir" ]; then
    print_info "Creating custom script directory: $custom_script_dir"
    mkdir -p "$custom_script_dir"
fi

# Check if custom script exists
if [ ! -f "$custom_script_path" ]; then
    print_warning "Custom bypass script not found at: $custom_script_path"
    print_info "Would you like to create a basic template for the custom script? (y/n)"
    read -p "> " create_script_template
    
    if [[ "$create_script_template" =~ ^[Yy]$ ]]; then
        print_info "Creating basic Frida script template at $custom_script_path"
        
        # Create a simple but effective Frida script template
        cat > "$custom_script_path" << 'EOT'
/*
 * Multiple Security Bypass Script for Android
 * Features:
 * - SSL Pinning Bypass
 * - Root Detection Bypass
 * - Emulator Detection Bypass
 * - Anti-Debug Bypass
 * - Anti-Frida Detection Bypass
 */

console.log("[+] Multiple security bypasses loaded");

// Wait for Java to be available
setTimeout(function() {
    Java.perform(function() {
        console.log("[+] Java environment initialized");
        
        // SSL Pinning Bypass
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            // TrustManager implementation
            var TrustManager = Java.registerClass({
                name: 'com.custom.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            // Create new TrustManager
            var TrustManagers = [TrustManager.$new()];
            
            // Override SSLContext
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            );
            
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log("[+] Bypassing SSL Pinning via SSLContext");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            
            // OkHttp3 CertificatePinner bypass
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
                    console.log("[+] OkHttp3 CertificatePinner bypass");
                    return;
                };
            } catch(err) {
                console.log("[-] OkHttp3 CertificatePinner not found");
            }
            
            console.log("[+] SSL Pinning should be bypassed now");
        } catch(err) {
            console.log("[-] Error in SSL Pinning bypass: " + err);
        }
        
        // Root Detection Bypass
        try {
            // Common root detection methods
            var RootPackages = [
                "com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
                "com.topjohnwu.magisk"
            ];
            
            // Hook File.exists
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                if (fileName.indexOf("su") != -1 || fileName.indexOf("magisk") != -1) {
                    console.log("[+] Root detection bypass: " + fileName);
                    return false;
                }
                return this.exists.call(this);
            };
            
            // Hook Build.TAGS
            var Build = Java.use("android.os.Build");
            Build.TAGS.value = "release-keys";
            
            console.log("[+] Root detection should be bypassed now");
        } catch(err) {
            console.log("[-] Error in Root Detection bypass: " + err);
        }
        
        // Emulator Detection Bypass
        try {
            var Build = Java.use("android.os.Build");
            Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
            Build.MODEL.value = "Pixel 2";
            Build.MANUFACTURER.value = "Google";
            
            console.log("[+] Emulator detection should be bypassed now");
        } catch(err) {
            console.log("[-] Error in Emulator Detection bypass: " + err);
        }
        
        // Anti-Debug Bypass
        try {
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                console.log("[+] Debugger detection bypass");
                return false;
            };
            
            console.log("[+] Anti-debug should be bypassed now");
        } catch(err) {
            console.log("[-] Error in Anti-Debug bypass: " + err);
        }
        
        // Anti-Frida Detection Bypass
        try {
            // Hook Runtime.exec to prevent detecting Frida
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                if (cmd.indexOf("frida") !== -1 || cmd.indexOf("fridump") !== -1) {
                    console.log("[+] Anti-Frida detection bypass: " + cmd);
                    return this.exec.call(this, "echo not_found");
                }
                return this.exec.call(this, cmd);
            };
            
            console.log("[+] Anti-Frida detection should be bypassed now");
        } catch(err) {
            console.log("[-] Error in Anti-Frida Detection bypass: " + err);
        }
        
        console.log("[+] All security bypasses completed");
    });
}, 0);
EOT
        
        if [ -f "$custom_script_path" ]; then
            print_success "Template script created successfully!"
        else
            print_error "Failed to create template script. Please check permissions and try again."
        fi
    else
        print_warning "Proceeding without custom script. Will use codeshare script instead."
    fi
fi

    echo ""
    echo "Select frida script to launch:"
    echo "1) Use default Frida codeshare (simple SSL bypass)"
    echo "2) Use local script (bypass SSL, root, emulator, frida detection, debugging enabled etc.)"
    read -p "Enter choice (1 or 2): " bypass_choice

    # Verify app installation first
    print_info "Verifying app installation..."
    package_exists=$(adb shell pm list packages | grep -F "$selected_package")
    if [ -z "$package_exists" ]; then
        print_error "Package '$selected_package' not found on the device. Please check the package name."
        exit 1
    fi
    print_success "App '$selected_package' is installed on the device."

    # Check if the app is already running
    print_info "Checking if the app is already running..."
    running_process=$(adb shell "ps -ef | grep $selected_package | grep -v grep" 2>/dev/null)
    
    if [ -n "$running_process" ]; then
        print_info "App is already running. Will use attach mode (-n)."
        attach_mode=true
    else
        print_info "App is not running. Will use spawn mode (-f)."
        attach_mode=false
    fi

    # Configure script based on user choice
    if [ "$bypass_choice" = "1" ]; then
        print_info "Using default codeshare SSL unpinning script..."
        script_option="--codeshare $default_script_option"
        script_name="Default SSL Unpinning Script"
    elif [ "$bypass_choice" = "2" ]; then
        # Check if custom script exists and is readable
        if [ ! -f "$custom_script_path" ]; then
            print_error "Custom bypass script not found at: $custom_script_path"
            exit 1
        fi
        if [ ! -r "$custom_script_path" ]; then
            print_error "Custom bypass script is not readable: $custom_script_path"
            exit 1
        fi

        print_info "Using local multiple bypass script..."
        script_option="-l \"$custom_script_path\""
        script_name="Custom Multiple Bypass Script"
    else
        print_error "Invalid choice. Aborting."
        exit 1
    fi

    # Build the proper Frida command based on mode
    if [ "$attach_mode" = "true" ]; then
        # App is running - use attach mode
        frida_cmd="$FRIDA_CMD -U -n \"$selected_package\" $script_option"
    else
        # App is not running - use spawn mode with no pause
        frida_cmd="$FRIDA_CMD -U -f \"$selected_package\" $script_option"
        
        # Try to launch the app first to verify it can be started
        print_info "Verifying app can be launched..."
        launch_test=$(adb shell "monkey -p $selected_package -c android.intent.category.LAUNCHER 1" 2>&1)
        
        if echo "$launch_test" | grep -i "error\|failed\|not found" > /dev/null; then
            print_error "Failed to launch app: $selected_package. Error: $launch_test"
            exit 1
        fi
        
        print_info "App launch verification successful."
        
        # Kill the app so Frida can spawn it cleanly
        print_info "Stopping app to prepare for Frida spawning..."
        adb shell "am force-stop $selected_package" > /dev/null 2>&1
        
        # Give it a moment to fully stop
        sleep 3
        
        # Verify app is stopped
        if adb shell "ps -ef | grep $selected_package | grep -v grep" > /dev/null 2>&1; then
            print_warning "App may still be running. Trying to force-stop again..."
            adb shell "am force-stop $selected_package" > /dev/null 2>&1
            sleep 2
        fi
    fi
    
    print_info "Executing: $frida_cmd"
    
    # Show a divider before Frida output
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}[FRIDA OUTPUT START]${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────────${NC}"
    
    # Run Frida with the constructed command
    eval $frida_cmd
    frida_exit_code=$?
    
    # Show a divider after Frida output
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}[FRIDA OUTPUT END]${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────────${NC}"

    if [ $frida_exit_code -eq 0 ]; then
        print_success "Frida launched successfully with $script_name!"
    else
        print_error "Failed to launch Frida using $script_name. Error code: $frida_exit_code"
        print_info "Performing diagnostics to identify the issue..."
        
        # Check if Frida server is running
        print_info "Checking Frida server status..."
        frida_server_running=$(adb shell "ps -ef | grep frida-server | grep -v grep" 2>/dev/null)
        
        if [ -z "$frida_server_running" ]; then
            print_error "Frida server is not running on the device! Attempting to restart it..."
            adb shell "su -c '/data/local/tmp/frida-server &'" > /dev/null 2>&1
            
            # Wait a moment and check again
            sleep 3
            frida_server_running=$(adb shell "ps -ef | grep frida-server | grep -v grep" 2>/dev/null)
            
            if [ -z "$frida_server_running" ]; then
                print_error "Failed to restart Frida server. Try running it manually:"
                print_info "adb shell \"su -c '/data/local/tmp/frida-server &'\""
            else
                print_success "Frida server restarted successfully. Try running the script again."
            fi
        else
            print_info "Frida server is running on the device."
            
            # Check if app is installed again
            package_exists=$(adb shell pm list packages | grep -F "$selected_package")
            if [ -z "$package_exists" ]; then
                print_error "The package '$selected_package' could not be found on the device."
                print_info "Verify the package name with: adb shell pm list packages | grep <keyword>"
            else
                # Check if script exists and is valid
                if [ "$bypass_choice" = "2" ]; then
                    if [ ! -s "$custom_script_path" ]; then
                        print_error "The custom script is empty. Please check the script content."
                    else
                        print_info "The issue may be related to script compatibility or app protections."
                        print_info "Try the following:"
                        print_info "1. Use the default codeshare script instead"
                        print_info "2. Check if the app has anti-Frida protection"
                        print_info "3. Try running the app manually first, then attach with Frida"
                    fi
                else
                    print_info "The issue may be related to codeshare script or app protections."
                    print_info "Try using the custom script instead, or check if the app has anti-Frida protection."
                fi
            fi
        fi
        
        # Additional diagnostic information
        print_info "Device connection status:"
        adb devices | grep -v "List" | grep "device$"
        
        print_info "App process status:"
        adb shell "ps -ef | grep $selected_package | grep -v grep" 2>/dev/null
    fi

# Clean up
rm -rf "$temp_dir"
