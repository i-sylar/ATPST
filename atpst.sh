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
    echo -e "${YELLOW}Android Testing Platform Setup Tool By @mortaltechnique${NC}"
    echo ""
}

# Global variable to store VM UUID for cleanup
CUSTOM_PHONE_UUID=""

# Setup cleanup trap
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

# Function to cleanup on exit
cleanup() {
    print_info "Performing cleanup..."
    
    # Stop the VM if it's running and we have its UUID
    if [ -n "$CUSTOM_PHONE_UUID" ] && [ -f "$GMTOOL_PATH" ]; then
        VM_STATUS=$("$GMTOOL_PATH" admin list 2>/dev/null | grep -F "$CUSTOM_PHONE_UUID" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
        
        if [ "$VM_STATUS" = "Running" ] || [ "$VM_STATUS" = "On" ]; then
            print_info "Stopping Custom Phone VM..."
            "$GMTOOL_PATH" admin stop "$CUSTOM_PHONE_UUID"
            if [ $? -eq 0 ]; then
                print_success "Custom Phone VM stopped successfully."
            else
                print_warning "Failed to stop Custom Phone VM. You may need to stop it manually."
            fi
        else
            print_info "Custom Phone VM is not running. No need to stop it."
        fi
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

# Function to install CA certificate on the device
install_ca_cert() {
    local cert_path="$1"
    
    if [ ! -f "$cert_path" ]; then
        print_error "Certificate file not found: $cert_path"
        return 1
    fi
    
    print_info "Installing PortSwigger CA certificate on the device..."
    openssl x509 -inform der -in "$cert_path" -out burp.pem
    # Create a readable filename
    #local cert_filename=$(basename "$cert_path")
    local cert_filename=$(basename "burp.pem")
    local device_cert_path="/sdcard/Download/$cert_filename"
    
    # Push certificate to device
    print_info "Copying certificate to device..."
    adb push "$cert_path" "$device_cert_path"
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

# Function to list all available VMs
list_vms() {
    print_info "Listing available Genymotion VMs..."
    
    VM_LIST=$("$GMTOOL_PATH" admin list)
    if [ $? -ne 0 ]; then
        print_error "Failed to list VMs. Please check if Genymotion is running properly."
    fi
    
    echo "$VM_LIST"
}

# Function to check if Custom Phone VM exists and get its UUID
get_custom_phone_vm() {
    print_info "Checking for 'Custom Phone' VM..."
    
    CUSTOM_PHONE_INFO=$("$GMTOOL_PATH" admin list | grep "Custom Phone")
    if [ -z "$CUSTOM_PHONE_INFO" ]; then
        print_error "Custom Phone VM not found. Please install it before continuing."
    fi
    
    # Extract the UUID - it's the third column in the pipe-separated table
    # The format is: State | ADB Serial | UUID | Name
    CUSTOM_PHONE_UUID=$(echo "$CUSTOM_PHONE_INFO" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3}')
    if [ -z "$CUSTOM_PHONE_UUID" ]; then
        print_error "Failed to extract Custom Phone VM UUID."
    fi
    
    print_success "Found Custom Phone VM with UUID: $CUSTOM_PHONE_UUID"
    return 0
}

# Function to wait for ADB connection
wait_for_adb_connection() {
    print_info "Waiting for ADB connection to device (this may take a minute)..."
    
    # Restart ADB server to ensure clean connection state
    print_info "Restarting ADB server..."
    adb kill-server
    sleep 2
    adb start-server
    sleep 3
    
    # Get ADB port from VM info
    ADB_PORT=$(echo "$CUSTOM_PHONE_INFO" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}' | cut -d':' -f2)
    
    if [ -z "$ADB_PORT" ]; then
        print_warning "Could not determine ADB port from VM info. Using default port 6555."
        ADB_PORT="6555"
    fi
    
    # Explicitly connect to the device
    print_info "Connecting to device at 127.0.0.1:$ADB_PORT..."
    adb connect 127.0.0.1:$ADB_PORT
    
    # Wait a moment for the connection to establish
    sleep 3
    
    # Check for ADB availability with timeout
    MAX_ATTEMPTS=30
    ATTEMPT=0
    
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
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
        
        # If no connection yet, try connecting again after a few attempts
        if [ $((ATTEMPT % 5)) -eq 0 ] && [ $ATTEMPT -gt 0 ]; then
            print_info "Retrying connection to 127.0.0.1:$ADB_PORT..."
            adb connect 127.0.0.1:$ADB_PORT
        fi
        
        ATTEMPT=$((ATTEMPT+1))
        print_info "Waiting for ADB connection... ($ATTEMPT/$MAX_ATTEMPTS)"
        sleep 5
    done
    
    print_error "Timed out waiting for ADB connection. Please check the VM and ADB setup manually."
}

# Function to start the Custom Phone VM
start_custom_phone_vm() {
    print_info "Checking VM status..."
    
    # Check if VM is already running - Genymotion might report "Running" or "On"
    VM_STATUS=$("$GMTOOL_PATH" admin list | grep -F "$CUSTOM_PHONE_UUID" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')
    
    # VM is already running
    if [ "$VM_STATUS" = "Running" ] || [ "$VM_STATUS" = "On" ]; then
        print_success "Custom Phone VM is already running."
        # Still need to ensure ADB is connected even if VM is already running
        wait_for_adb_connection
        return 0
    fi
    
    # VM needs to be started
    print_info "Starting Custom Phone VM..."
    START_OUTPUT=$("$GMTOOL_PATH" admin start "$CUSTOM_PHONE_UUID" 2>&1)
    START_RESULT=$?
    
    # Check for both exit code and "already started" message
    if [ $START_RESULT -ne 0 ] && ! echo "$START_OUTPUT" | grep -q "already started"; then
        print_error "Failed to start Custom Phone VM. Please check Genymotion setup."
    elif echo "$START_OUTPUT" | grep -q "already started"; then
        print_success "Custom Phone VM is already running."
        # Still need to ensure ADB is connected even if VM is already started
        wait_for_adb_connection
        return 0
    fi
    
    # VM was just started, wait for it to boot and connect to ADB
    print_info "VM started successfully. Waiting for it to boot..."
    # Initial delay to let VM start booting
    sleep 10
    
    # Wait for ADB connection
    wait_for_adb_connection
}
#display banner
display_banner
sleep 2
# Automated Genymotion VM setup
print_info "Preparing Genymotion environment..."

# Check prerequisites
check_genymotion
check_burpsuite

# We'll check for CA certificate installation after VM is started but before proceeding with the script

# Check and prompt about "Custom Phone" VM
list_vms
print_info "Please make sure you have installed the 'Custom Phone' VM in Genymotion."
read -p "Press Enter once you've verified the 'Custom Phone' VM is installed... " -r

# Get Custom Phone VM details and start it
get_custom_phone_vm
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

# Check if frida-tools is installed and install if necessary
#if ! $PIP_CMD show frida-tools &>/dev/null; then
 #   print_info "Frida-tools not found. Installing via pip..."
  #  $PIP_CMD install frida-tools
    
   # if ! $PIP_CMD show frida-tools &>/dev/null; then
    #    print_error "Failed to install Frida-tools. Please install them manually with '$PIP_CMD install frida-tools'."
    #else
    #    print_success "Frida-tools installed successfully."
    #fi
#else
 #   print_success "Frida-tools are already installed."
#fi

# Check if frida is installed and install if necessary
if ! $PIP_CMD show frida &>/dev/null; then
    print_info "Frida not found. Installing via pip..."
    $PIP_CMD install frida==16.7.19
    
    if ! $PIP_CMD show frida &>/dev/null; then
        print_error "Failed to install Frida. Please install it manually with '$PIP_CMD install frida'."
    else
        print_success "Frida installed successfully."
    fi
else
    print_success "Frida is already installed."
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

# Get the latest Frida version
print_info "Fetching latest Frida version..."
#frida_version=$(curl -s https://api.github.com/repos/frida/frida/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4)
frida_version="16.7.19"
if [ -z "$frida_version" ]; then
    print_error "Failed to fetch latest Frida version. Check your internet connection."
fi
print_success "Latest Frida version: $frida_version"

# Download Frida server
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
else
    print_error "Failed to upload Frida server to the device."
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

# Ask for proxy port
read -p "Enter the proxy port number (default: 8080): " proxy_port
proxy_port=${proxy_port:-8080}

print_info "Please configure your Android device to use the following proxy settings:"
print_info "Host: $host_ip"
print_info "Port: $proxy_port"
print_info "Go to Settings -> Network & Internet -> Wi-Fi -> [Your connected network] -> Edit -> Advanced options -> Proxy Manual"

read -p "Press Enter when you have configured the proxy settings... " -r

# List available packages
print_info "Listing available packages on the device..."
packages=$(adb shell pm list packages | cut -d: -f2)

# Filter packages containing "to-be-replaced-package-name"
theapp_packages=$(echo "$packages" | grep -i "to-be-replaced-package-name")

if [ -z "$theapp_packages" ]; then
    print_info "No packages containing 'to-be-replaced-package-name' found. Listing all packages instead."
    # List all packages and ask user to select
    package_array=()
    i=1
    while IFS= read -r line; do
        package_array+=("$line")
        echo "$i) $line"
        ((i++))
    done <<< "$packages"
else
    print_info "Found packages containing 'to-be-replaced-package-name':"
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

# Launch the app with Frida
print_info "Running Frida with the selected package..."
frida_cmd="$FRIDA_CMD -U -f '$selected_package' --codeshare akabe1/frida-multiple-unpinning"
print_info "Executing: $frida_cmd"

eval $frida_cmd

# Check if Frida command executed successfully
if [ $? -eq 0 ]; then
    print_success "Frida launched successfully! The app should be running with SSL unpinning."
    print_success "Setup completed successfully!"
else
    print_error "Failed to launch Frida. Check if the device is properly connected and Frida server is running."
fi

# Clean up
rm -rf "$temp_dir"
