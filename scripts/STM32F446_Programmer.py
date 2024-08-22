import serial
import struct
import os
import sys
import glob
import time

# Constants for some statuses
FLASH_OK = 0x00
FLASH_ERROR = 0x01
FLASH_BUSY = 0x02
FLASH_TIMEOUT = 0x03
FLASH_INV_ADDR = 0x04
COMMAND_PROCESS_SUCCESS = 0 
COMMAND_PROCESS_FAIL = -1 

# Bootloader Commands
COMMANDS = {
    "BL_GET_VER": 0x51,
    "BL_GET_HELP": 0x52,
    "BL_GET_CID": 0x53,
    "BL_GET_RDP_STATUS": 0x54,
    "BL_READ_MEM_ADDR": 0x55,
    "BL_FLASH_ERASE": 0x56,
    "BL_FIRMWARE_UPDATE": 0x57,
    "BL_EN_R_W_PROTECT": 0x58,
    "BL_READ_SECTOR_P_STATUS": 0x5A,
    "BL_DIS_R_W_PROTECT": 0x5C,
    "BL_FIRMWARE_UPDATE_FINISH": 0x5E
}

# Length of commands
COMMAND_LENGTHS = {
    "BL_GET_VER": 6,
    "BL_GET_HELP": 6,
    "BL_GET_CID": 6,
    "BL_GET_RDP_STATUS": 6,
    "BL_READ_MEM_ADDR": 11,
    "BL_FLASH_ERASE": 8,
    "BL_FIRMWARE_UPDATE": 11,
    "BL_EN_R_W_PROTECT": 8,
    "BL_READ_SECTOR_P_STATUS": 6,
    "BL_DIS_R_W_PROTECT": 6,
    "BL_FIRMWARE_UPDATE_FINISH": 10
}



verbose_mode = 1
firmware_update_active = 0


# ----------------------------- File Operations ----------------------------------------

def calc_file_len(file_path="user_app.bin"):
    return os.path.getsize(file_path)


def open_file(file_path="user_app.bin"):
    return open(file_path, 'rb')


# ----------------------------- Utilities ----------------------------------------

def word_to_byte(addr, index):
    return (addr >> (8 * (index - 1))) & 0x000000FF


def get_crc(buff, length):
    crc = 0xFFFFFFFF
    for data in buff[:length]:
        crc ^= data
        for _ in range(32):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc <<= 1
    return crc & 0xFFFFFFFF


# ----------------------------- Serial Port ----------------------------------------

def list_serial_ports():
    if sys.platform.startswith('win'):
        ports = [f'COM{i + 1}' for i in range(256)]
    elif sys.platform.startswith(('linux', 'cygwin', 'darwin')):
        ports = glob.glob('/dev/tty[A-Za-z]*')
    else:
        raise EnvironmentError('Unsupported platform')
    return [port for port in ports if is_port_available(port)]


def is_port_available(port):
    try:
        s = serial.Serial(port)
        s.close()
        return True
    except (OSError, serial.SerialException):
        return False


def configure_serial_port(port):
    global ser
    try:
        ser = serial.Serial(port, 115200, timeout=2)
        if ser.is_open:
            print("\n   Port Open Success")
            return 0
    except:
        print("\n   Oops! That was not a valid port")
        available_ports = list_serial_ports()
        if not available_ports:
            print("\n   No ports Detected")
        else:
            print("\n   Available ports:", available_ports)
        return -1
    print("\n   Port Open Failed")
    return -1


def read_serial_port(length):
    return ser.read(length)


def write_to_serial_port(data):
    if verbose_mode:
        print(f"   0x{data:02x}", end=' ')
    if firmware_update_active and not verbose_mode:
        print("#", end=' ')
    ser.write(struct.pack('>B', data))


def purge_serial_port():
    ser.reset_input_buffer()


def close_serial_port():
    ser.close()


# ----------------------------- Command Processing ----------------------------------------

def process_command(command_name, length):
    processors = {
        "BL_GET_VER": process_get_ver,
        "BL_GET_HELP": process_get_help,
        "BL_GET_CID": process_get_cid,
        "BL_GET_RDP_STATUS": process_get_rdp_status,
        "BL_READ_MEM_ADDR": process_read_mem_addr,
        "BL_FLASH_ERASE": process_flash_erase,
        "BL_FIRMWARE_UPDATE": process_firmware_update,
        "BL_EN_R_W_PROTECT": process_en_rw_protect,
        "BL_DIS_R_W_PROTECT": process_dis_rw_protect,
        "BL_READ_SECTOR_P_STATUS": process_read_sector_status,
        "BL_FIRMWARE_UPDATE_FINISH": process_firmware_update_finish
    }
    processor = processors.get(command_name)
    if processor:
       return processor(length)


def process_get_ver(length):
    version = read_serial_port(length)
    print("\n   Bootloader Ver.:", version)
    return COMMAND_PROCESS_SUCCESS


def process_get_help(length):
    value = bytearray(read_serial_port(length))
    print("\n   Supported Commands: \n")
    
    command_lookup = {v: k for k, v in COMMANDS.items()}
    for x in value:
        command_name = command_lookup.get(x, "UNKNOWN_COMMAND")
        print(f"   {command_name}: {hex(x)}")
    
    return COMMAND_PROCESS_SUCCESS


def process_get_cid(length):
    value = read_serial_port(length)
    chip_id = (value[1] << 8) + value[0]
    print("\n   Chip Id.:", hex(chip_id))
    return COMMAND_PROCESS_SUCCESS


def process_get_rdp_status(length):
    status = bytearray(read_serial_port(length))
    print("\n   RDP Status:", hex(status[0]))
    return COMMAND_PROCESS_SUCCESS


def process_read_mem_addr(length):
    data = bytearray(read_serial_port(length))
    if data[0] != COMMAND_PROCESS_SUCCESS: 
        print("\n   Error: Imvalid memory address")
        return COMMAND_PROCESS_FAIL
    else:
        print("\n   Extracted Memory Addresses:")
        for i in range(1, len(data), 4):
            chunk = data[i:i+4]
            hex_value = '0x' + chunk[::-1].hex().upper()  
            print(f"  - {hex_value}")
        
        return COMMAND_PROCESS_SUCCESS


def process_flash_erase(length):
    status = bytearray(read_serial_port(length))
    if len(status):
        status_code = {
            FLASH_OK: "Success  Code: FLASH_OK",
            FLASH_ERROR: "Fail  Code: FLASH_ERROR",
            FLASH_BUSY: "Fail  Code: FLASH_BUSY",
            FLASH_TIMEOUT: "Fail  Code: FLASH_TIMEOUT",
            FLASH_INV_ADDR: "Fail  Code: FLASH_INV_SECTOR"
        }
        print("\n   Erase Status:", status_code.get(status[0], "Fail  Code: UNKNOWN_ERROR_CODE"))
        if status[0] == FLASH_OK:
            return COMMAND_PROCESS_SUCCESS
        else:
            return COMMAND_PROCESS_FAIL
    else:
        print("Timeout: Bootloader is not responding")
        return COMMAND_PROCESS_FAIL


def process_firmware_update(length):
    status = bytearray(read_serial_port(length))
    status_code = {
        FLASH_OK: "FLASH_OK",
        FLASH_ERROR: "FLASH_ERROR",
        FLASH_BUSY: "FLASH_BUSY",
        FLASH_TIMEOUT: "FLASH_TIMEOUT",
        FLASH_INV_ADDR: "FLASH_INV_ADDR"
    }
    print("\n   Write Status:", status_code.get(status[0], "UNKNOWN_ERROR"))
    if status[0] == FLASH_OK:
        return COMMAND_PROCESS_SUCCESS
    else:
        return COMMAND_PROCESS_FAIL


def process_read_sector_status(length):
    status = bytearray(read_serial_port(length))
    print("\n   Sector Status:", status[0])
    print("\n  ====================================")
    print("  Sector                               Protection")
    print("  ====================================")
    protection_mode = "Read/Write Protection(PCROP)" if status[0] & (1 << 15) else "Write Protection"
    print(f"\n  Flash protection mode: {protection_mode}\n")
    for x in range(8):
        print(f"\n   Sector{x}                               {protection_type(status[0], x)}")
    return COMMAND_PROCESS_SUCCESS


def process_en_rw_protect(length):
    status = bytearray(read_serial_port(length))
    return status[0]

def process_dis_rw_protect(length):
    status = bytearray(read_serial_port(length))
    return status[0]

def process_firmware_update_finish(length):
    status = bytearray(read_serial_port(length))
    return status[0]
   


def protection_type(status, n):
    protection_modes = ["Write Protection", "Read/Write Protection", "No protection"]
    if status & (1 << 15):  # PCROP is active
        return protection_modes[1] if status & (1 << n) else protection_modes[2]
    return protection_modes[2] if status & (1 << n) else protection_modes[0]


def execute_command(command_name):
    command_len = COMMAND_LENGTHS.get(command_name)
    command_code = COMMANDS.get(command_name)
    if command_len and command_code is not None:
        data_buf = create_command_buffer(command_name)
        send_command(data_buf)
        read_bootloader_reply(command_name)
    else:
        print("\n   Invalid command code\n")
        return 


def create_command_buffer(command_name):
    command_len = COMMAND_LENGTHS[command_name]
    command_code = COMMANDS[command_name]
    data_buf = [0] * command_len
    data_buf[0] = command_len - 1
    data_buf[1] = command_code
    cmd_payload_index = 2
    crc_index = command_len - 4

    if command_name == "BL_READ_MEM_ADDR":
        base_address  = input("\n   Please enter 4 bytes base address in hex:")
        base_address = int(base_address, 16)
        base_address_bytes = base_address.to_bytes(4, 'little')
        data_buf[cmd_payload_index:6] = base_address_bytes
        data_len  = int(input("\n   Please enter the number of memory addresses to read:"))
        data_buf[6] = data_len
  
    elif command_name == "BL_FLASH_ERASE":
        start_sector_num = input("\n   Enter start sector number(0-7 OR 0xFF for Mass Flash Erasing) here :")
        start_sector_num = int(start_sector_num, 16)
        if start_sector_num != 0xff:
            num_of_sectors=int(input("\n  Enter number of sectors to be erased here :"))
            if (start_sector_num + num_of_sectors) > 8:
              print(f"\n  Invalid number of sectors. The last sector cannot exceed 7. "
              f"Starting from sector {start_sector_num}, the last sector would be {start_sector_num + num_of_sectors}.")
        else:
            num_of_sectors = 0
        data_buf[2]= start_sector_num 
        data_buf[3]= num_of_sectors 

    elif command_name == "BL_EN_R_W_PROTECT":
        total_sector = int(input("\n   How many sectors do you want to protect ?: "))
        sectors = [0] * 8
        selected_sectors=0
        for sector_index in range(total_sector):
            sector_number = int(input("\nEnter sector number[{0}]: ".format(sector_index + 1)))
            if sector_number < 0 or sector_number >= 8:
                print("Error: Sector number must be between 0 and 7.")
            else:
                sectors[sector_index] = sector_number
                selected_sectors |= (1 << sector_number)  

        print("\n   Mode:Flash sectors No Protection: 0")
        print("\n   Mode:Flash sectors Write Protection: 1")
        print("\n   Mode:Flash sectors Read/Write Protection: 2")
        prtoection_mode = int(input("\n   Enter Sector Protection Mode(0 or 1 or 2 ):"))

        if prtoection_mode > 2:
            print("\n   Invalid option : Command Dropped")
            return
        data_buf[2] = selected_sectors 
        data_buf[3] = prtoection_mode 

    elif command_name == "BL_FIRMWARE_UPDATE":
        bytes_remaining=0
        t_len_of_file=0
        bytes_so_far_sent = 0
        len_to_read=0
        base_mem_address=0
        firmware_data_index = 7
      
        #First get the total number of bytes in the .bin file.
        t_len_of_file =calc_file_len()

        #keep opening the file
        bin_file = open_file()

        bytes_remaining = t_len_of_file - bytes_so_far_sent

        base_mem_address = input("\n   Enter the memory write address here :")
        base_mem_address = int(base_mem_address, 16)
        start_app_address = base_mem_address
        data = [0] * 255
    
        data[1] = COMMANDS["BL_FIRMWARE_UPDATE"]
   
        global firmware_update_active
        while bytes_remaining:
            firmware_update_active = 1
            
            # Determine the number of bytes to read
            len_to_read = min(128, bytes_remaining)

            # Read the bytes from the file into the data buffer
            for file_byte_index in range(len_to_read):
                file_read_value = bin_file.read(1)
                if not file_read_value:
                    print("Error: Unexpected end of file.")
                    return
                data[firmware_data_index + file_byte_index] = file_read_value[0]  # directly using the byte value
            
            # Populate base memory address in the data buffer
            for index in range(4):
                data[cmd_payload_index + index] = word_to_byte(base_mem_address, index + 1)

            data[6] = len_to_read

            # Calculate total length and CRC
            firmware_update_cmd_total_len = COMMAND_LENGTHS["BL_FIRMWARE_UPDATE"] + len_to_read
            data[0] = firmware_update_cmd_total_len - 1
            crc32 = get_crc(data, firmware_update_cmd_total_len - 4)
            
            for index in range(4):
                data[firmware_data_index + len_to_read + index] = word_to_byte(crc32, index + 1)

            # Update the base memory address for the next iteration
            base_mem_address += len_to_read

            # Send the command
            send_command(data)

            # Read the bootloader reply
            ret_val = read_bootloader_reply("BL_FIRMWARE_UPDATE")
            if ret_val == COMMAND_PROCESS_FAIL:
                print("\n   Firmware update failed, please try again \n")
                return

            # Update bytes counters
            bytes_so_far_sent += len_to_read
            bytes_remaining = t_len_of_file - bytes_so_far_sent
            print(f"\n   bytes_so_far_sent: {bytes_so_far_sent} -- bytes_remaining: {bytes_remaining}\n")
            time.sleep(1)

        firmware_update_active = 0
        bin_file.close()

        print("\n   Firmwae Update Finished")
        command_len = COMMAND_LENGTHS["BL_FIRMWARE_UPDATE_FINISH"]
        data_buf[0] = command_len - 1 
        data_buf[1] = COMMANDS["BL_FIRMWARE_UPDATE_FINISH"] 
        start_app_address = start_app_address.to_bytes(4, 'little')
        data_buf[cmd_payload_index:crc_index] = start_app_address
        crc_index = command_len - 4

    crc32 = get_crc(data_buf, crc_index)
    crc32_bytes = crc32.to_bytes(4, 'little')
    data_buf[crc_index:command_len] = crc32_bytes

   
    return data_buf


def send_command(data_buf):
    write_to_serial_port(data_buf[0])
    for byte in data_buf[1:]:
        write_to_serial_port(byte)


def read_bootloader_reply(command_name):
    ack = read_serial_port(2)
    if len(ack):
        if ack[0] == 0xA5:  # ACK
            len_to_follow = ack[1]
            print("\n   CRC : SUCCESS Len:", len_to_follow)
            ret_val = process_command(command_name, len_to_follow)
            if ret_val == COMMAND_PROCESS_SUCCESS:
                print("\n   Command processed successfully! \n") 
            else:
                print("\n  Command process failed \n")
            return ret_val
        elif ack[0] == 0x7F:  # NACK
            print("\n   CRC: FAIL\n")
            return COMMAND_PROCESS_FAIL
    else:
        print("\n   Timeout : Bootloader not responding, please restart the board, and enter bootloader mode")
        return COMMAND_PROCESS_FAIL

def print_menu():
    print("\n +==========================================+")
    print(" |               Menu                       |")
    print(" |         STM32F446 BootLoader             |")
    print(" +==========================================+")

  
    
    print("\n   Which BL command do you want to send ??\n")
    print("   BL_GET_VER                            --> 1")
    print("   BL_GET_HLP                            --> 2")
    print("   BL_GET_CID                            --> 3")
    print("   BL_GET_RDP_STATUS                     --> 4")
    print("   BL_READ_MEM_ADDR                      --> 5")
    print("   BL_FLASH_ERASE                        --> 6")
    print("   BL_FIRMWARE_UPDATE                    --> 7")
    print("   BL_EN_R_W_PROTECT                     --> 8")
    print("   BL_READ_SECTOR_P_STATUS               --> 9")
    print("   BL_DIS_R_W_PROTECT                    --> 10")
    print("   MENU_EXIT                             --> 0")
# ----------------------------- Menu ----------------------------------------


def main():

    port_name = input("Enter the Port Name of your device (Ex: COM3):")
    if configure_serial_port(port_name) < 0:
        return

    command_mapping = {
        1: "BL_GET_VER",
        2: "BL_GET_HELP",
        3: "BL_GET_CID",
        4: "BL_GET_RDP_STATUS",
        5: "BL_READ_MEM_ADDR",
        6: "BL_FLASH_ERASE",
        7: "BL_FIRMWARE_UPDATE",
        8: "BL_EN_R_W_PROTECT",
        9: "BL_READ_SECTOR_P_STATUS",
        10: "BL_DIS_R_W_PROTECT"
    }

    while True:
        print_menu()
        command_code = input("\n   Type the command code here :")
        if command_code.isdigit():
            command_code = int(command_code)
            if command_code == 0:
                print("Exiting...")
                break
            command_name = command_mapping.get(command_code)
            if command_name:
                execute_command(command_name)
            else:
                print("\n   Invalid command code.")
        else:
            print("\n   Please Input a valid code shown above")

        input("\n   Press any key to continue  :")
        purge_serial_port()

if __name__ == "__main__":
    main()
