#include "bootloader.h"

/**
 * @brief Jump to the application if it is present.
 *
 * This function checks if there is a valid application at the specified
 * base address. If a valid application is found, it sets the main stack pointer
 * (MSP) and jumps to the application's reset handler. If not, it sends a debug
 * message indicating that no firmware is found.
 */
void bootloader_jump_to_app() {

  // Read the application start address from the base address
  const uint32_t app_start_addr = *((volatile uint32_t *)APP_BASE_ADDRESS);

  // Check if the start address is valid (not erased data)
  if (app_start_addr != DATA_IS_ERASED) {

    // Read the main stack pointer value from the application's vector table
    const uint32_t main_stack_ptr =
        *((volatile uint32_t *)(app_start_addr + APP_MSP_OFFSET));

    // Check if the stack pointer matches the end of stack
    if (main_stack_ptr == (uint32_t)&_estack) {

      // Set the main stack pointer
      __set_MSP(main_stack_ptr);

      // Read the application reset handler address and jump to it
      uint32_t app_reset_handler_addr =
          *((volatile uint32_t *)(app_start_addr + APP_RESET_HANDLER_OFFSET));
      void (*app_reset_handler)(void) = (void (*)(void))app_reset_handler_addr;
      app_reset_handler();

    } else {

      // Send a debug message if no valid firmware is found
      uint8_t debug_msg[] =
          "No firmware is found.\r\n Please restart the board, enter the "
          "bootloader, and flash a new firmware \r\n";
      bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    }

  } else {
    // Send a debug message if the application start address is erased
    uint8_t debug_msg[] =
        "No firmware is found.\r\n Please restart the board, enter the "
        "bootloader, and flash a new firmware \r\n";
    bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
  }
}

/**
 * @brief Start the bootloader process.
 *
 * This function continuously waits for commands from the user and handles them
 * accordingly by verifying the command and replying with the appropriate
 * response.
 */
void bootloader_start() {
  while (true) {

    uint8_t rec_cmd[BL_UART_BUFFER_LEN] = {0};
    bootloader_receive_cmd(rec_cmd);
    const uint8_t rec_cmd_code = rec_cmd[COMMAND_CMD_CODE_INDEX];

    // Switch case to handle different bootloader commands
    switch (rec_cmd_code) {
    case BL_GET_VER:
      bootloader_verify_and_reply(rec_cmd, BL_GET_VERSION_REPLY);
      break;

    case BL_GET_HELP:
      bootloader_verify_and_reply(rec_cmd, BL_GET_HELP_REPLY);
      break;

    case BL_GET_CHIP_ID:
      bootloader_verify_and_reply(rec_cmd, BL_GET_CHIP_ID_REPLY);
      break;

    case BL_GET_RDP_STATUS:
      bootloader_verify_and_reply(rec_cmd, BL_GET_RDP_STATUS_REPLY);
      break;

    case BL_READ_MEM_ADDR:
      bootloader_verify_and_reply(rec_cmd, BL_READ_MEM_ADDR_REPLY);
      break;

    case BL_FLASH_ERASE:
      bootloader_verify_and_reply(rec_cmd, BL_FLASH_ERASE_REPLY);
      break;

    case BL_FIRMWARE_UPDATE:
      bootloader_verify_and_reply(rec_cmd, BL_FIRMWARE_UPDATE_REPLY);
      break;

    case BL_EN_RW_PROTECT:
      bootloader_verify_and_reply(rec_cmd, BL_EN_RW_PROTECT_REPLY);
      break;

    case BL_DIS_RW_PROTECT:
      bootloader_verify_and_reply(rec_cmd, BL_DIS_RW_PROTECT_REPLY);
      break;

    case BL_READ_SECTOR_PROTECT_STATUS:
      bootloader_verify_and_reply(rec_cmd, BL_READ_SECTOR_PROTECT_STATUS_REPLY);
      break;

    case BL_FIRMWARE_UPDATE_FINISH:
      bootloader_verify_and_reply(rec_cmd, BL_FIRMWARE_UPDATE_FINISH_REPLY);
      break;

    default: {
      uint8_t debug_msg[] = "Error: Not supported command. \r\n";
      bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    } break;
    }
  }
}

/**
 * @brief Verify the received command's CRC and reply with the corresponding
 * response.
 *
 * @param rec_cmd The received command.
 * @param reply The reply type based on the received command.
 */
void bootloader_verify_and_reply(const uint8_t *const rec_cmd,
                                 eBl_reply reply) {
  const uint8_t command_packet_len = rec_cmd[COMMAND_LEN_INDEX] + 1;
  const uint8_t data_len = command_packet_len - CRC_DATA_LENGTH;

  // Extract received CRC from the command
  const uint32_t rec_crc =
      *((uint32_t *)(rec_cmd + command_packet_len - CRC_DATA_LENGTH));

  // Verify the CRC of the received command
  if (bootloader_verify_crc(rec_cmd, data_len, rec_crc) != CRC_VERIFY_FAIL) {

    // Switch case to handle different reply types
    switch (reply) {
    case BL_GET_VERSION_REPLY:
      bootloader_send_version_reply();
      break;

    case BL_GET_HELP_REPLY:
      bootloader_send_help_reply();
      break;

    case BL_GET_CHIP_ID_REPLY:
      bootloader_send_chip_id_reply();
      break;

    case BL_GET_RDP_STATUS_REPLY:
      bootloader_send_RDP_status_reply();
      break;

    case BL_READ_MEM_ADDR_REPLY:
      bootloader_read_mem_addr_reply(rec_cmd);
      break;

    case BL_FLASH_ERASE_REPLY:
      bootloader_flash_erase_reply(rec_cmd);
      break;

    case BL_FIRMWARE_UPDATE_REPLY:
      bootloader_firmware_update_reply(rec_cmd);
      break;

    case BL_EN_RW_PROTECT_REPLY:
      bootloader_enable_rw_protection_reply(rec_cmd);
      break;

    case BL_DIS_RW_PROTECT_REPLY:
      bootloader_disable_rw_protection_reply();
      break;

    case BL_READ_SECTOR_PROTECT_STATUS_REPLY:
      bootloader_read_sector_protection_status_reply();
      break;

    case BL_FIRMWARE_UPDATE_FINISH_REPLY:
      bootloader_firmware_update_finish_reply(rec_cmd);
      break;

    default: {
      uint8_t debug_msg[] = "Error: Not supported command. \r\n";
      bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    } break;
    }

  } else {
    // Send a debug message if CRC verification fails
    uint8_t debug_msg[] = "Error: CRC check failed. \r\n";
    bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    bootlader_send_nack();
  }
}

/**
 * @brief Verify the CRC of the received command.
 *
 * @param rec_cmd The received command.
 * @param len The length of the data.
 * @param rec_crc The received CRC value.
 * @return uint8_t CRC verification result (success or fail).
 */
uint8_t bootloader_verify_crc(const uint8_t *const rec_cmd, const uint32_t len,
                              const uint32_t rec_crc) {

  uint32_t crc_val = 0xFFFFFFFF;

  for (size_t index = 0; index < len; index++) {
    uint32_t cmd = rec_cmd[index];
    crc_val = HAL_CRC_Accumulate(&hcrc, &cmd, CRC_SINGLE_WORD_LEN);
  }

  __HAL_CRC_DR_RESET(&hcrc);

  // Compare calculated CRC with received CRC
  if (crc_val == rec_crc) {
    return CRC_VERIFY_SUCCESS;
  } else {
    return CRC_VERIFY_FAIL;
  }
}

/**
 * @brief Receive a command from the user via UART.
 *
 * @param rec_cmd The buffer to store the received command.
 */
void bootloader_receive_cmd(uint8_t *rec_cmd) {

  HAL_UART_Receive(BL_UART_REFERENCE, &rec_cmd[COMMAND_LEN_INDEX],
                   COMMAND_LEN_SIZE, HAL_MAX_DELAY);

  HAL_UART_Receive(BL_UART_REFERENCE, &rec_cmd[COMMAND_CMD_CODE_INDEX],
                   rec_cmd[COMMAND_LEN_INDEX], HAL_MAX_DELAY);
}

/**
 * @brief Send a reply to the user via UART.
 *
 * @param data_to_send The data to be sent.
 * @param len The length of the data.
 */
void bootloader_send_reply(uint8_t *data_to_send, const uint8_t len) {

  HAL_UART_Transmit(BL_UART_REFERENCE, data_to_send, len, HAL_MAX_DELAY);
}

/**
 * @brief Send a debug message to the user via UART.
 *
 * @param data_to_send The debug message to be sent.
 * @param len The length of the debug message.
 */
void bootloader_send_debug_msg(uint8_t *data_to_send, const uint8_t len) {
  HAL_UART_Transmit(DEBUG_UART_REFERENCE, data_to_send, len, HAL_MAX_DELAY);
}

/**
 * @brief Send an acknowledgment (ACK) reply to the user.
 *
 * @param reply_len The length of the reply.
 */
void bootlader_send_ack(const uint8_t reply_len) {
  uint8_t ack_reply[BL_ACK_REPLY_LEN] = {0};
  ack_reply[BL_ACK_CODE_INDEX] = BL_ACK_CODE;
  ack_reply[BL_ACK_LEN_INDEX] = reply_len;
  bootloader_send_reply(ack_reply, BL_ACK_REPLY_LEN);
}

/**
 * @brief Send a negative acknowledgment (NACK) reply to the user.
 */
void bootlader_send_nack() {
  uint8_t nack_reply = BL_NACK_CODE;
  bootloader_send_reply(&nack_reply, BL_NACK_REPLY_LEN);
}

/**
 * @brief Send the bootloader version reply to the user.
 */
void bootloader_send_version_reply() {
  const uint8_t reply_len = BL_VERSION_LEN;
  uint8_t bl_ver[BL_VERSION_LEN] = BL_VERSION;
  bootlader_send_ack(reply_len);
  bootloader_send_reply(bl_ver, reply_len);
}

/**
 * @brief Send the supported commands reply to the user.
 */
void bootloader_send_help_reply() {

  uint8_t supported_commands[BL_NUM_OF_CMD] = {
      BL_GET_VER,         BL_GET_HELP,      BL_GET_CHIP_ID,
      BL_GET_RDP_STATUS,  BL_READ_MEM_ADDR, BL_FLASH_ERASE,
      BL_FIRMWARE_UPDATE, BL_EN_RW_PROTECT, BL_READ_SECTOR_PROTECT_STATUS,
      BL_DIS_RW_PROTECT};

  const uint8_t reply_len = BL_NUM_OF_CMD;
  bootlader_send_ack(reply_len);
  bootloader_send_reply(supported_commands, reply_len);
}

/**
 * @brief Send the chip ID reply to the user.
 */
void bootloader_send_chip_id_reply() {
  const uint16_t chip_id = (uint16_t)(DBGMCU->IDCODE & CHIP_ID_MASK);
  const uint8_t reply_len = sizeof(chip_id);
  bootlader_send_ack(reply_len);
  bootloader_send_reply((uint8_t *)&chip_id, reply_len);
}

/**
 * @brief Send the Read Protection (RDP) status reply to the user.
 */
void bootloader_send_RDP_status_reply() {
  FLASH_OBProgramInitTypeDef flash_config = {0};
  HAL_FLASHEx_OBGetConfig(&flash_config);
  uint8_t rdp_status = flash_config.RDPLevel;
  const uint8_t reply_len = sizeof(rdp_status);
  bootlader_send_ack(reply_len);
  bootloader_send_reply(&rdp_status, reply_len);
}

/**
 * @brief Send the memory address read reply to the user.
 *
 * @param rec_cmd The received command containing the address to read.
 */
void bootloader_read_mem_addr_reply(const uint8_t *const rec_cmd) {

  uint64_t cmd_payload = 0;
  memcpy(&cmd_payload, rec_cmd + COMMAND_PAYLOAD_INDEX, sizeof(cmd_payload));
  const uint32_t target_addr = cmd_payload & MEM_ADDR_MASK;
  const uint8_t number_of_mem_addresses =
      SHIFT_RIGHT_FOUR_BYTE(cmd_payload & DATA_LEN_MASK);
  const uint16_t data_len = number_of_mem_addresses * sizeof(void *);

  // Verify if the address is valid
  if (bootloader_verify_addr(target_addr) != MEM_REG_INVALID_ADDR) {

    const uint8_t reply_len = data_len + ADDR_VALID_INVALID_REPLY_LEN;
    uint8_t data[UINT8_MAX] = {0};
    data[0] = ADDR_VALID;
    memcpy(&data[1], (void *)target_addr, data_len);

    bootlader_send_ack(reply_len);
    bootloader_send_reply(data, reply_len);
  } else {

    const uint8_t reply_len = ADDR_VALID_INVALID_REPLY_LEN;
    uint8_t addr_invalid_reply = ADDR_INVALID;
    uint8_t debug_msg[] = " Error: Accessing invalid memory address \r\n";

    bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    bootlader_send_ack(reply_len);
    bootloader_send_reply(&addr_invalid_reply, reply_len);
  }
}

/**
 * @brief Verify if the target address is within a valid memory region.
 *
 * @param target_addr The address to verify.
 * @return uint8_t The memory region type (SRAM1, SRAM2, FLASH, etc.).
 */
uint8_t bootloader_verify_addr(const uint32_t target_addr) {

  if ((target_addr >= SRAM1_BASE) && (target_addr <= SRAM1_END)) {
    return MEM_REG_SRAM_1;
  } else if ((target_addr >= SRAM2_BASE) && (target_addr <= SRAM2_END)) {
    return MEM_REG_SRAM_2;
  } else if ((target_addr >= FLASH_BASE) && (target_addr <= FLASH_END)) {
    return MEM_REG_FLASH;
  } else if ((target_addr >= BKPSRAM_BASE) && (target_addr <= BKPSRAM_END)) {
    return MEM_REG_BKP_SRAM;
  } else {
    return MEM_REG_INVALID_ADDR;
  }
}

/**
 * @brief Send the flash erase reply to the user.
 *
 * @param rec_cmd The received command containing the sector number and number
 * of sectors to erase.
 */
void bootloader_flash_erase_reply(const uint8_t *const rec_cmd) {

  const uint8_t reply_len = FLASH_ERASE_REPLY_LEN;
  uint16_t cmd_payload = 0;

  memcpy(&cmd_payload, rec_cmd + COMMAND_PAYLOAD_INDEX, sizeof(cmd_payload));

  const uint8_t start_sector_number = cmd_payload & START_SECTOR_NUM_MASK;
  const uint8_t num_of_sectors =
      SHIFT_RIGHT_ONE_BYTE(cmd_payload & NUM_OF_SECTORS_MASK);

  uint8_t flash_erase_status =
      bootloader_execute_flash_erase(start_sector_number, num_of_sectors);

  bootlader_send_ack(reply_len);
  bootloader_send_reply(&flash_erase_status, reply_len);
}

/**
 * @brief Execute the flash erase operation.
 *
 * @param start_sector_number The starting sector number to erase.
 * @param num_of_sectors The number of sectors to erase.
 * @return uint8_t The status of the flash erase operation.
 */
uint8_t bootloader_execute_flash_erase(const uint8_t start_sector_number,
                                       const uint8_t num_of_sectors) {

  FLASH_EraseInitTypeDef erase_config = {0};
  uint32_t err_status = 0;
  erase_config.VoltageRange = FLASH_VOLTAGE_RANGE_3;

  const uint8_t last_erased_sector_num =
      start_sector_number + num_of_sectors - 1;

  // Check if it's a mass erase or sector erase operation
  if (start_sector_number == MASS_ERASE_CODE) {
    erase_config.TypeErase = FLASH_TYPEERASE_MASSERASE;

  } else if ((start_sector_number <= MAX_SECTOR_NUM) &&
             (last_erased_sector_num <= MAX_SECTOR_NUM)) {
    erase_config.TypeErase = FLASH_TYPEERASE_SECTORS;
    erase_config.Sector = start_sector_number;
    erase_config.NbSectors = num_of_sectors;
  } else {
    return INVALID_SECTOR;
  }

  HAL_FLASH_Unlock();
  const uint8_t flash_erase_status =
      HAL_FLASHEx_Erase(&erase_config, &err_status);
  HAL_FLASH_Lock();

  return flash_erase_status;
}

/**
 * @brief Send the firmware update reply to the user.
 *
 * @param rec_cmd The received command containing the start memory address and
 * data.
 */
void bootloader_firmware_update_reply(const uint8_t *const rec_cmd) {

  uint64_t cmd_payload = 0;
  memcpy(&cmd_payload, rec_cmd + COMMAND_PAYLOAD_INDEX, sizeof(cmd_payload));
  const uint32_t start_mem_addr = cmd_payload & MEM_ADDR_MASK;
  const uint8_t data_len = SHIFT_RIGHT_FOUR_BYTE(cmd_payload & DATA_LEN_MASK);
  const uint8_t *const payload = &rec_cmd[COMMAND_FIRMWARE_INDEX];
  uint8_t firmware_update_status = HAL_ERROR;
  const uint8_t reply_len = FIRMWARE_UPDATE_REPLY_LEN;

  const uint8_t mem_regiom = bootloader_verify_addr(start_mem_addr);

  // Check if the memory region is flash or SRAM
  if (mem_regiom == MEM_REG_FLASH) {

    HAL_FLASH_Unlock();
    for (size_t index = 0; index < data_len; index++) {
      firmware_update_status = HAL_FLASH_Program(
          FLASH_TYPEPROGRAM_BYTE, start_mem_addr + index, payload[index]);
      if (firmware_update_status == HAL_ERROR) {
        uint8_t debug_msg[] = " Error: Firmware update failed. \r\n";
        bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
        break;
      }
    }
    HAL_FLASH_Lock();

  } else if ((mem_regiom == MEM_REG_SRAM_1) || (mem_regiom == MEM_REG_SRAM_2) ||
             (mem_regiom == MEM_REG_BKP_SRAM)) {

    firmware_update_status = HAL_OK;
    memcpy((void *)start_mem_addr, payload, data_len);

  } else {
    firmware_update_status = HAL_ERROR;
    uint8_t debug_msg[] = " Error: Firmware update failed. \r\n";
    bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
  }

  bootlader_send_ack(reply_len);
  bootloader_send_reply(&firmware_update_status, FIRMWARE_UPDATE_REPLY_LEN);
}

/**
 * @brief Set the application start address in flash memory.
 *
 * @param app_start_addr The start address of the application.
 */
void bootloader_set_app_start_addr(const uint32_t app_start_addr) {

  bootloader_execute_flash_erase(FLASH_SECTOR_1, 1);
  HAL_FLASH_Unlock();
  HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, APP_BASE_ADDRESS, app_start_addr);
  HAL_FLASH_Lock();
}

/**
 * @brief Send the enable read/write protection reply to the user.
 *
 * @param rec_cmd The received command containing the sectors and protection
 * type.
 */
void bootloader_enable_rw_protection_reply(const uint8_t *const rec_cmd) {

  const uint8_t reply_len = RW_PROTECTION_REPLY_LEN;
  uint16_t cmd_payload = 0;

  memcpy(&cmd_payload, rec_cmd + COMMAND_PAYLOAD_INDEX, sizeof(cmd_payload));

  const uint8_t sectors = cmd_payload & SECTORS_DETAILS_MASK;
  const uint8_t protection_type =
      SHIFT_RIGHT_ONE_BYTE(cmd_payload & PROTECTION_TYPE_MASK);

  uint8_t OB_program_status = HAL_OK;

  HAL_FLASH_OB_Unlock();

  // Wait until the FLASH_SR_BSY flag is reset
  while (__HAL_FLASH_GET_FLAG(FLASH_SR_BSY) != RESET) {
    // Busy waiting
  }

  // Apply the selected protection type
  switch (protection_type) {

  case NO_PROTECTION:
    FLASH->OPTCR &= ~(SET << FLASH_OPTCR_SPRMOD_Pos);
    FLASH->OPTCR |= (sectors << FLASH_OPTCR_nWRP_Pos);
    break;

  case WRITE_PROTECTION:
    FLASH->OPTCR &= ~(SET << FLASH_OPTCR_SPRMOD_Pos);
    FLASH->OPTCR &= ~(sectors << FLASH_OPTCR_nWRP_Pos);
    break;

  case READ_WRITE_PROTECTION:
    FLASH->OPTCR |= (SET << FLASH_OPTCR_SPRMOD_Pos);
    FLASH->OPTCR &= ~(FLASH_OPTCR_nWRP_SET << FLASH_OPTCR_nWRP_Pos);
    FLASH->OPTCR |= (sectors << FLASH_OPTCR_nWRP_Pos);
    break;

  default:
    OB_program_status = HAL_ERROR;
    uint8_t debug_msg[] = " Error: Invalid protection type. \r\n";
    bootloader_send_debug_msg(debug_msg, sizeof(debug_msg));
    break;
  }

  FLASH->OPTCR |= (SET << FLASH_OPTCR_OPTSTRT_Pos);

  // Wait until the FLASH_SR_BSY flag is reset
  while (__HAL_FLASH_GET_FLAG(FLASH_SR_BSY) != RESET) {
    // Busy waiting
  }

  HAL_FLASH_OB_Lock();

  bootlader_send_ack(reply_len);
  bootloader_send_reply(&OB_program_status, reply_len);
}

/**
 * @brief Send the disable read/write protection reply to the user.
 */
void bootloader_disable_rw_protection_reply() {

  const uint8_t reply_len = RW_PROTECTION_REPLY_LEN;
  uint8_t OB_program_status = HAL_OK;

  HAL_FLASH_OB_Unlock();

  // Wait until the FLASH_SR_BSY flag is reset
  while (__HAL_FLASH_GET_FLAG(FLASH_SR_BSY) != RESET) {
    // Busy waiting
  }

  FLASH->OPTCR &= ~(SET << FLASH_OPTCR_SPRMOD_Pos);
  FLASH->OPTCR |= (FLASH_DIS_RW_PROTECT << FLASH_OPTCR_nWRP_Pos);
  FLASH->OPTCR |= (SET << FLASH_OPTCR_OPTSTRT_Pos);

  // Wait until the FLASH_SR_BSY flag is reset
  while (__HAL_FLASH_GET_FLAG(FLASH_SR_BSY) != RESET) {
    // Busy waiting
  }

  HAL_FLASH_OB_Lock();

  bootlader_send_ack(reply_len);
  bootloader_send_reply(&OB_program_status, reply_len);
}

/**
 * @brief Send the read sector protection status reply to the user.
 */
void bootloader_read_sector_protection_status_reply() {

  FLASH_OBProgramInitTypeDef OB_config = {0};
  const uint8_t reply_len = 2;
  HAL_FLASH_OB_Unlock();
  HAL_FLASHEx_OBGetConfig(&OB_config);
  HAL_FLASH_OB_Lock();

  const uint16_t sector_protect_status = OB_config.WRPSector;

  bootlader_send_ack(reply_len);
  bootloader_send_reply((uint8_t *)&sector_protect_status,
                        sizeof(sector_protect_status));
}

/**
 * @brief Send the firmware update finish reply to the user and jump to the
 * application.
 *
 * @param rec_cmd The received command containing the start application address.
 */
void bootloader_firmware_update_finish_reply(const uint8_t *const rec_cmd) {

  uint32_t start_app_addr = 0;
  const uint8_t reply_len = FIRMWARE_UPDATE_REPLY_LEN;
  uint8_t firmware_update_finish_status = HAL_OK;

  memcpy(&start_app_addr, rec_cmd + COMMAND_PAYLOAD_INDEX,
         sizeof(start_app_addr));

  bootlader_send_ack(reply_len);
  bootloader_send_reply(&firmware_update_finish_status, reply_len);
  bootloader_set_app_start_addr(start_app_addr);
  bootloader_jump_to_app();
}
