#ifndef __BOOTLOADER_H
#define __BOOTLOADER_H

#include "stm32f4xx_hal.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* External variables declaration */
extern uint32_t _estack;       /**< External stack pointer for the MCU */
extern CRC_HandleTypeDef hcrc; /**< External CRC handler for CRC operations */
extern UART_HandleTypeDef
    huart2; /**< External UART handler for UART2 communication */
extern UART_HandleTypeDef
    huart3; /**< External UART handler for UART3 communication */

/* Bootloader version */
#define BL_VERSION "1.0.0" /**< Bootloader version string */
#define BL_VERSION_LEN 5   /**< Length of the bootloader version string */

/* Chip identification mask */
#define CHIP_ID_MASK 0x0FFF /**< Mask for extracting chip identification */

/* UART settings */
#define BL_UART_REFERENCE                                                      \
  &huart2 /**< UART reference for bootloader communication */
#define BL_UART_BUFFER_LEN 200 /**< Buffer length for UART communication */

/* Debug UART settings */
#define DEBUG_UART_REFERENCE &huart3 /**< UART reference for debugging */

/* Application related constants */
#define NO_APP_AVAILABLE                                                       \
  0xFFFFFFFF /**< Indicator for no application available */
#define APP_BASE_ADDRESS                                                       \
  0x08004000                /**< Base address of the application in flash */
#define APP_MSP_OFFSET 0x0U /**< Offset to the Main Stack Pointer (MSP) */
#define APP_RESET_HANDLER_OFFSET 0x4U /**< Offset to the Reset Handler */

/* Flash and memory settings */
#define DATA_IS_ERASED 0xFFFFFFFF /**< Value indicating that data is erased */
#define FLASH_ERASE_REPLY_LEN 1   /**< Length of the flash erase reply */
#define INVALID_SECTOR 0x04       /**< Code for invalid sector */
#define MASS_ERASE_CODE 0xFF      /**< Code for mass erase */
#define MAX_NUM_OF_SECTOR 0x8     /**< Maximum number of sectors */
#define MAX_SECTOR_NUM (MAX_NUM_OF_SECTOR - 1) /**< Maximum sector number */
#define START_SECTOR_NUM_MASK 0xFF /**< Mask for start sector number */
#define NUM_OF_SECTORS_MASK 0xFF00 /**< Mask for number of sectors */

/* Read/Write protection settings */
#define RW_PROTECTION_REPLY_LEN                                                \
  1 /**< Length of the read/write protection reply */
#define SECTORS_DETAILS_MASK 0xFF   /**< Mask for sector details */
#define PROTECTION_TYPE_MASK 0xFF00 /**< Mask for protection type */
#define FLASH_OPTCR_nWRP_SET                                                   \
  0xFF /**< Flash option register value for no write protection */
#define NO_PROTECTION 0x0         /**< Code for no protection */
#define WRITE_PROTECTION 0x1      /**< Code for write protection */
#define READ_WRITE_PROTECTION 0x2 /**< Code for read/write protection */
#define FLASH_DIS_RW_PROTECT                                                   \
  0xFF /**< Code to disable read/write protection                              \
        */

/* Memory write settings */
#define FIRMWARE_UPDATE_REPLY_LEN 1 /**< Length of the memory write reply */
#define MEM_ADDR_MASK 0xFFFFFFFF    /**< Mask for memory address */
#define DATA_LEN_MASK 0xFF00000000  /**< Mask for data length */

/* Memory sizes for STM32F446xx MCU */
#define SRAM1_SIZE (112 * 1024)             /**< Size of SRAM1 (112KB) */
#define SRAM1_END (SRAM1_BASE + SRAM1_SIZE) /**< End address of SRAM1 */
#define SRAM2_SIZE (16 * 1024)              /**< Size of SRAM2 (16KB) */
#define SRAM2_END (SRAM2_BASE + SRAM2_SIZE) /**< End address of SRAM2 */
#define FLASH_SIZE (512 * 1024)             /**< Size of flash memory (512KB) */
#define BKPSRAM_SIZE (4 * 1024)             /**< Size of Backup SRAM (4KB) */
#define BKPSRAM_END                                                            \
  (BKPSRAM_BASE + BKPSRAM_SIZE) /**< End address of Backup SRAM */

/* Command indices and lengths */
#define COMMAND_LEN_INDEX 0 /**< Index for command length in command buffer */
#define COMMAND_CMD_CODE_INDEX                                                 \
  1 /**< Index for command code in command buffer */
#define COMMAND_PAYLOAD_INDEX                                                  \
  2 /**< Index for command payload in command buffer */
#define COMMAND_FIRMWARE_INDEX                                                 \
  7                        /**< Index for firmware version in command buffer */
#define COMMAND_LEN_SIZE 1 /**< Size of the command length field */

/* CRC settings */
#define CRC_DATA_LENGTH 4     /**< Length of CRC data */
#define CRC_SINGLE_WORD_LEN 1 /**< Length of single-word CRC */
#define CRC_VERIFY_SUCCESS 0  /**< CRC verification success code */
#define CRC_VERIFY_FAIL 1     /**< CRC verification failure code */

/* Bootloader acknowledgment codes */
#define BL_ACK_CODE 0xA5    /**< Bootloader acknowledgment code */
#define BL_NACK_CODE 0x7F   /**< Bootloader negative acknowledgment code */
#define BL_ACK_CODE_INDEX 0 /**< Index for acknowledgment code in reply */
#define BL_ACK_LEN_INDEX 1  /**< Index for acknowledgment length in reply */
#define BL_ACK_REPLY_LEN 2  /**< Length of acknowledgment reply */
#define BL_NACK_REPLY_LEN 1 /**< Length of negative acknowledgment reply */

/* Address validation codes */
#define ADDR_VALID 0   /**< Address validation successful */
#define ADDR_INVALID 1 /**< Address validation failed */
#define ADDR_VALID_INVALID_REPLY_LEN                                           \
  1 /**< Length of address validation reply */

/* Number of supported bootloader commands */
#define BL_NUM_OF_CMD 10 /**< Number of supported bootloader commands */

/* Bootloader command codes */
#define BL_GET_VER 0x51     /**< Command code to get bootloader version */
#define BL_GET_HELP 0x52    /**< Command code to get bootloader help */
#define BL_GET_CHIP_ID 0x53 /**< Command code to get chip identification */
#define BL_GET_RDP_STATUS                                                      \
  0x54 /**< Command code to get read-out protection status */
#define BL_READ_MEM_ADDR                                                       \
  0x55                          /**< Command code to jump to specified address \
                                 */
#define BL_FLASH_ERASE 0x56     /**< Command code to erase flash memory */
#define BL_FIRMWARE_UPDATE 0x57 /**< Command code to write to memory */
#define BL_EN_RW_PROTECT                                                       \
  0x58 /**< Command code to enable read/write protection */
#define BL_READ_SECTOR_PROTECT_STATUS                                          \
  0x5A /**< Command code to read sector protection status */
#define BL_DIS_RW_PROTECT                                                      \
  0x5C /**< Command code to disable read/write protection */
#define BL_FIRMWARE_UPDATE_FINISH                                              \
  0x5E /**< Command code to indicate firmware update finished */

/* Private macros */
#define SHIFT_RIGHT_ONE_BYTE(val)                                              \
  ((val) >> 8) /**< Macro to shift value right by one byte */
#define SHIFT_RIGHT_FOUR_BYTE(val)                                             \
  ((val) >> 32) /**< Macro to shift value right by four bytes */

/* Enum for bootloader reply types */
typedef enum {
  BL_GET_VERSION_REPLY = 0, /**< Reply type for version command */
  BL_GET_HELP_REPLY,        /**< Reply type for help command */
  BL_GET_CHIP_ID_REPLY,     /**< Reply type for chip ID command */
  BL_GET_RDP_STATUS_REPLY,  /**< Reply type for RDP status command */
  BL_READ_MEM_ADDR_REPLY,   /**< Reply type for go-to-address command */
  BL_FLASH_ERASE_REPLY,     /**< Reply type for flash erase command */
  BL_FIRMWARE_UPDATE_REPLY, /**< Reply type for memory write command */
  BL_EN_RW_PROTECT_REPLY,   /**< Reply type for enable read/write protection
                               command */
  BL_DIS_RW_PROTECT_REPLY,  /**< Reply type for disable read/write protection
                               command */
  BL_READ_SECTOR_PROTECT_STATUS_REPLY, /**< Reply type for sector protection
                                          status command */
  BL_FIRMWARE_UPDATE_FINISH_REPLY /**< Reply type for firmware updated command
                                   */
} eBl_reply;

/* Enum for memory regions */
typedef enum {
  MEM_REG_INVALID_ADDR = 0, /**< Invalid memory address */
  MEM_REG_FLASH,            /**< Flash memory region */
  MEM_REG_SRAM_1,           /**< SRAM1 memory region */
  MEM_REG_SRAM_2,           /**< SRAM2 memory region */
  MEM_REG_BKP_SRAM          /**< Backup SRAM memory region */
} eMemory_region;

/**
 * @brief Starts the bootloader process.
 */
void bootloader_start();

/**
 * @brief Jumps to the application at the specified address.
 */
void bootloader_jump_to_app();

/**
 * @brief Verifies the received command and sends a reply based on the result.
 * @param rec_cmd Pointer to the received command buffer.
 * @param reply The type of reply to be sent.
 */
void bootloader_verify_and_reply(const uint8_t *const rec_cmd, eBl_reply reply);

/**
 * @brief Verifies the CRC of the received command.
 * @param rec_cmd Pointer to the received command buffer.
 * @param len Length of the command.
 * @param rec_crc Received CRC value to be verified.
 * @return CRC verification result (0 for success, 1 for failure).
 */
uint8_t bootloader_verify_crc(const uint8_t *const rec_cmd, const uint32_t len,
                              const uint32_t rec_crc);

/**
 * @brief Receives a command from the UART.
 * @param rec_cmd Pointer to the buffer where the received command will be
 * stored.
 */
void bootloader_receive_cmd(uint8_t *rec_cmd);

/**
 * @brief Sends a reply over UART.
 * @param data_to_send Pointer to the data to be sent.
 * @param len Length of the data to be sent.
 */
void bootloader_send_reply(uint8_t *data_to_send, const uint8_t len);

/**
 * @brief Sends a debug message over UART.
 * @param data_to_send Pointer to the debug message to be sent.
 * @param len Length of the debug message.
 */
void bootloader_send_debug_msg(uint8_t *data_to_send, const uint8_t len);

/**
 * @brief Sends an acknowledgment (ACK) message.
 * @param reply_len Length of the acknowledgment reply.
 */
void bootlader_send_ack(const uint8_t reply_len);

/**
 * @brief Sends a negative acknowledgment (NACK) message.
 */
void bootlader_send_nack();

/**
 * @brief Sends the bootloader version reply.
 */
void bootloader_send_version_reply();

/**
 * @brief Sends the bootloader help reply.
 */
void bootloader_send_help_reply();

/**
 * @brief Sends the chip identification reply.
 */
void bootloader_send_chip_id_reply();

/**
 * @brief Sends the read-out protection (RDP) status reply.
 */
void bootloader_send_RDP_status_reply();

/**
 * @brief Sends a reply for the read memory address command.
 * @param rec_cmd Pointer to the received command buffer.
 */
void bootloader_read_mem_addr_reply(const uint8_t *const rec_cmd);

/**
 * @brief Verifies if the target address is valid.
 * @param target_addr The address to be verified.
 * @return Address validation result (0 for valid, 1 for invalid).
 */
uint8_t bootloader_verify_addr(const uint32_t target_addr);

/**
 * @brief Sends a reply for the flash erase command.
 * @param rec_cmd Pointer to the received command buffer.
 */
void bootloader_flash_erase_reply(const uint8_t *const rec_cmd);

/**
 * @brief Executes the flash erase operation.
 * @param start_sector_number The starting sector number for the erase
 * operation.
 * @param num_of_sectors The number of sectors to be erased.
 * @return Operation result (0 for success, non-zero for failure).
 */
uint8_t bootloader_execute_flash_erase(const uint8_t start_sector_number,
                                       const uint8_t num_of_sectors);

/**
 * @brief Sends a reply for the firmware update command.
 * @param rec_cmd Pointer to the received command buffer.
 */
void bootloader_firmware_update_reply(const uint8_t *const rec_cmd);

/**
 * @brief Sets the start address for the application.
 * @param app_start_addr The application start address.
 */
void bootloader_set_app_start_addr(const uint32_t app_start_addr);

/**
 * @brief Sends a reply for enabling read/write protection.
 * @param rec_cmd Pointer to the received command buffer.
 */
void bootloader_enable_rw_protection_reply(const uint8_t *const rec_cmd);

/**
 * @brief Sends a reply for disabling read/write protection.
 */
void bootloader_disable_rw_protection_reply();

/**
 * @brief Sends a reply for reading sector protection status.
 */
void bootloader_read_sector_protection_status_reply();

/**
 * @brief Sends a reply for indicating a firmware update finish.
 * @param rec_cmd Pointer to the received command buffer.
 */
void bootloader_firmware_update_finish_reply(const uint8_t *const rec_cmd);

#endif
