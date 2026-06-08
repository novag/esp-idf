/*
 * SPDX-FileCopyrightText: 2021-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_openthread_uart.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>

#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_openthread.h"
#include "esp_openthread_common_macro.h"
#include "esp_openthread_platform.h"
#include "esp_openthread_types.h"
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "common/logging.hpp"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "utils/uart.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "driver/usb_serial_jtag.h"
#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
#include <string.h>
#include "esp_attr.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_rom_sys.h"
#include "hal/usb_serial_jtag_ll.h"
#endif

static int s_uart_port;
static int s_uart_fd = -1;
static bool s_uart_driver_installed = false;
static uint8_t s_uart_buffer[ESP_OPENTHREAD_UART_BUFFER_SIZE];
static const char *uart_workflow = "uart";

#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
// ---------------------------------------------------------------------------
// USB-Serial/JTAG link-wedge recovery + diagnostics (related to IDF-14303).
//
// The RCP can keep running yet go deaf+mute over USB (host sees endless spinel
// timeouts, no crash, no reboot) in two distinct ways:
//   1. conn_status latches false: the connection monitor reports disconnected (e.g. a
//      false disconnect from FreeRTOS tick jitter when FREERTOS_HZ==1ms SOF rate, or a
//      real bus event) and the VFS read()/write() are gated off.
//   2. deaf-despite-connected: the USB data path dies while the connection monitor still
//      reads "connected" (conn_status stays TRUE) -- the CONFIRMED real failure, seen
//      both spontaneously after hours and after a simultaneous host+RCP power-on.
//      conn_status gives NO signal for it, so recovery must key on "have I received data".
//
// esp_restart() on the ESP32-C6 is a CPU-only reset (esp_rom_software_reset_cpu) that
// does NOT re-initialize the USB peripheral/PHY, so it cannot recover the link. A full
// system (digital-core) reset via esp_rom_software_reset_system() re-enumerates the
// USB-Serial/JTAG link exactly like an esptool reset, which is the only thing observed
// to recover it. This watchdog forces that reset if the link stays dead, and records
// persistent (RTC-RAM, survives reset) diagnostics so the failure mechanism can be
// confirmed from a later esptool memory/flash read-out.
// ---------------------------------------------------------------------------

// Force a recovery reset after the connection monitor has reported "disconnected"
// continuously for this long (the observed wedge condition)...
#define ESP_OT_RCP_USB_DISCONNECT_TIMEOUT_US   (30LL * 1000 * 1000)
// ...or, as a backstop for any other "deaf" mode, after this long with zero bytes RX.
#define ESP_OT_RCP_USB_RX_SILENCE_TIMEOUT_US   (180LL * 1000 * 1000)

#define ESP_OT_RCP_USB_DIAG_MAGIC 0x4f544442u  // "OTDB"

typedef struct {
    uint32_t magic;
    uint32_t boot_count;        // total boots since power-on (RTC RAM survives reset)
    int32_t  last_reset_reason; // esp_reset_reason() observed at the latest boot
    uint32_t disconnect_events; // usb_serial_jtag_is_connected() true->false transitions
    uint32_t reconnect_events;  // false->true transitions (stays flat if monitor never recovers)
    uint32_t max_disconnect_ms; // longest observed not-connected streak
    uint32_t watchdog_resets;   // times this watchdog forced a recovery reset
    uint32_t last_wedge_kind;   // 1 = sustained-disconnect, 2 = deaf-despite-connected
    // --- USB peripheral forensic snapshot: WHY does the data path die? ---
    uint32_t usb_int_raw_accum;     // OR of USB_SERIAL_JTAG.int_raw across this boot. Sticky bits
                                    // the driver never clears reveal the trigger: bit9 usb_bus_reset,
                                    // bits4-7 pid_err/crc5_err/crc16_err/stuff_err, bit13 dtr_chg.
    uint32_t usb_int_raw_at_wedge;  // int_raw snapshot at the moment the watchdog detects "deaf"
    uint32_t usb_conf0_at_wedge;    // CONF0 at wedge: bit8 pad_pull_override, bit9 dp_pullup, bit0 phy_sel
    uint32_t usb_chip_rst_at_wedge; // chip_rst reg at wedge: bit0 host RTS, bit1 host DTR (port open?)
} esp_ot_rcp_usb_diag_t;

static RTC_NOINIT_ATTR esp_ot_rcp_usb_diag_t s_usb_diag;

static void esp_openthread_rcp_usb_diag_init(void)
{
    if (s_usb_diag.magic != ESP_OT_RCP_USB_DIAG_MAGIC) {
        memset(&s_usb_diag, 0, sizeof(s_usb_diag));
        s_usb_diag.magic = ESP_OT_RCP_USB_DIAG_MAGIC;
    }
    s_usb_diag.boot_count++;
    s_usb_diag.last_reset_reason = (int32_t)esp_reset_reason();
    s_usb_diag.usb_int_raw_accum = 0;  // accumulate fresh per boot session
}

static void esp_openthread_rcp_usb_link_watchdog(bool received_data)
{
    static bool s_initialized = false;
    static bool s_ever_received = false;
    static int64_t s_last_rx_us;
    static int64_t s_disconnected_since_us;
    static bool s_was_connected;

    int64_t now = esp_timer_get_time();
    if (!s_initialized) {
        s_last_rx_us = now;
        s_disconnected_since_us = 0;
        s_was_connected = true;
        s_initialized = true;
    }
    if (received_data) {
        s_last_rx_us = now;
        s_ever_received = true;
    }

    // Accumulate the USB interrupt-raw bits. The driver only ever clears sof / serial_out_recv_pkt /
    // serial_in_empty, so bus_reset, the USB error bits, and dtr/rts changes stay latched here and
    // tell us what happened on the link by the time we read this out after a wedge+reset.
    s_usb_diag.usb_int_raw_accum |= usb_serial_jtag_ll_get_intraw_mask();

    bool connected = usb_serial_jtag_is_connected();
    if (connected != s_was_connected) {
        if (connected) {
            s_usb_diag.reconnect_events++;
        } else {
            s_usb_diag.disconnect_events++;
        }
        s_was_connected = connected;
    }

    if (connected) {
        s_disconnected_since_us = 0;
    } else {
        if (s_disconnected_since_us == 0) {
            s_disconnected_since_us = now;
        }
        uint32_t streak_ms = (uint32_t)((now - s_disconnected_since_us) / 1000);
        if (streak_ms > s_usb_diag.max_disconnect_ms) {
            s_usb_diag.max_disconnect_ms = streak_ms;
        }
    }

    // Deaf-despite-connected: the link reports connected (host SOF is present) but we
    // have received no data for a long time. This is the CONFIRMED real failure -- caught
    // in-band with diagnostics on 2026-06-08 (deaf ~7h; diag showed conn_status healthy
    // the whole time: disconnect_events==reconnect_events, max_disconnect_ms==0,
    // watchdog_resets==0) and identical to the power-on event. The USB data path dies
    // while the connection monitor still reads "connected", so conn_status never goes
    // false and the disconnect path below never triggers. Gating on `connected` (a host
    // is present) keeps a board with no host attached from reset-looping; deliberately
    // NOT gating on s_ever_received so this also recovers a link that came up broken from
    // the very first boot (the power-on variant, where no byte is ever received).
    bool deaf_despite_connected = connected &&
                                  (now - s_last_rx_us > ESP_OT_RCP_USB_RX_SILENCE_TIMEOUT_US);
    // Sustained disconnect: SOF genuinely gone for a long time (conn_status latched
    // false). Gated on s_ever_received so a no-host board cannot reset-loop.
    bool sustained_disconnect = s_ever_received && (s_disconnected_since_us != 0) &&
                                (now - s_disconnected_since_us > ESP_OT_RCP_USB_DISCONNECT_TIMEOUT_US);

    if (deaf_despite_connected || sustained_disconnect) {
        s_usb_diag.watchdog_resets++;
        s_usb_diag.last_wedge_kind = sustained_disconnect ? 1u : 2u;  // 1=disconnect, 2=deaf-despite-connected
        // Forensic snapshot of the USB peripheral at the wedge, so the cause of the data-path
        // death is readable from RTC RAM after the recovery reset.
        s_usb_diag.usb_int_raw_at_wedge = usb_serial_jtag_ll_get_intraw_mask();
        s_usb_diag.usb_conf0_at_wedge = USB_SERIAL_JTAG.conf0.val;
        s_usb_diag.usb_chip_rst_at_wedge = USB_SERIAL_JTAG.chip_rst.val;
        // Full digital-core reset -> clean USB re-enumeration. esp_restart() would be a
        // CPU-only reset on C6 and would leave the wedged USB peripheral untouched.
        esp_rom_software_reset_system();
    }
}
#endif // CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG

#if (CONFIG_OPENTHREAD_CLI || (CONFIG_OPENTHREAD_RADIO && (CONFIG_OPENTHREAD_RCP_UART || CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG)))
otError otPlatUartEnable(void)
{
    return OT_ERROR_NONE;
}

otError otPlatUartDisable(void)
{
    return OT_ERROR_NONE;
}

otError otPlatUartFlush(void)
{
    return OT_ERROR_NONE;
}

otError otPlatUartSend(const uint8_t *buf, uint16_t buf_length)
{
    int rval = write(s_uart_fd, buf, buf_length);

    // DIG-727
#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
    usb_serial_jtag_ll_txfifo_flush();
#endif

    if (rval != (int)buf_length) {
        return OT_ERROR_FAILED;
    }

    otPlatUartSendDone();

    return OT_ERROR_NONE;
}
#endif

esp_err_t esp_openthread_uart_init_port(const esp_openthread_uart_config_t *config)
{
#ifndef CONFIG_ESP_CONSOLE_UART
    // If UART console is used, UART vfs devices should be registered during startup.
    // Otherwise we need to register them here.
    char uart_path[16];
    snprintf(uart_path, sizeof(uart_path), "/dev/uart/%d", config->port);
    bool is_uart_registered = (access(uart_path, F_OK) == 0);
    if (!is_uart_registered) {
        // If UART vfs devices are registered, we will failed to open the directory
        uart_vfs_dev_register();
    }
#endif
    ESP_RETURN_ON_ERROR(uart_param_config(config->port, &config->uart_config), OT_PLAT_LOG_TAG,
                        "uart_param_config failed");
    ESP_RETURN_ON_ERROR(
        uart_set_pin(config->port, config->tx_pin, config->rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE),
        OT_PLAT_LOG_TAG, "uart_set_pin failed");
    ESP_RETURN_ON_ERROR(uart_driver_install(config->port, ESP_OPENTHREAD_UART_BUFFER_SIZE, 0, 0, NULL, 0),
                        OT_PLAT_LOG_TAG, "uart_driver_install failed");
    s_uart_driver_installed = true;
    uart_vfs_dev_use_driver(config->port);
    return ESP_OK;
}

#if CONFIG_OPENTHREAD_CONSOLE_TYPE_USB_SERIAL_JTAG
esp_err_t esp_openthread_host_cli_usb_init(const esp_openthread_platform_config_t *config)
{
    esp_err_t ret = ESP_OK;
    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
    /* Move the caret to the beginning of the next line on '\n' */
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);

    /* Enable non-blocking mode on stdin and stdout */
    fcntl(fileno(stdout), F_SETFL, O_NONBLOCK);
    fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);

    ret = usb_serial_jtag_driver_install((usb_serial_jtag_driver_config_t *)&config->host_config.host_usb_config);
    usb_serial_jtag_vfs_use_driver();
    return ret;
}
#endif

#if CONFIG_OPENTHREAD_CONSOLE_TYPE_UART
esp_err_t esp_openthread_host_cli_uart_init(const esp_openthread_platform_config_t *config)
{
    ESP_RETURN_ON_ERROR(esp_openthread_uart_init_port(&config->host_config.host_uart_config), OT_PLAT_LOG_TAG,
                        "esp_openthread_uart_init_port failed");
    return ESP_OK;
}
#endif

#if CONFIG_OPENTHREAD_RCP_UART
esp_err_t esp_openthread_host_rcp_uart_init(const esp_openthread_platform_config_t *config)
{
    esp_err_t ret = ESP_OK;
    // Install UART driver for interrupt-driven reads and writes.
    char uart_path[16];
    s_uart_port = config->host_config.host_uart_config.port;
    ESP_RETURN_ON_ERROR(esp_openthread_uart_init_port(&config->host_config.host_uart_config), OT_PLAT_LOG_TAG,
                        "esp_openthread_uart_init_port failed");

    uart_vfs_dev_port_set_rx_line_endings(s_uart_port, ESP_LINE_ENDINGS_LF);
    uart_vfs_dev_port_set_tx_line_endings(s_uart_port, ESP_LINE_ENDINGS_LF);
    snprintf(uart_path, sizeof(uart_path), "/dev/uart/%d", s_uart_port);
    s_uart_fd = open(uart_path, O_RDWR | O_NONBLOCK);
    ESP_RETURN_ON_FALSE(s_uart_fd >= 0, ESP_FAIL, OT_PLAT_LOG_TAG, "open uart_path failed");
    ret = esp_openthread_platform_workflow_register(&esp_openthread_uart_update, &esp_openthread_uart_process,
                                                    uart_workflow);

    return ret;
}
#endif

#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
esp_err_t esp_openthread_host_rcp_usb_init(const esp_openthread_platform_config_t *config)
{
    esp_err_t ret = ESP_OK;

    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_LF);
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_LF);

    ESP_ERROR_CHECK(usb_serial_jtag_driver_install((usb_serial_jtag_driver_config_t *)&config->host_config.host_usb_config));
    ESP_ERROR_CHECK(usb_serial_jtag_vfs_register());
    usb_serial_jtag_vfs_use_driver();

    esp_openthread_rcp_usb_diag_init();

    s_uart_fd = open("/dev/usbserjtag", O_RDWR | O_NONBLOCK);
    ESP_RETURN_ON_FALSE(s_uart_fd >= 0, ESP_FAIL, OT_PLAT_LOG_TAG, "open usbserjtag failed");
    ret = esp_openthread_platform_workflow_register(&esp_openthread_uart_update, &esp_openthread_uart_process,
                                                    uart_workflow);

    return ret;
}
#endif

void esp_openthread_uart_deinit()
{
    if (s_uart_fd != -1) {
        close(s_uart_fd);
        s_uart_fd = -1;
    }
    if (s_uart_driver_installed) {
        uart_driver_delete(s_uart_port);
        s_uart_driver_installed = false;
    }
    esp_openthread_platform_workflow_unregister(uart_workflow);
}

void esp_openthread_uart_update(esp_openthread_mainloop_context_t *mainloop)
{
    FD_SET(s_uart_fd, &mainloop->read_fds);
    if (s_uart_fd > mainloop->max_fd) {
        mainloop->max_fd = s_uart_fd;
    }
}

esp_err_t esp_openthread_uart_process(otInstance *instance, const esp_openthread_mainloop_context_t *mainloop)
{
    int rval = read(s_uart_fd, s_uart_buffer, sizeof(s_uart_buffer));

    if (rval > 0) {
#if (CONFIG_OPENTHREAD_CLI || (CONFIG_OPENTHREAD_RADIO && (CONFIG_OPENTHREAD_RCP_UART || CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG)))
        otPlatUartReceived(s_uart_buffer, (uint16_t)rval);
#endif
    } else if (rval < 0) {
        // EAGAIN means no data is currently available. errno == 0 guards against an
        // older USB Serial/JTAG driver (IDF-14303) returning -1 without setting errno
        // when the host is transiently "not connected". For an RCP a host disconnect
        // is normal and recoverable, so treat both as "no data" and keep looping
        // instead of aborting the firmware.
        if (errno != EAGAIN && errno != 0) {
            return (esp_err_t)(0x10000 | (errno & 0xFFFF));
        }
    }
#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
    esp_openthread_rcp_usb_link_watchdog(rval > 0);
#endif
    return ESP_OK;
}
