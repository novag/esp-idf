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
// ...or the FAILURE actually observed in the field (2026-06-10): the host keeps sending and the RCP
// keeps RECEIVING (so RX silence never trips), but the device->host TX path is dead -- otbr sees no
// response. Detect "RX is active but no successful TX for this long" (ms). See otPlatUartSend().
#define ESP_OT_RCP_USB_TX_STALL_TIMEOUT_MS     (60u * 1000u)

// Set to 0 to build a DEBUG variant that detects + records a wedge but does NOT reset --
// it leaves the link deaf so the failure is loud and the live state can be inspected (e.g.
// to test whether a host-side USB re-enumerate recovers it). Default 1 = auto-recover.
#ifndef ESP_OT_RCP_USB_WEDGE_AUTORECOVER
#define ESP_OT_RCP_USB_WEDGE_AUTORECOVER 1
#endif

// Ring of the last N wedge records kept in RTC RAM, so multiple failures are preserved and a
// later (possibly less-informative) wedge cannot overwrite the one that shows the cause.
#define ESP_OT_RCP_USB_WEDGE_LOG_N 16

#define ESP_OT_RCP_USB_DIAG_MAGIC 0x4f544444u  // bumped for new layout; dump shows bytes "DDTO"

// One forensic record per wedge (32 bytes). int_raw bits: bit1 sof, bit2 serial_out_recv_pkt,
// bits4-7 pid/crc5/crc16/stuff err, bit9 usb_bus_reset, bit13 dtr_chg.
typedef struct {
    uint32_t uptime_ms;         // device uptime at the wedge (this boot session)
    uint32_t wedge_kind;        // 1 = sustained-disconnect, 2 = rx-silence (deaf), 4 = tx-stall
    uint32_t int_raw_accum;     // OR of USB int_raw this boot up to the wedge (sticky bits)
    uint32_t int_raw_at_wedge;  // USB int_raw snapshot at the wedge
    uint32_t conf0_at_wedge;    // CONF0: bit0 phy_sel, bit8 pad_pull_override, bit9 dp_pullup
    uint32_t chip_rst_at_wedge; // chip_rst: bit0 host RTS, bit1 host DTR (is the host port open?)
    uint32_t rx_idle_ms;        // ms since last successful read() at the wedge (small => RX still works)
    uint32_t tx_idle_ms;        // ms since last successful otPlatUartSend() at the wedge (large => TX dead)
} esp_ot_rcp_usb_wedge_rec_t;

typedef struct {
    uint32_t magic;
    uint32_t boot_count;        // total boots since power-on (RTC RAM survives reset)
    int32_t  last_reset_reason; // esp_reset_reason() observed at the latest boot
    uint32_t disconnect_events; // usb_serial_jtag_is_connected() true->false transitions
    uint32_t reconnect_events;  // false->true transitions (stays flat if monitor never recovers)
    uint32_t max_disconnect_ms; // longest observed not-connected streak
    uint32_t wedge_count;       // total wedges detected ever (> N => oldest ring entries rolled off)
    uint32_t last_wedge_kind;   // 1 = sustained-disconnect, 2 = deaf-despite-connected
    uint32_t usb_int_raw_accum; // live OR of USB int_raw for the current boot session
    uint32_t wedge_log_head;    // next write index into wedge_log (newest record is at (head-1) % N)
    esp_ot_rcp_usb_wedge_rec_t wedge_log[ESP_OT_RCP_USB_WEDGE_LOG_N];
} esp_ot_rcp_usb_diag_t;

static RTC_NOINIT_ATTR esp_ot_rcp_usb_diag_t s_usb_diag;

// Updated by otPlatUartSend() on every successful device->host send. The watchdog compares it against
// the last RX to detect a dead TX path (RX still flowing, but nothing gets sent back). uint32 ms is
// atomic on the 32-bit core, so there are no torn reads across the two contexts.
static volatile uint32_t s_last_tx_ok_ms;

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
    static bool s_wedge_recorded = false;  // one ring record per deaf episode (avoid spam if not auto-resetting)
    static int64_t s_last_rx_us;
    static int64_t s_disconnected_since_us;
    static bool s_was_connected;

    int64_t now = esp_timer_get_time();
    uint32_t now_ms = (uint32_t)(now / 1000);
    if (!s_initialized) {
        s_last_rx_us = now;
        s_disconnected_since_us = 0;
        s_was_connected = true;
        s_last_tx_ok_ms = now_ms;
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
    // TX-stall: the CONFIRMED field failure (2026-06-10). The host keeps sending and we keep RECEIVING
    // (so deaf_despite_connected never trips -- the device stayed deaf 43min with the RX timer never
    // expiring), but the device->host TX path is dead so otbr sees no response. Detect "RX is recent
    // (host is actively talking to us) but no successful send for too long". Gated on s_ever_received;
    // the rx-recent term keeps a genuinely idle link from tripping.
    bool tx_stall = connected && s_ever_received &&
                    ((now - s_last_rx_us) < ESP_OT_RCP_USB_RX_SILENCE_TIMEOUT_US) &&
                    ((uint32_t)(now_ms - s_last_tx_ok_ms) > ESP_OT_RCP_USB_TX_STALL_TIMEOUT_MS);
    // Sustained disconnect: SOF genuinely gone for a long time (conn_status latched
    // false). Gated on s_ever_received so a no-host board cannot reset-loop.
    bool sustained_disconnect = s_ever_received && (s_disconnected_since_us != 0) &&
                                (now - s_disconnected_since_us > ESP_OT_RCP_USB_DISCONNECT_TIMEOUT_US);

    if (deaf_despite_connected || tx_stall || sustained_disconnect) {
        if (!s_wedge_recorded) {
            s_wedge_recorded = true;
            uint32_t kind = sustained_disconnect ? 1u : (deaf_despite_connected ? 2u : 4u);
            s_usb_diag.wedge_count++;
            s_usb_diag.last_wedge_kind = kind;
            // Record a forensic snapshot of the USB peripheral into the ring, so the cause of the
            // data-path death is readable from RTC RAM later -- and a subsequent wedge cannot
            // overwrite the record that shows the cause.
            esp_ot_rcp_usb_wedge_rec_t *rec = &s_usb_diag.wedge_log[s_usb_diag.wedge_log_head % ESP_OT_RCP_USB_WEDGE_LOG_N];
            rec->uptime_ms = now_ms;
            rec->wedge_kind = kind;
            rec->int_raw_accum = s_usb_diag.usb_int_raw_accum;
            rec->int_raw_at_wedge = usb_serial_jtag_ll_get_intraw_mask();
            rec->conf0_at_wedge = USB_SERIAL_JTAG.conf0.val;
            rec->chip_rst_at_wedge = USB_SERIAL_JTAG.chip_rst.val;
            rec->rx_idle_ms = (uint32_t)((now - s_last_rx_us) / 1000);
            rec->tx_idle_ms = (uint32_t)(now_ms - s_last_tx_ok_ms);
            s_usb_diag.wedge_log_head++;
        }
#if ESP_OT_RCP_USB_WEDGE_AUTORECOVER
        // Full digital-core reset -> clean USB re-enumeration. esp_restart() would be a
        // CPU-only reset on C6 and would leave the wedged USB peripheral untouched.
        esp_rom_software_reset_system();
#else
        // DEBUG build: do not reset -- leave the link deaf for live inspection. The wedge is
        // already recorded above; it stays loud until manually recovered.
#endif
    } else {
        s_wedge_recorded = false;  // link is healthy again -> the next wedge is a new episode
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

#if CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG
    // Mark a successful device->host send for the TX-stall watchdog (see the link watchdog above).
    s_last_tx_ok_ms = (uint32_t)(esp_timer_get_time() / 1000);
#endif
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
