#include "esp_check.h"
#include "led_strip_encoder.h"

static const char *TAG = "led_encoder";

typedef struct {
    rmt_encoder_t base;
    rmt_encoder_t *bytes_encoder;
    rmt_encoder_t *copy_encoder;
    int state;
    rmt_symbol_word_t reset_code;
} rmt_led_strip_encoder_t;

static size_t rmt_encode_led_strip(rmt_encoder_t *encoder, rmt_channel_handle_t channel,
                                   const void *primary_data, size_t data_size,
                                   rmt_encode_state_t *ret_state) {
    rmt_led_strip_encoder_t *led_encoder = (rmt_led_strip_encoder_t *)encoder;
    rmt_encoder_handle_t bytes_encoder = led_encoder->bytes_encoder;
    rmt_encoder_handle_t copy_encoder = led_encoder->copy_encoder;
    rmt_encode_state_t session_state = RMT_ENCODING_RESET;
    rmt_encode_state_t state = RMT_ENCODING_RESET;
    size_t encoded_symbols = 0;
    switch (led_encoder->state) {
    case 0:
        encoded_symbols += bytes_encoder->encode(bytes_encoder, channel, primary_data, data_size, &session_state);
        if (session_state & RMT_ENCODING_COMPLETE) led_encoder->state = 1;
        if (session_state & RMT_ENCODING_MEM_FULL) {
            state = (rmt_encode_state_t)(state | RMT_ENCODING_MEM_FULL);
            goto out;
        }
    case 1:
        encoded_symbols += copy_encoder->encode(copy_encoder, channel, &led_encoder->reset_code,
                                                sizeof(led_encoder->reset_code), &session_state);
        if (session_state & RMT_ENCODING_COMPLETE) {
            led_encoder->state = RMT_ENCODING_RESET;
            state = (rmt_encode_state_t)(state | RMT_ENCODING_COMPLETE);
        }
        if (session_state & RMT_ENCODING_MEM_FULL) {
            state = (rmt_encode_state_t)(state | RMT_ENCODING_MEM_FULL);
            goto out;
        }
    }
out:
    *ret_state = state;
    return encoded_symbols;
}

static esp_err_t rmt_del_led_strip_encoder(rmt_encoder_t *encoder) {
    rmt_led_strip_encoder_t *led_encoder = (rmt_led_strip_encoder_t *)encoder;
    rmt_del_encoder(led_encoder->bytes_encoder);
    rmt_del_encoder(led_encoder->copy_encoder);
    free(led_encoder);
    return ESP_OK;
}

static esp_err_t rmt_led_strip_encoder_reset(rmt_encoder_t *encoder) {
    rmt_led_strip_encoder_t *led_encoder = (rmt_led_strip_encoder_t *)encoder;
    rmt_encoder_reset(led_encoder->bytes_encoder);
    rmt_encoder_reset(led_encoder->copy_encoder);
    led_encoder->state = RMT_ENCODING_RESET;
    return ESP_OK;
}

esp_err_t rmt_new_led_strip_encoder(const led_strip_encoder_config_t *config, rmt_encoder_handle_t *ret_encoder) {
    esp_err_t ret = ESP_OK;
    rmt_led_strip_encoder_t *led_encoder = NULL;
    if (!config || !ret_encoder) return ESP_ERR_INVALID_ARG;

    led_encoder = (rmt_led_strip_encoder_t *)rmt_alloc_encoder_mem(sizeof(rmt_led_strip_encoder_t));
    if (!led_encoder) return ESP_ERR_NO_MEM;

    led_encoder->base.encode = rmt_encode_led_strip;
    led_encoder->base.del = rmt_del_led_strip_encoder;
    led_encoder->base.reset = rmt_led_strip_encoder_reset;

    rmt_bytes_encoder_config_t bytes_encoder_config;
    memset(&bytes_encoder_config, 0, sizeof(bytes_encoder_config));
    bytes_encoder_config.bit0.level0 = 1;
    bytes_encoder_config.bit0.duration0 = config->resolution / 1000000 * 0.3;
    bytes_encoder_config.bit0.level1 = 0;
    bytes_encoder_config.bit0.duration1 = config->resolution / 1000000 * 0.9;
    bytes_encoder_config.bit1.level0 = 1;
    bytes_encoder_config.bit1.duration0 = config->resolution / 1000000 * 0.9;
    bytes_encoder_config.bit1.level1 = 0;
    bytes_encoder_config.bit1.duration1 = config->resolution / 1000000 * 0.3;
    bytes_encoder_config.flags.msb_first = 1;

    ret = rmt_new_bytes_encoder(&bytes_encoder_config, &led_encoder->bytes_encoder);
    if (ret != ESP_OK) { free(led_encoder); return ret; }

    rmt_copy_encoder_config_t copy_encoder_config;
    memset(&copy_encoder_config, 0, sizeof(copy_encoder_config));
    ret = rmt_new_copy_encoder(&copy_encoder_config, &led_encoder->copy_encoder);
    if (ret != ESP_OK) {
        rmt_del_encoder(led_encoder->bytes_encoder);
        free(led_encoder);
        return ret;
    }

    uint32_t reset_ticks = config->resolution / 1000000 * 50 / 2;
    memset(&led_encoder->reset_code, 0, sizeof(led_encoder->reset_code));
    led_encoder->reset_code.level0 = 0;
    led_encoder->reset_code.duration0 = reset_ticks;
    led_encoder->reset_code.level1 = 0;
    led_encoder->reset_code.duration1 = reset_ticks;

    *ret_encoder = &led_encoder->base;
    return ESP_OK;
}
