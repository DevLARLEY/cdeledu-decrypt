#include <stdio.h>

#include "runtime.h"

uint32_t readFileIntoWasmBuffer(w2c_runtime* runtime, const char* filePath) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        return 0;
    }

    fseek(file, 0, SEEK_END);
    const uint32_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    const uint32_t bufferPtr = w2c_runtime_create_buff(runtime, fileSize);
    if (bufferPtr == 0) {
        fclose(file);
        return 0;
    }

    const wasm_rt_memory_t* memory = w2c_runtime_memory(runtime);

    const size_t bytesRead = fread(&memory->data[bufferPtr], 1, fileSize, file);
    fclose(file);

    if (bytesRead != fileSize) {
        w2c_runtime_free_buff(runtime, bufferPtr);
        return 0;
    }

    return bufferPtr;
}

int main(int argc, char** argv) {
    printf("cdeledu.com WASM decrypt by github.com/DevLARLEY\n");

    if (argc < 5) {
        printf("%s [input_file] [key] [output_file] [fragment_number]\n", argv[0]);
        return 0;
    }

    printf("reading: %s\n", argv[1]);

    wasm_rt_init();

    w2c_runtime runtime;
    wasm2c_runtime_instantiate(&runtime, 0, 0);

    const wasm_rt_memory_t* memory = w2c_runtime_memory(&runtime);

    // ----------------- data ----------------- //

    FILE* data_file = fopen(argv[1], "rb");
    if (!data_file) {
        printf("unable to open input file\n");
        return 0;
    }

    fseek(data_file, 0, SEEK_END);
    const uint32_t data_length = ftell(data_file);
    fseek(data_file, 0, SEEK_SET);

    const uint32_t data_buffer = w2c_runtime_create_buff(&runtime, data_length);
    if (data_buffer == 0) {
        printf("unable to allocate input buffer\n");
        fclose(data_file);
        return 0;
    }

    const size_t data_read = fread(&memory->data[data_buffer], 1, data_length, data_file);
    fclose(data_file);

    if (data_read != data_length) {
        w2c_runtime_free_buff(&runtime, data_buffer);
        printf("incomplete input file read\n");
        return 0;
    }

    // ----------------- key ----------------- //

    const uint8_t* key = (const uint8_t*)argv[2];
    const uint32_t key_length = sizeof(key);
    const uint32_t key_buffer = w2c_runtime_create_buff(&runtime, key_length);

    for (uint32_t i = 0; i < key_length; i++) {
        memory->data[key_buffer + i] = key[i];
    }

    // ----------------- iv ----------------- //

    char *end_ptr;
    errno = 0;

    const uint32_t int_iv = strtol(argv[4], &end_ptr, 10);

    if (errno != 0 || *end_ptr != '\0' || int_iv > UINT32_MAX) {
        printf("invalid index\n");
        return 0;
    }

    uint8_t iv[16] = { 0 };
    iv[12] = int_iv >> 24 & 0xFF;
    iv[13] = int_iv >> 16 & 0xFF;
    iv[14] = int_iv >> 8 & 0xFF;
    iv[15] = int_iv & 0xFF;

    const uint32_t iv_length = 16;
    const uint32_t iv_buffer = w2c_runtime_create_buff(&runtime, iv_length);

    for (uint32_t i = 0; i < iv_length; i++) {
        memory->data[iv_buffer + i] = iv[i];
    }

    // ----------------- processing ----------------- //

    const uint32_t output_length = w2c_runtime_de3(&runtime, data_buffer, data_length, key_buffer, key_length, iv_buffer, iv_length);
    const uint32_t output_ptr = w2c_runtime_getoutputPtr(&runtime);

    uint8_t* output_data = malloc(output_length);
    if (!output_data) {
        printf("unable to allocate output data\n");
        return 0;
    }

    memcpy(output_data, &memory->data[output_ptr], output_length);

    printf("writing: %s\n", argv[3]);

    FILE* out_file = fopen(argv[3], "wb");
    if (!out_file) {
        printf("unable to open output file\n");
        return 0;
    }

    const size_t output_written = fwrite(output_data, 1, output_length, data_file);
    fclose(data_file);

    if (output_written != output_length) {
        printf("incomplete output file write\n");
        return 0;
    }

    free(output_data);

    // ----------------- cleaning up ----------------- //

    w2c_runtime_free_buff(&runtime, data_buffer);
    w2c_runtime_free_buff(&runtime, key_buffer);
    w2c_runtime_free_buff(&runtime, iv_buffer);
    w2c_runtime_free_buff(&runtime, output_ptr);

    wasm2c_runtime_free(&runtime);
    wasm_rt_free();

    return 0;
}