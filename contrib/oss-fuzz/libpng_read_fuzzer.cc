// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#include "png.h"

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}

static const int kPngHeaderSize = 8;

void check_metadata(const PngObjectHandler &png_handler) {

  png_uint_32 width = png_get_image_width(png_handler.png_ptr, png_handler.info_ptr);
  png_uint_32 height = png_get_image_height(png_handler.png_ptr, png_handler.info_ptr);



  int bit_depth = png_get_bit_depth(png_handler.png_ptr, png_handler.info_ptr);
  int color_type = png_get_color_type(png_handler.png_ptr, png_handler.info_ptr);
  int compression_type = png_get_compression_type(png_handler.png_ptr, png_handler.info_ptr);
  int filter_type = png_get_filter_type(png_handler.png_ptr, png_handler.info_ptr);
  int interlace_type = png_get_interlace_type(png_handler.png_ptr, png_handler.info_ptr);



  // --- METADATA RETRIEVAL ---
  png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type);

  //png_uint_32 valid_t = png_get_valid(png_handler.png_ptr, png_handler.info_ptr, ~0U);
  png_uint_32 uint1, uint2;
  png_bytep bytep_1, bytep_2, bytep_3;
  png_color_16p color1, color2, color3;
  int int1, int2, int3;

  double white_x = color1->gray;
  double white_y = color2->gray;
  double red_x = color1->red;
  double red_y = color2->red;
  double green_x = color1->green;
  double green_y = color2->green;
  double blue_x = color1->blue;
  double blue_y = color2->blue;
  double red_z = color3->red;
  double green_z = color3->green;
  double blue_z = color3->blue;

  png_fixed_point white_x_fixed = color1->gray;
  png_fixed_point white_y_fixed = color2->gray;
  png_fixed_point red_x_fixed = color1->red;
  png_fixed_point red_y_fixed = color2->red;
  png_fixed_point green_x_fixed = color1->green;
  png_fixed_point green_y_fixed = color2->green;
  png_fixed_point blue_x_fixed = color1->blue;
  png_fixed_point blue_y_fixed = color2->blue;
  png_fixed_point red_z_fixed = color3->red;
  png_fixed_point green_z_fixed = color3->green;
  png_fixed_point blue_z_fixed = color3->blue;

  // Retrieve pHYs chunk (resolution)
  if (PNG_INFO_pHYs) {
    png_uint_32 res_x;
    png_uint_32 res_y;
    int unit_type = int1;
    png_get_pHYs(png_handler.png_ptr, png_handler.info_ptr,
                 &res_x, &res_y, &unit_type);
    png_get_x_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
    png_get_y_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
    png_get_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
    png_get_pixel_aspect_ratio(png_handler.png_ptr, png_handler.info_ptr);
    png_get_pixel_aspect_ratio_fixed(png_handler.png_ptr, png_handler.info_ptr);
    png_uint_32 res_x_fixed, res_y_fixed;
    png_get_pHYs_dpi(png_handler.png_ptr, png_handler.info_ptr,
                    &res_x_fixed, &res_y_fixed, &unit_type);
  }

  // Retrieve tRNS chunk (transparency)
  if (PNG_INFO_tRNS) {
    png_bytep trans_alpha = bytep_1;
    int num_trans = uint1;
    png_color_16p trans_color = color1;
    png_get_tRNS(png_handler.png_ptr, png_handler.info_ptr,
                 &trans_alpha, &num_trans, &trans_color);
  }

  // Retrieve cHRM chunk (chromaticity)
#ifdef PNG_cHRM_SUPPORTED
  if (PNG_INFO_cHRM) {


    png_get_cHRM(png_handler.png_ptr, png_handler.info_ptr,
                 &white_x, &white_y, &red_x, &red_y,
                 &green_x, &green_y, &blue_x, &blue_y);

    png_get_cHRM_XYZ(png_handler.png_ptr, png_handler.info_ptr,
                 &red_x, &red_y, &red_z,
                 &green_x, &green_y, &green_z,
                  &blue_x, &blue_y, &blue_z);

    png_get_cHRM_fixed(png_handler.png_ptr, png_handler.info_ptr,
                     &white_x_fixed, &white_y_fixed, &red_x_fixed, &red_y_fixed,
                     &green_x_fixed, &green_y_fixed, &blue_x_fixed, &blue_y_fixed);



    png_get_cHRM_XYZ_fixed(png_handler.png_ptr, png_handler.info_ptr,
                     &red_x_fixed, &red_y_fixed, &red_z_fixed,
                     &green_x_fixed, &green_y_fixed, &green_z_fixed,
                     &blue_x_fixed, &blue_y_fixed, &blue_z_fixed);
  }
#endif

#ifdef PNG_gAMA_SUPPORTED
  // Retrieve gAMA chunk (gamma)
  if(PNG_INFO_gAMA) {
    double gamma = int1;
    png_get_gAMA(png_handler.png_ptr, png_handler.info_ptr, &gamma);
    png_fixed_point gamma_fixed = int2;
    png_get_gAMA_fixed(png_handler.png_ptr, png_handler.info_ptr,
                       &gamma_fixed);
  }
#endif

#ifdef PNG_sRGB_SUPPORTED
  // Retrieve sRGB chunk (gamma)
if (PNG_INFO_sRGB) {
    int intent = int1;
    png_get_sRGB(png_handler.png_ptr, png_handler.info_ptr, &intent);
  }
#endif

#ifdef PNG_bKGD_SUPPORTED
  // Retrieve bKGD chunk (background color)
if (PNG_INFO_bKGD) {
    png_color_16p background = color1;
    png_get_bKGD(png_handler.png_ptr, png_handler.info_ptr, &background);
  }
#endif


#ifdef PNG_TEXT_SUPPORTED
  png_textp text_ptr = nullptr;
  int num_text = int1;
  png_get_text(png_handler.png_ptr, png_handler.info_ptr, &text_ptr, &num_text);
#endif
  // Retrieve ICC profile
#ifdef PNG_iCCP_SUPPORTED
  if (PNG_INFO_iCCP) {
    png_charp name;
    png_bytep profile = bytep_1;
    png_uint_32 proflen = int2;
    png_get_iCCP(png_handler.png_ptr, png_handler.info_ptr,
                 &name, &compression_type, &profile, &proflen);
  }
#endif

#ifdef PNG_oFFs_SUPPORTED
  if (PNG_INFO_oFFs) {
    png_int_32 offset_x = int1;
    png_int_32 offset_y = int2;
    int unit_type = int3;
    png_get_oFFs(png_handler.png_ptr, png_handler.info_ptr,
                 &offset_x, &offset_y, &unit_type);

    png_get_x_offset_microns(png_handler.png_ptr, png_handler.info_ptr);
    png_get_y_offset_microns(png_handler.png_ptr, png_handler.info_ptr);
    png_get_x_offset_pixels(png_handler.png_ptr, png_handler.info_ptr);
    png_get_y_offset_pixels(png_handler.png_ptr, png_handler.info_ptr);
  }
#endif

#ifdef PNG_cICP_SUPPORTED
  if (PNG_INFO_cICP) {
    png_bytep colour_primaries = bytep_1;
    png_bytep transfer_function = bytep_2;
    png_bytep matrix_coefficients = bytep_3;
    png_bytep video_full_range_flag;
    png_get_cICP(png_handler.png_ptr, png_handler.info_ptr,
                 colour_primaries, transfer_function,
                 matrix_coefficients, video_full_range_flag);
  }
#endif
    png_uint_32p uintp1, uintp2, uintp3;
#ifdef PNG_mDCV_SUPPORTED
  if (PNG_INFO_mDCV) {
    double mastering_maxDL = int1;
    double mastering_minDL  = int2;
    png_get_mDCV(png_handler.png_ptr, png_handler.info_ptr,
                 &white_x, &white_y, &red_x, &red_y,
                 &green_x, &green_y, &blue_x, &blue_y,
                 &mastering_maxDL, &mastering_minDL);
    png_uint_32p mastering_maxDL_fixed = uintp1;
    png_uint_32p mastering_minDL_fixed = uintp2;
    png_get_mDCV_fixed(png_handler.png_ptr, png_handler.info_ptr,
                         &white_x_fixed, &white_y_fixed, &red_x_fixed, &red_y_fixed,
                         &green_x_fixed, &green_y_fixed, &blue_x_fixed, &blue_y_fixed,
                         mastering_maxDL_fixed, mastering_minDL_fixed);
  }
#endif

#ifdef PNG_eXIf_SUPPORTED
  if (PNG_INFO_eXIf) {
    png_bytep exif = bytep_1;
    png_uint_32 num_exif = uint1;
    png_get_eXIf(png_handler.png_ptr, png_handler.info_ptr,
                  &exif);
    png_get_eXIf_1(png_handler.png_ptr, png_handler.info_ptr,
                  &num_exif, &exif);
  }

#endif

#ifdef PNG_hIST_SUPPORTED
  if (PNG_INFO_hIST) {
    png_uint_16p hist;
    png_get_hIST(png_handler.png_ptr, png_handler.info_ptr,
                 &hist);
  }
#endif

#ifdef PNG_pCAL_SUPPORTED
  if (PNG_INFO_pCAL) {
    png_charp *purpose, *units, *params;
    png_int_32 X0 = uint1;
    png_int_32 X1 = uint2;
    int *type_int, *nparams;
    png_get_pCAL(png_handler.png_ptr, png_handler.info_ptr,
                 purpose, &X0, &X1, type_int, nparams, units, &params);
  }
#endif

#ifdef PNG_sCAL_SUPPORTED
  if (PNG_INFO_sCAL) {
    int *unit = &int1;
    png_fixed_point *width_fixed = &int2;
    png_fixed_point *height_fixed = &int3;
    png_get_sCAL_fixed(png_handler.png_ptr, png_handler.info_ptr,
                       unit, width_fixed, height_fixed);
    double width_d = uint1;
    double height_d = uint2;
    png_get_sCAL(png_handler.png_ptr, png_handler.info_ptr,
                  unit, &width_d, &height_d);

    png_charpp swidth, sheight;
    png_get_sCAL_s(png_handler.png_ptr, png_handler.info_ptr,
                   unit, swidth, sheight);
  }
#endif

#ifdef PNG_PLTE_SUPPORTED
  if (PNG_INFO_PLTE) {
    png_colorp palette;
    int num_palette = int1;
    png_get_PLTE(png_handler.png_ptr, png_handler.info_ptr,
                 &palette, &num_palette);
  }
#endif

#ifdef PNG_tIME_SUPPORTED
  if (PNG_INFO_tIME) {
    png_timep mod_time;
    png_get_tIME(png_handler.png_ptr, png_handler.info_ptr,
                 &mod_time);
  }
#endif

#ifdef PNG_UNKNOWN_CHUNKS_SUPPORTED
  png_unknown_chunkpp entries;
  png_get_unknown_chunks(png_handler.png_ptr, png_handler.info_ptr,
                       entries);
  png_get_user_chunk_ptr(png_handler.png_ptr);
#endif

#ifdef PNG_sBIT_SUPPORTED
  if (PNG_INFO_sBIT) {
    png_color_8p sig_bit;
    png_get_sBIT(png_handler.png_ptr, png_handler.info_ptr,
                 &sig_bit);
  }
#endif
  #ifdef PNG_cLLI_SUPPORTED
    if (PNG_INFO_cLLI) {  // Use bitwise AND (&) not logical AND (&&)
      double maxCLL = 0.0;
      double maxFALL = 0.0;
      png_uint_32 maxCLL_fixed = 0;
      png_uint_32 maxFALL_fixed = 0;

      // Floating point version
      if (!png_get_cLLI(png_handler.png_ptr, png_handler.info_ptr,
                      &maxCLL, &maxFALL)) {
        return;
      }

      // Fixed point version
      if (!png_get_cLLI_fixed(png_handler.png_ptr, png_handler.info_ptr,
                            &maxCLL_fixed, &maxFALL_fixed)) {
        return;
      }
    }
  #endif

  #ifdef PNG_sPLT_SUPPORTED
    if (PNG_INFO_sPLT) {  // Use bitwise AND (&)
      png_sPLT_tpp splt_palettes;
      png_get_sPLT(png_handler.png_ptr,
                                     png_handler.info_ptr,
                                     splt_palettes);
    }
  #endif
}

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;

  }

  if (size > 100000) return 0;  // Skip overly large files

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }

  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;


  png_handler.png_ptr = png_create_read_struct
    (PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Use a custom allocator that fails for large allocations to avoid OOM.
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

  // Setting up reading from buffer.
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  // Reading.
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // reset error handler to put png_deleter into scope.
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }


  png_uint_32 width = png_get_image_width(png_handler.png_ptr, png_handler.info_ptr);
  png_uint_32 height = png_get_image_height(png_handler.png_ptr, png_handler.info_ptr);

  // Before allocations:
  const size_t kMaxAlloc = 100*1024*1024; // 100MB
  if (width > 10000 || height > 10000 || width*height > kMaxAlloc/4) {
    return 0;
  }

  int bit_depth = png_get_bit_depth(png_handler.png_ptr, png_handler.info_ptr);
  int color_type = png_get_color_type(png_handler.png_ptr, png_handler.info_ptr);
  int compression_type = png_get_compression_type(png_handler.png_ptr, png_handler.info_ptr);
  int filter_type = png_get_filter_type(png_handler.png_ptr, png_handler.info_ptr);
  int interlace_type = png_get_interlace_type(png_handler.png_ptr, png_handler.info_ptr);



  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                      &height, &bit_depth, &color_type, &interlace_type,
                      &compression_type, &filter_type)) {
    PNG_CLEANUP
    return 0;
                      }

  if (rand() % 7 == 0) {
    check_metadata(png_handler);
  }

  // This is going to be too slow.
  if (width && height > 100000000 / width) {
    PNG_CLEANUP
    return 0;
  }

  // Set several transforms that browsers typically use:
  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr,
                                            png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  PNG_CLEANUP

#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
  // Simplified READ API
  png_image image;
  memset(&image, 0, (sizeof image));
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    return 0;
  }

  image.format = PNG_FORMAT_RGBA;
  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
  png_image_finish_read(&image, NULL, buffer.data(), 0, NULL);
#endif

  return 0;
}
