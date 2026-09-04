#pragma once

#include "iat.hxx"

#include <cstdint>
#include <string>
#include <vector>

auto dump_runtime( const char* packed_path, std::uint32_t wait_ms = 8000 ) -> runtime_image;
auto dump_pid( std::uint32_t pid, const char* module_name = nullptr ) -> runtime_image;
auto dump_and_fix( const char* packed_path, std::uint32_t wait_ms = 8000 ) -> std::vector< std::uint8_t >;
auto dump_pid_and_fix( std::uint32_t pid, const char* module_name = nullptr ) -> std::vector< std::uint8_t >;
