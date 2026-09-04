#pragma once

#include <cstdint>
#include <vector>

auto find_oep( const std::vector< std::uint8_t >& image, bool is64 ) -> std::uint32_t;
auto apply_oep( std::vector< std::uint8_t >& image, std::uint32_t oep ) -> void;
