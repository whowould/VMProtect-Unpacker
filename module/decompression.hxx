#pragma once

#include <cstdint>
#include <vector>

auto unpack_pe( const std::vector< std::uint8_t >& packed ) -> std::vector< std::uint8_t >;
