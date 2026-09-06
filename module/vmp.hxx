#pragma once

#include "iat.hxx"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct vm_stub
{
    std::uint32_t rva;
    std::uint32_t len;
    std::uint32_t type;
    std::uint8_t reg;
    std::uint32_t resume;
    std::string module;
    std::string name;
    std::uint32_t ordinal;
    std::uint64_t dest;
};

constexpr auto k_vm_call = 0u;
constexpr auto k_vm_jmp = 1u;
constexpr auto k_vm_mov = 2u;

auto is_vm_section_name( const char* name ) -> bool;
auto recover_vm_stubs( const runtime_image& img ) -> std::vector< vm_stub >;
auto count_vm_stubs( const runtime_image& img ) -> std::size_t;
auto apply_vm_stubs( runtime_image& img, const std::vector< vm_stub >& stubs, const std::map< std::uint64_t, std::uint32_t >& dest_to_iat ) -> void;
