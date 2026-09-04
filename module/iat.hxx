#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct export_sym
{
    std::string module;
    std::string name;
    std::uint32_t ordinal;
    std::uint64_t address;
};

struct module_info
{
    std::string name;
    std::string path;
    std::uint64_t base;
    std::uint32_t size;
};

struct runtime_image
{
    std::vector< std::uint8_t > bytes;
    std::uint64_t base;
    bool is64;
    std::vector< module_info > modules;
    std::vector< export_sym > exports;
};

auto rebuild_iat( runtime_image& img ) -> std::vector< std::uint8_t >;
auto count_resolved_imports( const runtime_image& img ) -> std::size_t;
