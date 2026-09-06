#pragma once

#include <cstdint>
#include <vector>

enum class emu_stop_kind
{
    external,
    unmapped,
    returned,
    limit
};

struct emu_reg
{
    std::uint8_t id;
    std::uint64_t bits;
};

struct emu_stop
{
    emu_stop_kind kind;
    std::uint64_t dest;
    std::int64_t sp_delta;
    std::uint64_t ext_ret;
    std::uint64_t ret_addr;
    std::vector< emu_reg > regs;
    std::uint64_t insn_addr;
    std::uint32_t insns;
};

class stub_emulator
{
public:
    stub_emulator( bool is64, std::uint64_t base, std::vector< std::uint8_t > snap );
    auto emulate( std::uint64_t stub, bool has_ret, std::uint64_t ret, std::size_t limit ) const -> emu_stop;

private:
    bool is64_;
    std::uint64_t base_;
    std::uint64_t end_;
    std::uint64_t mapped_;
    std::vector< std::uint8_t > snap_;
};
