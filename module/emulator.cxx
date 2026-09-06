#include "emulator.hxx"

#include <unicorn/unicorn.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    constexpr auto k_page = 0x1000ull;
    constexpr auto k_stack_size = 0x100000ull;
    constexpr auto k_x86_stack = 0x70000000ull;
    constexpr auto k_x64_stack = 0x00007fff00000000ull;
    constexpr auto k_flags = 0x202ull;

    struct monitor
    {
        std::uint64_t begin;
        std::uint64_t end;
        bool has_ret;
        std::uint64_t ret;
        emu_stop_kind kind;
        bool stopped;
        std::uint32_t insns;
        std::uint64_t dest;
        std::uint64_t ret_addr;
        std::uint64_t mem_addr;
        std::size_t mem_size;
    };

    auto fail( const char* op, uc_err err ) -> std::runtime_error
    {
        return std::runtime_error( std::string( op ) + ": " + uc_strerror( err ) );
    }

    auto align_up( std::uint64_t v, std::uint64_t a ) -> std::uint64_t
    {
        return ( v + ( a - 1 ) ) & ~( a - 1 );
    }

    auto stack_base( bool is64 ) -> std::uint64_t
    {
        return is64 ? k_x64_stack : k_x86_stack;
    }

    auto stack_ptr( bool is64 ) -> std::uint64_t
    {
        return stack_base( is64 ) + k_stack_size - k_page;
    }

    auto inside( const monitor* m, std::uint64_t addr ) -> bool
    {
        return addr >= m->begin && addr < m->end;
    }

    auto hook_code( uc_engine* uc, std::uint64_t addr, std::uint32_t, void* user ) -> void
    {
        auto* m = static_cast< monitor* >( user );
        ++m->insns;
        if ( m->has_ret && addr == m->ret )
        {
            m->kind = emu_stop_kind::returned;
            m->ret_addr = addr;
            m->stopped = true;
            uc_emu_stop( uc );
            return;
        }
        if ( !inside( m, addr ) )
        {
            m->kind = emu_stop_kind::external;
            m->dest = addr;
            m->stopped = true;
            uc_emu_stop( uc );
        }
    }

    auto hook_mem( uc_engine* uc, uc_mem_type type, std::uint64_t addr, int size, std::int64_t, void* user ) -> bool
    {
        auto* m = static_cast< monitor* >( user );
        if ( type == UC_MEM_FETCH_UNMAPPED && !inside( m, addr ) )
        {
            m->kind = emu_stop_kind::external;
            m->dest = addr;
        }
        else
        {
            m->kind = emu_stop_kind::unmapped;
            m->mem_addr = addr;
            m->mem_size = static_cast< std::size_t >( size );
        }
        m->stopped = true;
        uc_emu_stop( uc );
        return false;
    }

    auto read_u64( uc_engine* uc, int reg ) -> std::uint64_t
    {
        std::uint64_t v = 0;
        const auto err = uc_reg_read( uc, reg, &v );
        if ( err != UC_ERR_OK )
            throw fail( "uc_reg_read", err );
        return v;
    }

    auto write_u64( uc_engine* uc, int reg, std::uint64_t v ) -> void
    {
        const auto err = uc_reg_write( uc, reg, &v );
        if ( err != UC_ERR_OK )
            throw fail( "uc_reg_write", err );
    }

    auto gprs( bool is64 ) -> std::vector< std::pair< std::uint8_t, int > >
    {
        if ( is64 )
        {
            return {
                { 0, UC_X86_REG_RAX }, { 1, UC_X86_REG_RCX }, { 2, UC_X86_REG_RDX }, { 3, UC_X86_REG_RBX },
                { 5, UC_X86_REG_RBP }, { 6, UC_X86_REG_RSI }, { 7, UC_X86_REG_RDI }, { 8, UC_X86_REG_R8 },
                { 9, UC_X86_REG_R9 }, { 10, UC_X86_REG_R10 }, { 11, UC_X86_REG_R11 }, { 12, UC_X86_REG_R12 },
                { 13, UC_X86_REG_R13 }, { 14, UC_X86_REG_R14 }, { 15, UC_X86_REG_R15 }
            };
        }
        return {
            { 0, UC_X86_REG_EAX }, { 1, UC_X86_REG_ECX }, { 2, UC_X86_REG_EDX }, { 3, UC_X86_REG_EBX },
            { 5, UC_X86_REG_EBP }, { 6, UC_X86_REG_ESI }, { 7, UC_X86_REG_EDI }
        };
    }
}

stub_emulator::stub_emulator( bool is64, std::uint64_t base, std::vector< std::uint8_t > snap )
    : is64_( is64 ), base_( base ), snap_( std::move( snap ) )
{
    if ( snap_.empty( ) )
        throw std::runtime_error( "the module snapshot is empty" );
    if ( base_ & ( k_page - 1 ) )
        throw std::runtime_error( "module base is not aligned to a Unicorn page" );
    const auto size = static_cast< std::uint64_t >( snap_.size( ) );
    if ( base_ > UINT64_MAX - size )
        throw std::runtime_error( "emulator address arithmetic overflowed" );
    end_ = base_ + size;
    mapped_ = align_up( size, k_page );
    if ( base_ > UINT64_MAX - mapped_ )
        throw std::runtime_error( "emulator address arithmetic overflowed" );
    if ( !is64_ && base_ + mapped_ > 0x100000000ull )
        throw std::runtime_error( "address is outside the x86 address space" );
    const auto sb = stack_base( is64_ );
    if ( sb < base_ + mapped_ && base_ < sb + k_stack_size )
        throw std::runtime_error( "the synthetic stack overlaps the module snapshot" );
}

auto stub_emulator::emulate( std::uint64_t stub, bool has_ret, std::uint64_t ret, std::size_t limit ) const -> emu_stop
{
    if ( stub < base_ || stub >= end_ )
        throw std::runtime_error( "stub entry address is outside the module snapshot" );
    if ( has_ret && ( ret < base_ || ret >= end_ ) )
        throw std::runtime_error( "return address is outside the module snapshot" );

    uc_engine* uc = nullptr;
    auto err = uc_open( UC_ARCH_X86, is64_ ? UC_MODE_64 : UC_MODE_32, &uc );
    if ( err != UC_ERR_OK )
        throw fail( "cannot create the emulator", err );

    struct closer
    {
        uc_engine* uc;
        ~closer( )
        {
            if ( uc )
                uc_close( uc );
        }
    } guard{ uc };

    err = uc_mem_map( uc, base_, static_cast< std::size_t >( mapped_ ), UC_PROT_ALL );
    if ( err != UC_ERR_OK )
        throw fail( "cannot map the module snapshot", err );
    err = uc_mem_write( uc, base_, snap_.data( ), snap_.size( ) );
    if ( err != UC_ERR_OK )
        throw fail( "cannot write the module snapshot", err );

    const auto sb = stack_base( is64_ );
    err = uc_mem_map( uc, sb, static_cast< std::size_t >( k_stack_size ), UC_PROT_ALL );
    if ( err != UC_ERR_OK )
        throw fail( "cannot map the synthetic stack", err );

    const auto sp = stack_ptr( is64_ );
    if ( has_ret )
    {
        if ( is64_ )
        {
            err = uc_mem_write( uc, sp, &ret, 8 );
        }
        else
        {
            const auto r32 = static_cast< std::uint32_t >( ret );
            err = uc_mem_write( uc, sp, &r32, 4 );
        }
        if ( err != UC_ERR_OK )
            throw fail( "cannot write the synthetic return address", err );
    }
    write_u64( uc, is64_ ? UC_X86_REG_RSP : UC_X86_REG_ESP, sp );
    write_u64( uc, UC_X86_REG_EFLAGS, k_flags );

    monitor mon{};
    mon.begin = base_;
    mon.end = end_;
    mon.has_ret = has_ret;
    mon.ret = ret;
    mon.kind = emu_stop_kind::limit;
    uc_hook h1{}, h2{};
    err = uc_hook_add( uc, &h1, UC_HOOK_CODE, reinterpret_cast< void* >( hook_code ), &mon, 1, 0 );
    if ( err != UC_ERR_OK )
        throw fail( "cannot install the instruction hook", err );
    err = uc_hook_add( uc, &h2, UC_HOOK_MEM_UNMAPPED, reinterpret_cast< void* >( hook_mem ), &mon, 1, 0 );
    if ( err != UC_ERR_OK )
        throw fail( "cannot install the memory hook", err );

    err = uc_emu_start( uc, stub, 0, 0, limit );
    emu_stop out{};
    if ( mon.stopped )
    {
        out.kind = mon.kind;
        out.dest = mon.dest;
        out.ret_addr = mon.ret_addr;
        out.insns = mon.insns;
        if ( mon.kind == emu_stop_kind::external )
        {
            const auto final_sp = read_u64( uc, is64_ ? UC_X86_REG_RSP : UC_X86_REG_ESP );
            out.sp_delta = static_cast< std::int64_t >( final_sp ) - static_cast< std::int64_t >( sp );
            if ( is64_ )
            {
                std::uint64_t v = 0;
                if ( uc_mem_read( uc, final_sp, &v, 8 ) == UC_ERR_OK )
                    out.ext_ret = v;
            }
            else
            {
                std::uint32_t v = 0;
                if ( uc_mem_read( uc, final_sp, &v, 4 ) == UC_ERR_OK )
                    out.ext_ret = v;
            }
        }
        else if ( mon.kind == emu_stop_kind::returned )
        {
            for ( const auto& g : gprs( is64_ ) )
                out.regs.push_back( { g.first, read_u64( uc, g.second ) } );
        }
        else
        {
            out.insn_addr = mon.mem_addr;
        }
        return out;
    }
    if ( err != UC_ERR_OK )
        throw fail( "cannot emulate the protected import stub", err );
    out.kind = emu_stop_kind::limit;
    out.insn_addr = read_u64( uc, is64_ ? UC_X86_REG_RIP : UC_X86_REG_EIP );
    out.insns = mon.insns;
    return out;
}

