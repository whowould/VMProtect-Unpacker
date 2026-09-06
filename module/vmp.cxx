#include "vmp.hxx"
#include "emulator.hxx"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    constexpr auto k_max_sections = 96u;
    constexpr auto k_section_hdr = 40u;
    constexpr auto k_entropy_min = 7.0;
    constexpr auto k_stub_limit = 100000u;
    constexpr auto k_max_stub_insns = 768u;
    constexpr auto k_max_patch = 32u;

    auto read_u16( const std::uint8_t* p ) -> std::uint16_t
    {
        std::uint16_t v;
        std::memcpy( &v, p, sizeof( v ) );
        return v;
    }

    auto read_u32( const std::uint8_t* p ) -> std::uint32_t
    {
        std::uint32_t v;
        std::memcpy( &v, p, sizeof( v ) );
        return v;
    }

    auto lower8( const char* s ) -> std::string
    {
        char n[ 9 ]{};
        if ( !s )
            return {};
        for ( auto i = 0; i < 8 && s[ i ]; ++i )
            n[ i ] = static_cast< char >( ::tolower( static_cast< unsigned char >( s[ i ] ) ) );
        return n;
    }

    auto is_api_set( const std::string& m ) -> bool
    {
        auto s = m;
        for ( auto& c : s )
            c = static_cast< char >( ::tolower( static_cast< unsigned char >( c ) ) );
        return s.rfind( "api-ms-", 0 ) == 0 || s.rfind( "ext-ms-", 0 ) == 0;
    }

    auto better( const export_sym& a, const export_sym& b ) -> bool
    {
        if ( is_api_set( a.module ) != is_api_set( b.module ) )
            return !is_api_set( a.module );
        if ( a.name.empty( ) != b.name.empty( ) )
            return a.name.empty( ) < b.name.empty( );
        if ( a.module != b.module )
            return a.module < b.module;
        return a.name < b.name;
    }

    auto pick_export( const runtime_image& img, std::uint64_t addr ) -> const export_sym*
    {
        const export_sym* best = nullptr;
        for ( const auto& e : img.exports )
        {
            if ( e.address != addr )
                continue;
            if ( !best || better( e, *best ) )
                best = &e;
        }
        return best;
    }

    struct vsec
    {
        char name[ 9 ];
        std::uint32_t va;
        std::uint32_t span;
        std::uint32_t ch;
        bool vm;
    };

    auto entropy( const std::uint8_t* p, std::size_t n ) -> double
    {
        if ( !n )
            return 0;
        const auto take = ( std::min )( n, static_cast< std::size_t >( 65536 ) );
        std::size_t c[ 256 ]{};
        for ( std::size_t i = 0; i < take; ++i )
            ++c[ p[ i ] ];
        auto h = 0.0;
        for ( auto i = 0; i < 256; ++i )
        {
            if ( !c[ i ] )
                continue;
            const auto q = static_cast< double >( c[ i ] ) / static_cast< double >( take );
            h -= q * ( std::log( q ) / std::log( 2.0 ) );
        }
        return h;
    }

    auto read_secs( const runtime_image& img ) -> std::vector< vsec >
    {
        std::vector< vsec > out;
        if ( img.bytes.size( ) < 0x40 )
            return out;
        const auto nt = read_u32( img.bytes.data( ) + 0x3c );
        if ( nt + 24 >= img.bytes.size( ) )
            return out;
        const auto nsec = read_u16( img.bytes.data( ) + nt + 6 );
        const auto opt_size = read_u16( img.bytes.data( ) + nt + 20 );
        const auto secoff = nt + 24 + opt_size;
        if ( !nsec || nsec > k_max_sections )
            return out;
        for ( std::uint16_t i = 0; i < nsec; ++i )
        {
            const auto off = secoff + i * k_section_hdr;
            if ( off + k_section_hdr > img.bytes.size( ) )
                break;
            vsec s{};
            std::memcpy( s.name, img.bytes.data( ) + off, 8 );
            const auto vsize = read_u32( img.bytes.data( ) + off + 8 );
            s.va = read_u32( img.bytes.data( ) + off + 12 );
            const auto raw = read_u32( img.bytes.data( ) + off + 16 );
            s.ch = read_u32( img.bytes.data( ) + off + 36 );
            s.span = vsize > raw ? vsize : raw;
            if ( s.va >= img.bytes.size( ) )
                s.span = 0;
            else if ( static_cast< std::size_t >( s.va ) + s.span > img.bytes.size( ) )
                s.span = static_cast< std::uint32_t >( img.bytes.size( ) - s.va );
            s.vm = is_vm_section_name( s.name );
            out.push_back( s );
        }
        auto named = 0;
        for ( const auto& s : out )
        {
            if ( s.vm && ( s.ch & IMAGE_SCN_MEM_EXECUTE ) )
                ++named;
        }
        if ( !named )
        {
            auto n = 0;
            for ( auto& s : out )
            {
                if ( n >= 3 )
                    break;
                if ( !( s.ch & IMAGE_SCN_MEM_EXECUTE ) || !s.span )
                    continue;
                const auto nm = lower8( s.name );
                if ( nm == ".text" || nm == ".textbss" )
                    continue;
                if ( entropy( img.bytes.data( ) + s.va, s.span ) > k_entropy_min )
                {
                    s.vm = true;
                    ++n;
                }
            }
        }
        return out;
    }

    auto in_vm( const std::vector< vsec >& secs, std::uint32_t rva ) -> bool
    {
        for ( const auto& s : secs )
        {
            if ( s.vm && rva >= s.va && rva < s.va + s.span )
                return true;
        }
        return false;
    }

    auto read_u64( const std::uint8_t* p ) -> std::uint64_t
    {
        std::uint64_t v;
        std::memcpy( &v, p, sizeof( v ) );
        return v;
    }

    struct decoded
    {
        bool ok;
        std::uint8_t len;
        ZydisMnemonic mnemonic;
        ZydisInstructionCategory category;
        ZydisDecodedOperand ops[ ZYDIS_MAX_OPERAND_COUNT ];
        ZyanU8 op_count;
        std::uint64_t abs0;
        bool has_abs0;
    };

    auto decode_at( const runtime_image& img, std::uint32_t rva ) -> decoded
    {
        decoded d{};
        if ( rva >= img.bytes.size( ) )
            return d;
        ZydisDecoder dec;
        if ( !ZYAN_SUCCESS( ZydisDecoderInit( &dec, img.is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32, img.is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32 ) ) )
            return d;
        ZydisDecodedInstruction insn;
        if ( !ZYAN_SUCCESS( ZydisDecoderDecodeFull( &dec, img.bytes.data( ) + rva, img.bytes.size( ) - rva, &insn, d.ops ) ) )
            return d;
        d.ok = true;
        d.len = insn.length;
        d.mnemonic = insn.mnemonic;
        d.category = insn.meta.category;
        d.op_count = insn.operand_count_visible;
        if ( d.op_count && ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &insn, &d.ops[ 0 ], img.base + rva, &d.abs0 ) ) )
            d.has_abs0 = true;
        return d;
    }

    auto zy_reg( ZydisRegister r ) -> std::uint8_t
    {
        switch ( r )
        {
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return 0;
        case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX:
            return 1;
        case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX:
            return 2;
        case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX:
            return 3;
        case ZYDIS_REGISTER_ESP:
        case ZYDIS_REGISTER_RSP:
            return 4;
        case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_RBP:
            return 5;
        case ZYDIS_REGISTER_ESI:
        case ZYDIS_REGISTER_RSI:
            return 6;
        case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_RDI:
            return 7;
        case ZYDIS_REGISTER_R8:
            return 8;
        case ZYDIS_REGISTER_R9:
            return 9;
        case ZYDIS_REGISTER_R10:
            return 10;
        case ZYDIS_REGISTER_R11:
            return 11;
        case ZYDIS_REGISTER_R12:
            return 12;
        case ZYDIS_REGISTER_R13:
            return 13;
        case ZYDIS_REGISTER_R14:
            return 14;
        case ZYDIS_REGISTER_R15:
            return 15;
        default:
            return 0xff;
        }
    }

    auto is_rel_call( const decoded& d ) -> bool
    {
        return d.ok && d.mnemonic == ZYDIS_MNEMONIC_CALL && d.len == 5 && d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    }

    auto is_rel_jmp( const decoded& d ) -> bool
    {
        return d.ok && d.mnemonic == ZYDIS_MNEMONIC_JMP && d.len == 5 && d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    }

    auto is_near_imm( const decoded& d ) -> bool
    {
        return d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.ops[ 0 ].imm.is_relative;
    }

    auto dir_off( const runtime_image& img ) -> std::uint32_t
    {
        if ( img.bytes.size( ) < 0x40 )
            return 0;
        const auto nt = read_u32( img.bytes.data( ) + 0x3c );
        if ( nt + 24 >= img.bytes.size( ) )
            return 0;
        const auto magic = read_u16( img.bytes.data( ) + nt + 24 );
        const auto opt = nt + 24;
        if ( magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
            return opt + 112;
        if ( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            return opt + 96;
        return 0;
    }

    auto read_dir( const runtime_image& img, std::size_t i ) -> std::pair< std::uint32_t, std::uint32_t >
    {
        const auto off = dir_off( img );
        if ( !off || off + ( i + 1 ) * 8 > img.bytes.size( ) )
            return { 0, 0 };
        return { read_u32( img.bytes.data( ) + off + i * 8 ), read_u32( img.bytes.data( ) + off + i * 8 + 4 ) };
    }

    auto code_roots( const runtime_image& img ) -> std::vector< std::uint32_t >
    {
        std::set< std::uint32_t > roots;
        auto add = [ & ]( std::uint32_t rva )
        {
            if ( rva && rva < img.bytes.size( ) )
                roots.insert( rva );
        };
        if ( img.bytes.size( ) >= 0x40 )
        {
            const auto nt = read_u32( img.bytes.data( ) + 0x3c );
            const auto opt = nt + 24;
            if ( opt + 20 < img.bytes.size( ) )
                add( read_u32( img.bytes.data( ) + opt + 16 ) );
        }
        const auto exp = read_dir( img, IMAGE_DIRECTORY_ENTRY_EXPORT );
        if ( exp.first && exp.second >= 40 && exp.first + 40 <= img.bytes.size( ) )
        {
            const auto nfun = read_u32( img.bytes.data( ) + exp.first + 20 );
            const auto funs = read_u32( img.bytes.data( ) + exp.first + 28 );
            for ( std::uint32_t i = 0; i < nfun && i < 1000000u; ++i )
            {
                const auto off = funs + i * 4;
                if ( off + 4 > img.bytes.size( ) )
                    break;
                const auto rva = read_u32( img.bytes.data( ) + off );
                if ( rva && !( rva >= exp.first && rva < exp.first + exp.second ) )
                    add( rva );
            }
        }
        if ( img.is64 )
        {
            const auto ex = read_dir( img, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
            if ( ex.first && ex.second && ( ex.second % 12 ) == 0 )
            {
                const auto n = ex.second / 12;
                for ( std::uint32_t i = 0; i < n && i < 1000000u; ++i )
                {
                    const auto off = ex.first + i * 12;
                    if ( off + 4 > img.bytes.size( ) )
                        break;
                    add( read_u32( img.bytes.data( ) + off ) );
                }
            }
        }
        const auto tls = read_dir( img, IMAGE_DIRECTORY_ENTRY_TLS );
        const auto tls_sz = img.is64 ? 40u : 24u;
        const auto cb_off = img.is64 ? 24u : 12u;
        const auto w = img.is64 ? 8u : 4u;
        if ( tls.first && tls.second >= tls_sz && tls.first + tls_sz <= img.bytes.size( ) )
        {
            const auto table = img.is64 ? read_u64( img.bytes.data( ) + tls.first + cb_off ) : read_u32( img.bytes.data( ) + tls.first + cb_off );
            if ( table >= img.base )
            {
                auto rva = static_cast< std::uint32_t >( table - img.base );
                for ( auto i = 0; i < 1000000; ++i )
                {
                    if ( static_cast< std::size_t >( rva ) + w > img.bytes.size( ) )
                        break;
                    const auto addr = img.is64 ? read_u64( img.bytes.data( ) + rva ) : read_u32( img.bytes.data( ) + rva );
                    if ( !addr )
                        break;
                    if ( addr >= img.base )
                        add( static_cast< std::uint32_t >( addr - img.base ) );
                    rva += w;
                }
            }
        }
        if ( roots.empty( ) )
        {
            const auto secs = read_secs( img );
            for ( const auto& s : secs )
            {
                if ( ( s.ch & IMAGE_SCN_MEM_EXECUTE ) && !s.vm && s.va )
                    add( s.va );
            }
        }
        return { roots.begin( ), roots.end( ) };
    }

    struct xfer
    {
        bool jmp;
        std::uint32_t rva;
        std::uint8_t len;
        std::uint32_t stub;
        std::uint32_t ret;
        bool has_ret;
    };

    auto find_xfers( const runtime_image& img, const std::vector< vsec >& secs ) -> std::vector< xfer >
    {
        std::vector< xfer > out;
        std::vector< std::uint32_t > pending = code_roots( img );
        std::set< std::uint32_t > seen;
        std::map< std::uint32_t, std::uint32_t > decoded;
        while ( !pending.empty( ) )
        {
            const auto rva = pending.back( );
            pending.pop_back( );
            if ( !seen.insert( rva ).second )
                continue;
            auto in_exec = false;
            for ( const auto& s : secs )
            {
                if ( ( s.ch & IMAGE_SCN_MEM_EXECUTE ) && !s.vm && rva >= s.va && rva < s.va + s.span )
                    in_exec = true;
            }
            if ( !in_exec )
                continue;
            const auto d = decode_at( img, rva );
            if ( !d.ok )
                continue;
            const auto end = rva + d.len;
            auto overlap = false;
            auto it = decoded.upper_bound( rva );
            if ( it != decoded.begin( ) )
            {
                --it;
                if ( it->second > rva )
                    overlap = true;
            }
            for ( auto jt = decoded.lower_bound( rva ); !overlap && jt != decoded.end( ) && jt->first < end; ++jt )
                overlap = true;
            if ( overlap )
                continue;
            decoded[ rva ] = end;
            if ( ( is_rel_call( d ) || is_rel_jmp( d ) ) && d.has_abs0 && d.abs0 >= img.base )
            {
                const auto stub = static_cast< std::uint32_t >( d.abs0 - img.base );
                if ( in_vm( secs, stub ) )
                {
                    xfer x{};
                    x.jmp = is_rel_jmp( d );
                    x.rva = rva;
                    x.len = d.len;
                    x.stub = stub;
                    x.has_ret = !x.jmp;
                    x.ret = x.has_ret ? end : 0;
                    out.push_back( x );
                }
            }
            const auto next = end;
            if ( d.category == ZYDIS_CATEGORY_CALL || d.category == ZYDIS_CATEGORY_COND_BR )
            {
                if ( is_near_imm( d ) && d.has_abs0 && d.abs0 >= img.base )
                    pending.push_back( static_cast< std::uint32_t >( d.abs0 - img.base ) );
                pending.push_back( next );
            }
            else if ( d.category == ZYDIS_CATEGORY_UNCOND_BR )
            {
                if ( is_near_imm( d ) && d.has_abs0 && d.abs0 >= img.base )
                    pending.push_back( static_cast< std::uint32_t >( d.abs0 - img.base ) );
            }
            else if ( d.category != ZYDIS_CATEGORY_RET && d.category != ZYDIS_CATEGORY_INTERRUPT )
            {
                pending.push_back( next );
            }
        }
        std::sort( out.begin( ), out.end( ), [ ]( const xfer& a, const xfer& b ) { return a.rva < b.rva; } );
        return out;
    }

    auto match_push( const runtime_image& img, std::uint32_t rva ) -> bool
    {
        for ( auto back = 1u; back <= 4 && back <= rva; ++back )
        {
            const auto d = decode_at( img, rva - back );
            if ( d.ok && d.len == back && d.mnemonic == ZYDIS_MNEMONIC_PUSH && d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER )
                return true;
        }
        return false;
    }

    auto push_rva( const runtime_image& img, std::uint32_t rva ) -> std::uint32_t
    {
        for ( auto back = 1u; back <= 4 && back <= rva; ++back )
        {
            const auto d = decode_at( img, rva - back );
            if ( d.ok && d.len == back && d.mnemonic == ZYDIS_MNEMONIC_PUSH && d.op_count && d.ops[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER )
                return rva - back;
        }
        return rva;
    }

    auto match_setup( const runtime_image& img, std::uint32_t rva, std::uint8_t dest_reg ) -> bool
    {
        for ( auto back = 1u; back <= 4 && back <= rva; ++back )
        {
            const auto d = decode_at( img, rva - back );
            if ( !d.ok || d.len != back || !d.op_count || d.ops[ 0 ].type != ZYDIS_OPERAND_TYPE_REGISTER )
                continue;
            const auto r = zy_reg( d.ops[ 0 ].reg.value );
            if ( d.mnemonic == ZYDIS_MNEMONIC_POP && r == dest_reg )
                return true;
            if ( d.mnemonic == ZYDIS_MNEMONIC_PUSH && r != dest_reg )
                return true;
        }
        return false;
    }

    auto setup_rva( const runtime_image& img, std::uint32_t rva, std::uint8_t dest_reg ) -> std::uint32_t
    {
        for ( auto back = 1u; back <= 4 && back <= rva; ++back )
        {
            const auto d = decode_at( img, rva - back );
            if ( !d.ok || d.len != back || !d.op_count || d.ops[ 0 ].type != ZYDIS_OPERAND_TYPE_REGISTER )
                continue;
            const auto r = zy_reg( d.ops[ 0 ].reg.value );
            if ( d.mnemonic == ZYDIS_MNEMONIC_POP && r == dest_reg )
                return rva - back;
            if ( d.mnemonic == ZYDIS_MNEMONIC_PUSH && r != dest_reg )
                return rva - back;
        }
        return rva;
    }

    auto looks_like_vm_enter( const runtime_image& img, std::uint32_t rva ) -> bool
    {
        const auto a = decode_at( img, rva );
        if ( !a.ok || a.mnemonic != ZYDIS_MNEMONIC_PUSH )
            return false;
        const auto b = decode_at( img, rva + a.len );
        if ( !b.ok )
            return false;
        if ( b.mnemonic == ZYDIS_MNEMONIC_PUSH )
        {
            const auto c = decode_at( img, rva + a.len + b.len );
            return c.ok && ( c.mnemonic == ZYDIS_MNEMONIC_JMP || c.mnemonic == ZYDIS_MNEMONIC_CALL || c.mnemonic == ZYDIS_MNEMONIC_RET );
        }
        return b.mnemonic == ZYDIS_MNEMONIC_JMP || b.mnemonic == ZYDIS_MNEMONIC_CALL;
    }

    auto classify_stop( const runtime_image& img, const std::vector< vsec >& secs, const xfer& x, const emu_stop& stop, vm_stub& st ) -> bool
    {
        if ( stop.kind == emu_stop_kind::limit || stop.kind == emu_stop_kind::unmapped )
            return false;
        if ( stop.insns > k_max_stub_insns )
            return false;
        if ( in_vm( secs, x.rva ) )
            return false;

        const auto w = img.is64 ? 8 : 4;
        if ( stop.kind == emu_stop_kind::external )
        {
            const auto* exp = pick_export( img, stop.dest );
            if ( !exp )
                return false;
            auto has_resume = false;
            std::uint32_t resume = 0;
            if ( stop.ext_ret >= img.base && stop.ext_ret - img.base < img.bytes.size( ) )
            {
                resume = static_cast< std::uint32_t >( stop.ext_ret - img.base );
                if ( in_vm( secs, resume ) )
                    return false;
                has_resume = true;
            }
            else if ( x.has_ret && stop.sp_delta >= 0 )
            {
                const auto dlt = static_cast< std::size_t >( stop.sp_delta );
                if ( dlt % static_cast< std::size_t >( w ) )
                    return false;
                if ( !( x.jmp || dlt >= static_cast< std::size_t >( w ) ) )
                    return false;
            }
            else
            {
                return false;
            }
            st.dest = stop.dest;
            st.module = exp->module;
            st.name = exp->name;
            st.ordinal = exp->ordinal;
            st.resume = has_resume ? resume : 0;
            auto discard = stop.sp_delta < 0 ? 0ull : static_cast< std::uint64_t >( stop.sp_delta );
            if ( !has_resume && !x.jmp )
            {
                if ( discard < static_cast< std::uint64_t >( w ) )
                    return false;
                discard -= w;
            }
            if ( discard == 0 )
            {
                st.rva = x.rva;
                st.len = has_resume ? ( resume > x.rva ? resume - x.rva : x.len ) : x.len;
            }
            else if ( discard == static_cast< std::uint64_t >( w ) )
            {
                if ( !match_push( img, x.rva ) )
                    return false;
                const auto push = push_rva( img, x.rva );
                st.rva = push;
                st.len = has_resume ? ( resume > push ? resume - push : x.rva + x.len - push ) : ( x.rva + x.len - push );
            }
            else
            {
                return false;
            }
            if ( !st.len || st.len > k_max_patch )
                return false;
            st.type = has_resume ? k_vm_call : k_vm_jmp;
            return true;
        }
        if ( stop.kind == emu_stop_kind::returned )
        {
            const emu_reg* hit = nullptr;
            for ( const auto& r : stop.regs )
            {
                if ( pick_export( img, r.bits ) )
                {
                    if ( hit )
                        return false;
                    hit = &r;
                }
            }
            if ( !hit || !x.has_ret )
                return false;
            const auto* exp = pick_export( img, hit->bits );
            if ( !exp )
                return false;
            st.type = k_vm_mov;
            st.reg = hit->id;
            st.dest = hit->bits;
            st.module = exp->module;
            st.name = exp->name;
            st.ordinal = exp->ordinal;
            st.resume = x.ret;
            if ( !img.is64 && hit->id == 0 )
            {
                st.rva = x.rva;
                st.len = x.ret - x.rva;
            }
            else
            {
                if ( !match_setup( img, x.rva, hit->id ) )
                    return false;
                const auto setup = setup_rva( img, x.rva, hit->id );
                st.rva = setup;
                st.len = x.ret - setup;
            }
            return st.len != 0 && st.len <= k_max_patch;
        }
        return false;
    }

    auto encode_mem( bool is64, std::uint8_t op, std::uint8_t reg, std::uint32_t disp ) -> std::vector< std::uint8_t >
    {
        std::vector< std::uint8_t > b;
        if ( is64 )
        {
            auto rex = 0x40u;
            if ( op == 0x8B )
                rex |= 8;
            if ( reg & 8 )
                rex |= 4;
            if ( rex != 0x40 )
                b.push_back( static_cast< std::uint8_t >( rex ) );
            b.push_back( op );
            b.push_back( static_cast< std::uint8_t >( 0x05 | ( ( reg & 7 ) << 3 ) ) );
        }
        else
        {
            b.push_back( op );
            b.push_back( static_cast< std::uint8_t >( 0x05 | ( ( reg & 7 ) << 3 ) ) );
        }
        b.push_back( static_cast< std::uint8_t >( disp ) );
        b.push_back( static_cast< std::uint8_t >( disp >> 8 ) );
        b.push_back( static_cast< std::uint8_t >( disp >> 16 ) );
        b.push_back( static_cast< std::uint8_t >( disp >> 24 ) );
        return b;
    }

    auto encode_rel_jmp( std::uint32_t from, std::uint32_t to, std::size_t avail ) -> std::vector< std::uint8_t >
    {
        if ( avail >= 2 )
        {
            const auto d = static_cast< std::int64_t >( to ) - static_cast< std::int64_t >( from + 2 );
            if ( d >= INT8_MIN && d <= INT8_MAX )
                return { 0xEB, static_cast< std::uint8_t >( static_cast< std::int8_t >( d ) ) };
        }
        if ( avail >= 5 )
        {
            const auto d = static_cast< std::int64_t >( to ) - static_cast< std::int64_t >( from + 5 );
            if ( d < INT32_MIN || d > INT32_MAX )
                return {};
            const auto rel = static_cast< std::uint32_t >( static_cast< std::int32_t >( d ) );
            return {
                0xE9,
                static_cast< std::uint8_t >( rel ),
                static_cast< std::uint8_t >( rel >> 8 ),
                static_cast< std::uint8_t >( rel >> 16 ),
                static_cast< std::uint8_t >( rel >> 24 )
            };
        }
        return {};
    }
}

auto is_vm_section_name( const char* name ) -> bool
{
    const auto s = lower8( name );
    if ( s.rfind( ".vmp", 0 ) == 0 )
        return true;
    if ( s == ".be0" || s == ".be1" || s == ".byted" )
        return true;
    return false;
}

auto recover_vm_stubs( const runtime_image& img ) -> std::vector< vm_stub >
{
    std::vector< vm_stub > out;
    if ( img.bytes.size( ) < 0x200 || img.exports.empty( ) )
        return out;
    const auto secs = read_secs( img );
    auto have_vm = false;
    for ( const auto& s : secs )
    {
        if ( s.vm )
            have_vm = true;
    }
    if ( !have_vm )
        return out;

    stub_emulator emu( img.is64, img.base, img.bytes );
    const auto xfers = find_xfers( img, secs );
    std::map< std::uint32_t, std::uint32_t > stub_uses;
    for ( const auto& x : xfers )
        ++stub_uses[ x.stub ];
    for ( const auto& x : xfers )
    {
        if ( stub_uses[ x.stub ] >= 2 )
            continue;
        if ( looks_like_vm_enter( img, x.stub ) )
            continue;
        emu_stop stop{};
        try
        {
            stop = emu.emulate( img.base + x.stub, x.has_ret, img.base + x.ret, k_stub_limit );
        }
        catch ( ... )
        {
            continue;
        }
        vm_stub st{};
        if ( !classify_stop( img, secs, x, stop, st ) )
            continue;
        if ( !st.len || st.rva >= img.bytes.size( ) || static_cast< std::size_t >( st.rva ) + st.len > img.bytes.size( ) )
            continue;
        out.push_back( std::move( st ) );
    }
    return out;
}

auto count_vm_stubs( const runtime_image& img ) -> std::size_t
{
    try
    {
        return recover_vm_stubs( img ).size( );
    }
    catch ( ... )
    {
        return 0;
    }
}

auto apply_vm_stubs( runtime_image& img, const std::vector< vm_stub >& stubs, const std::map< std::uint64_t, std::uint32_t >& dest_to_iat ) -> void
{
    for ( const auto& st : stubs )
    {
        const auto it = dest_to_iat.find( st.dest );
        if ( it == dest_to_iat.end( ) )
            continue;
        if ( !st.len || static_cast< std::size_t >( st.rva ) + st.len > img.bytes.size( ) )
            continue;
        const auto slot_va = img.base + it->second;
        std::vector< std::uint8_t > bytes;
        if ( st.type == k_vm_mov )
        {
            std::uint32_t disp = 0;
            if ( img.is64 )
            {
                const auto next = img.base + st.rva + 7;
                const auto d = static_cast< std::int64_t >( slot_va ) - static_cast< std::int64_t >( next );
                if ( d < INT32_MIN || d > INT32_MAX )
                    continue;
                disp = static_cast< std::uint32_t >( static_cast< std::int32_t >( d ) );
            }
            else
            {
                if ( slot_va > 0xffffffffull )
                    continue;
                disp = static_cast< std::uint32_t >( slot_va );
            }
            bytes = encode_mem( img.is64, 0x8B, st.reg, disp );
        }
        else
        {
            const auto ff_reg = st.type == k_vm_jmp ? static_cast< std::uint8_t >( 4 ) : static_cast< std::uint8_t >( 2 );
            std::uint32_t disp = 0;
            if ( img.is64 )
            {
                const auto next = img.base + st.rva + 6;
                const auto d = static_cast< std::int64_t >( slot_va ) - static_cast< std::int64_t >( next );
                if ( d < INT32_MIN || d > INT32_MAX )
                    continue;
                disp = static_cast< std::uint32_t >( static_cast< std::int32_t >( d ) );
            }
            else
            {
                if ( slot_va > 0xffffffffull )
                    continue;
                disp = static_cast< std::uint32_t >( slot_va );
            }
            bytes = encode_mem( img.is64, 0xFF, ff_reg, disp );
        }
        if ( bytes.empty( ) || bytes.size( ) > st.len )
            continue;
        if ( st.resume && st.resume != st.rva + static_cast< std::uint32_t >( bytes.size( ) ) )
        {
            const auto remain = static_cast< std::size_t >( st.len ) - bytes.size( );
            auto jmp = encode_rel_jmp( st.rva + static_cast< std::uint32_t >( bytes.size( ) ), st.resume, remain );
            if ( jmp.empty( ) )
                continue;
            bytes.insert( bytes.end( ), jmp.begin( ), jmp.end( ) );
            if ( bytes.size( ) > st.len )
                continue;
        }
        std::memcpy( img.bytes.data( ) + st.rva, bytes.data( ), bytes.size( ) );
    }
}