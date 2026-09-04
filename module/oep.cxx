#include "oep.hxx"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <cstring>
#include <vector>

namespace
{
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

    auto read_u64( const std::uint8_t* p ) -> std::uint64_t
    {
        std::uint64_t v;
        std::memcpy( &v, p, sizeof( v ) );
        return v;
    }

    auto write_u32( std::uint8_t* p, std::uint32_t v ) -> void
    {
        std::memcpy( p, &v, sizeof( v ) );
    }

    auto opt_off( const std::vector< std::uint8_t >& image ) -> std::uint32_t
    {
        if ( image.size( ) < 0x40 )
            return 0;
        const auto nt = read_u32( image.data( ) + 0x3c );
        if ( nt + 24 + 18 >= image.size( ) )
            return 0;
        return nt + 4 + static_cast< std::uint32_t >( sizeof( IMAGE_FILE_HEADER ) );
    }

    auto in_image( const std::vector< std::uint8_t >& image, std::uint32_t rva, std::uint32_t need ) -> bool
    {
        return rva < image.size( ) && image.size( ) - rva >= need;
    }

    auto rel32( const std::uint8_t* p, std::uint32_t rva, std::uint32_t insn_len ) -> std::uint32_t
    {
        const auto rel = static_cast< std::int32_t >( read_u32( p ) );
        return static_cast< std::uint32_t >( static_cast< std::int64_t >( rva ) + insn_len + rel );
    }

    struct range
    {
        std::uint32_t begin;
        std::uint32_t end;
    };

    auto exec_ranges( const std::vector< std::uint8_t >& image ) -> std::vector< range >
    {
        std::vector< range > out;
        if ( image.size( ) < 0x40 )
            return out;
        const auto nt = read_u32( image.data( ) + 0x3c );
        const auto file = nt + 4;
        if ( file + 20 >= image.size( ) )
            return out;
        const auto section_count = read_u16( image.data( ) + file + 2 );
        const auto opt_size = read_u16( image.data( ) + file + 16 );
        const auto section_off = file + static_cast< std::uint32_t >( sizeof( IMAGE_FILE_HEADER ) ) + opt_size;
        for ( std::uint16_t i = 0; i < section_count; ++i )
        {
            const auto off = section_off + i * 40u;
            if ( off + 40 > image.size( ) )
                break;
            if ( !( read_u32( image.data( ) + off + 36 ) & IMAGE_SCN_MEM_EXECUTE ) )
                continue;
            const auto va = read_u32( image.data( ) + off + 12 );
            const auto vsize = read_u32( image.data( ) + off + 8 );
            const auto raw = read_u32( image.data( ) + off + 16 );
            const auto span = vsize > raw ? vsize : raw;
            if ( !span || va >= image.size( ) )
                continue;
            range r{};
            r.begin = va;
            r.end = static_cast< std::uint32_t >( ( std::min )( image.size( ), static_cast< std::size_t >( va ) + span ) );
            out.push_back( r );
        }
        return out;
    }

    auto executable( const std::vector< range >& ranges, std::uint32_t rva ) -> bool
    {
        for ( const auto& r : ranges )
        {
            if ( rva >= r.begin && rva < r.end )
                return true;
        }
        return false;
    }

    auto contains_u64( const std::uint8_t* p, std::size_t n, std::uint64_t v ) -> bool
    {
        if ( n < 8 )
            return false;
        for ( std::size_t i = 0; i + 8 <= n; ++i )
        {
            if ( read_u64( p + i ) == v )
                return true;
        }
        return false;
    }

    auto is_security_cookie64( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 32 )
            return false;
        return contains_u64( p, ( std::min )( n, static_cast< std::size_t >( 64 ) ), 0x00002B992DDFA232ull );
    }

    auto is_scrt_seh64( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 27 )
            return false;
        if ( p[ 0 ] != 0x48 || p[ 1 ] != 0x89 || p[ 2 ] != 0x5C || p[ 3 ] != 0x24 || p[ 4 ] != 0x08 )
            return false;
        if ( p[ 5 ] != 0x48 || p[ 6 ] != 0x89 || p[ 7 ] != 0x74 || p[ 8 ] != 0x24 || p[ 9 ] != 0x10 )
            return false;
        if ( p[ 10 ] != 0x57 )
            return false;
        if ( p[ 11 ] != 0x48 || p[ 12 ] != 0x83 || p[ 13 ] != 0xEC )
            return false;
        if ( p[ 15 ] != 0xB9 || p[ 16 ] != 0x01 || p[ 17 ] != 0x00 || p[ 18 ] != 0x00 || p[ 19 ] != 0x00 )
            return false;
        if ( p[ 20 ] != 0xE8 )
            return false;
        return p[ 25 ] == 0x84 && p[ 26 ] == 0xC0;
    }

    auto is_user_main64( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 16 )
            return false;
        for ( std::size_t i = 0; i + 5 < ( std::min )( n, static_cast< std::size_t >( 24 ) ); ++i )
        {
            if ( p[ i ] == 0x48 && p[ i + 1 ] == 0x33 && p[ i + 2 ] == 0xC4 )
                return true;
        }
        return false;
    }

    auto is_main_crt64( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 18 )
            return false;
        if ( p[ 0 ] != 0x48 || p[ 1 ] != 0x83 || p[ 2 ] != 0xEC || p[ 3 ] != 0x28 )
            return false;
        if ( p[ 4 ] != 0xE8 )
            return false;
        if ( p[ 9 ] != 0x48 || p[ 10 ] != 0x83 || p[ 11 ] != 0xC4 || p[ 12 ] != 0x28 )
            return false;
        if ( p[ 13 ] != 0xE9 )
            return false;
        if ( n >= 19 && p[ 18 ] != 0xCC && p[ 18 ] != 0x90 && p[ 18 ] != 0x00 )
            return false;
        return true;
    }

    auto is_security_cookie32( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 16 )
            return false;
        return contains_u64( p, ( std::min )( n, static_cast< std::size_t >( 48 ) ), 0x00002B992DDFA232ull )
            || ( n >= 8 && read_u32( p ) != 0 && p[ 0 ] == 0xA1 );
    }

    auto is_scrt_seh32( const std::uint8_t* p, std::size_t n ) -> bool
    {
        if ( n < 8 )
            return false;
        if ( p[ 0 ] != 0x55 || p[ 1 ] != 0x8B || p[ 2 ] != 0xEC )
            return false;
        return ( p[ 3 ] == 0x6A && p[ 4 ] == 0xFF && p[ 5 ] == 0x68 )
            || ( p[ 3 ] == 0x83 && p[ 4 ] == 0xEC );
    }

    auto valid_stub64( const std::vector< std::uint8_t >& image, const std::vector< range >& ranges, std::uint32_t rva ) -> bool
    {
        if ( !in_image( image, rva, 18 ) || !is_main_crt64( image.data( ) + rva, image.size( ) - rva ) )
            return false;
        if ( is_user_main64( image.data( ) + rva, image.size( ) - rva ) )
            return false;
        const auto call = rel32( image.data( ) + rva + 5, rva, 9 );
        const auto jmp = rel32( image.data( ) + rva + 14, rva, 18 );
        if ( call == jmp || call == rva || jmp == rva )
            return false;
        if ( !executable( ranges, call ) || !executable( ranges, jmp ) )
            return false;
        if ( !in_image( image, call, 32 ) || !in_image( image, jmp, 32 ) )
            return false;
        if ( is_user_main64( image.data( ) + jmp, image.size( ) - jmp ) )
            return false;
        if ( !is_security_cookie64( image.data( ) + call, image.size( ) - call ) )
            return false;
        return is_scrt_seh64( image.data( ) + jmp, image.size( ) - jmp );
    }

    auto valid_stub32( const std::vector< std::uint8_t >& image, const std::vector< range >& ranges, std::uint32_t rva ) -> bool
    {
        if ( !in_image( image, rva, 10 ) )
            return false;
        const auto* p = image.data( ) + rva;
        if ( p[ 0 ] != 0xE8 || p[ 5 ] != 0xE9 )
            return false;
        const auto call = rel32( p + 1, rva, 5 );
        const auto jmp = rel32( p + 6, rva, 10 );
        if ( call == jmp || !executable( ranges, call ) || !executable( ranges, jmp ) )
            return false;
        if ( !in_image( image, call, 16 ) || !in_image( image, jmp, 16 ) )
            return false;
        return is_scrt_seh32( image.data( ) + jmp, image.size( ) - jmp );
    }

    auto follow_jmps( const std::vector< std::uint8_t >& image, std::uint32_t rva ) -> std::uint32_t
    {
        auto cur = rva;
        for ( auto i = 0; i < 8; ++i )
        {
            if ( !in_image( image, cur, 5 ) )
                break;
            auto skip = 0u;
            while ( skip < 8 && in_image( image, cur + skip, 1 ) )
            {
                const auto b = image[ cur + skip ];
                if ( b == 0x90 || b == 0xCC )
                    ++skip;
                else
                    break;
            }
            if ( !in_image( image, cur + skip, 5 ) )
                break;
            const auto* p = image.data( ) + cur + skip;
            if ( p[ 0 ] == 0xE9 )
            {
                cur = rel32( p + 1, cur + skip, 5 );
                continue;
            }
            if ( p[ 0 ] == 0xEB && in_image( image, cur + skip, 2 ) )
            {
                cur = static_cast< std::uint32_t >( static_cast< std::int64_t >( cur + skip + 2 ) + static_cast< std::int8_t >( p[ 1 ] ) );
                continue;
            }
            break;
        }
        return cur;
    }

    auto scan_stubs( const std::vector< std::uint8_t >& image, bool is64 ) -> std::uint32_t
    {
        const auto ranges = exec_ranges( image );
        std::uint32_t aligned = 0;
        std::uint32_t any = 0;
        for ( const auto& r : ranges )
        {
            const auto need = is64 ? 18u : 10u;
            if ( r.end <= r.begin + need )
                continue;
            for ( auto rva = r.begin; rva + need <= r.end; ++rva )
            {
                const auto ok = is64 ? valid_stub64( image, ranges, rva ) : valid_stub32( image, ranges, rva );
                if ( !ok )
                    continue;
                if ( ( rva & 0xF ) == 0 )
                {
                    if ( !aligned )
                        aligned = rva;
                }
                else if ( !any )
                {
                    any = rva;
                }
            }
        }
        return aligned ? aligned : any;
    }
}

auto find_oep( const std::vector< std::uint8_t >& image, bool is64 ) -> std::uint32_t
{
    const auto opt = opt_off( image );
    if ( !opt )
        return 0;
    const auto current = read_u32( image.data( ) + opt + 16 );
    const auto ranges = exec_ranges( image );
    const auto landed = follow_jmps( image, current );
    if ( is64 )
    {
        if ( valid_stub64( image, ranges, landed ) )
            return landed;
        if ( valid_stub64( image, ranges, current ) )
            return current;
    }
    else
    {
        if ( valid_stub32( image, ranges, landed ) )
            return landed;
        if ( valid_stub32( image, ranges, current ) )
            return current;
    }
    const auto scanned = scan_stubs( image, is64 );
    return scanned ? scanned : current;
}

auto apply_oep( std::vector< std::uint8_t >& image, std::uint32_t oep ) -> void
{
    const auto opt = opt_off( image );
    if ( !opt || !oep )
        return;
    write_u32( image.data( ) + opt + 16, oep );
}
