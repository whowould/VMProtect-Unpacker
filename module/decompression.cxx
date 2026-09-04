#include "decompression.hxx"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace
{
    constexpr auto k_lzma_props = 5u;
    constexpr auto k_num_states = 12u;
    constexpr auto k_num_pos_bits_max = 4u;
    constexpr auto k_num_pos_states_max = 1u << k_num_pos_bits_max;
    constexpr auto k_num_lit_states = 7u;
    constexpr auto k_len_num_low_bits = 3u;
    constexpr auto k_len_num_mid_bits = 3u;
    constexpr auto k_len_num_high_bits = 8u;
    constexpr auto k_len_num_low_symbols = 1u << k_len_num_low_bits;
    constexpr auto k_len_num_mid_symbols = 1u << k_len_num_mid_bits;
    constexpr auto k_len_num_high_symbols = 1u << k_len_num_high_bits;
    constexpr auto k_match_min_len = 2u;
    constexpr auto k_num_len_to_pos_states = 4u;
    constexpr auto k_num_pos_slot_bits = 6u;
    constexpr auto k_start_pos_model_index = 4u;
    constexpr auto k_end_pos_model_index = 14u;
    constexpr auto k_num_full_distances = 1u << ( k_end_pos_model_index >> 1u );
    constexpr auto k_num_align_bits = 4u;
    constexpr auto k_align_table_size = 1u << k_num_align_bits;
    constexpr auto k_lit_size = 0x300u;
    constexpr auto k_top_value = 1u << 24u;
    constexpr auto k_bit_model_total = 1u << 11u;
    constexpr auto k_prob_init = k_bit_model_total >> 1u;
    constexpr auto k_num_move_bits = 5u;

    constexpr auto k_len_choice = 0u;
    constexpr auto k_len_choice2 = 1u;
    constexpr auto k_len_low = 2u;
    constexpr auto k_len_mid = k_len_low + ( k_num_pos_states_max << k_len_num_low_bits );
    constexpr auto k_len_high = k_len_mid + ( k_num_pos_states_max << k_len_num_mid_bits );
    constexpr auto k_num_len_probs = k_len_high + k_len_num_high_symbols;

    constexpr auto k_is_match = 0u;
    constexpr auto k_is_rep = k_is_match + ( k_num_states << k_num_pos_bits_max );
    constexpr auto k_is_rep_g0 = k_is_rep + k_num_states;
    constexpr auto k_is_rep_g1 = k_is_rep_g0 + k_num_states;
    constexpr auto k_is_rep_g2 = k_is_rep_g1 + k_num_states;
    constexpr auto k_is_rep0_long = k_is_rep_g2 + k_num_states;
    constexpr auto k_pos_slot = k_is_rep0_long + ( k_num_states << k_num_pos_bits_max );
    constexpr auto k_spec_pos = k_pos_slot + ( k_num_len_to_pos_states << k_num_pos_slot_bits );
    constexpr auto k_align = k_spec_pos + k_num_full_distances - k_end_pos_model_index;
    constexpr auto k_len_coder = k_align + k_align_table_size;
    constexpr auto k_rep_len_coder = k_len_coder + k_num_len_probs;
    constexpr auto k_literal = k_rep_len_coder + k_num_len_probs;
    constexpr auto k_base_probs = k_literal;

#pragma pack( push, 1 )
    struct packer_info
    {
        std::uint32_t src;
        std::uint32_t dst;
    };
#pragma pack( pop )

    auto hex( std::uint64_t v ) -> std::string
    {
        char buf[ 32 ];
        std::snprintf( buf, sizeof( buf ), "0x%llx", static_cast< unsigned long long >( v ) );
        return buf;
    }

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

    auto write_u32( std::uint8_t* p, std::uint32_t v ) -> void
    {
        std::memcpy( p, &v, sizeof( v ) );
    }

    auto find_pattern( const std::uint8_t* data, std::size_t n, const std::uint8_t* pat, std::size_t m ) -> std::ptrdiff_t
    {
        if ( !m || n < m )
            return -1;

        for ( std::size_t i = 0; i + m <= n; ++i )
        {
            auto hit = true;
            for ( std::size_t j = 0; j < m; ++j )
            {
                if ( pat[ j ] != 0xFF && data[ i + j ] != pat[ j ] )
                {
                    hit = false;
                    break;
                }
            }

            if ( hit )
                return static_cast< std::ptrdiff_t >( i );
        }

        return -1;
    }

    struct pe_view
    {
        const std::uint8_t* data;
        std::size_t size;
        const IMAGE_FILE_HEADER* file;
        const IMAGE_SECTION_HEADER* sections;
        std::uint32_t section_count;
        std::uint32_t size_of_image;
        std::uint32_t size_of_headers;
        std::uint32_t section_table_off;
        std::uint16_t magic;
    };

    auto parse_pe( const std::vector< std::uint8_t >& packed ) -> pe_view
    {
        if ( packed.size( ) < sizeof( IMAGE_DOS_HEADER ) )
            throw std::runtime_error( "Invalid PE file format: truncated DOS header" );

        const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( packed.data( ) );
        if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
            throw std::runtime_error( "Invalid PE file format: bad DOS signature" );

        const auto nt_off = static_cast< std::uint32_t >( dos->e_lfanew );
        if ( nt_off < sizeof( IMAGE_DOS_HEADER ) || packed.size( ) < static_cast< std::size_t >( nt_off ) + 4 + sizeof( IMAGE_FILE_HEADER ) + 2 )
            throw std::runtime_error( "Invalid PE file format: truncated NT headers" );

        if ( read_u32( packed.data( ) + nt_off ) != IMAGE_NT_SIGNATURE )
            throw std::runtime_error( "Invalid PE file format: bad NT signature" );

        const auto file = reinterpret_cast< const IMAGE_FILE_HEADER* >( packed.data( ) + nt_off + 4 );
        const auto opt_off = nt_off + 4 + static_cast< std::uint32_t >( sizeof( IMAGE_FILE_HEADER ) );
        const auto opt_size = file->SizeOfOptionalHeader;
        if ( !opt_size || packed.size( ) < static_cast< std::size_t >( opt_off ) + opt_size )
            throw std::runtime_error( "Invalid PE file format: truncated optional header" );

        const auto magic = read_u16( packed.data( ) + opt_off );
        std::uint32_t size_of_image = 0;
        std::uint32_t size_of_headers = 0;

        if ( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
        {
            if ( opt_size < sizeof( IMAGE_OPTIONAL_HEADER32 ) )
                throw std::runtime_error( "Invalid PE file format: optional header too small" );

            const auto opt = reinterpret_cast< const IMAGE_OPTIONAL_HEADER32* >( packed.data( ) + opt_off );
            size_of_image = opt->SizeOfImage;
            size_of_headers = opt->SizeOfHeaders;
        }
        else if ( magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
        {
            if ( opt_size < sizeof( IMAGE_OPTIONAL_HEADER64 ) )
                throw std::runtime_error( "Invalid PE file format: optional header too small" );

            const auto opt = reinterpret_cast< const IMAGE_OPTIONAL_HEADER64* >( packed.data( ) + opt_off );
            size_of_image = opt->SizeOfImage;
            size_of_headers = opt->SizeOfHeaders;
        }
        else
        {
            throw std::runtime_error( "Invalid PE file format: unknown optional header magic" );
        }

        const auto section_off = opt_off + opt_size;
        const auto section_count = static_cast< std::uint32_t >( file->NumberOfSections );
        if ( packed.size( ) < static_cast< std::size_t >( section_off ) + section_count * sizeof( IMAGE_SECTION_HEADER ) )
            throw std::runtime_error( "Invalid PE file format: truncated section table" );

        if ( !size_of_image || size_of_headers > packed.size( ) || size_of_headers > size_of_image )
            throw std::runtime_error( "Invalid PE file format: bad SizeOfImage / SizeOfHeaders" );

        pe_view pe{};
        pe.data = packed.data( );
        pe.size = packed.size( );
        pe.file = file;
        pe.sections = reinterpret_cast< const IMAGE_SECTION_HEADER* >( packed.data( ) + section_off );
        pe.section_count = section_count;
        pe.size_of_image = size_of_image;
        pe.size_of_headers = size_of_headers;
        pe.section_table_off = section_off;
        pe.magic = magic;
        return pe;
    }

    auto rva_to_offset( const pe_view& pe, std::uint32_t rva ) -> std::uint32_t
    {
        for ( std::uint32_t i = 0; i < pe.section_count; ++i )
        {
            const auto& s = pe.sections[ i ];
            const auto span = ( std::max )( s.Misc.VirtualSize, s.SizeOfRawData );
            if ( !span )
                continue;

            if ( rva >= s.VirtualAddress && rva < s.VirtualAddress + span )
                return s.PointerToRawData + ( rva - s.VirtualAddress );
        }

        if ( rva < pe.size_of_headers )
            return rva;

        throw std::runtime_error( "Cannot convert RVA to file offset: " + hex( rva ) );
    }

    auto section_name( const IMAGE_SECTION_HEADER& s ) -> std::string
    {
        char name[ 9 ]{};
        std::memcpy( name, s.Name, 8 );
        return name;
    }

    struct lzma_dec
    {
        const std::uint8_t* in;
        const std::uint8_t* in_end;
        std::uint32_t range;
        std::uint32_t code;
        std::vector< std::uint16_t > probs;

        auto read_byte( ) -> std::uint8_t
        {
            if ( in >= in_end )
                throw std::runtime_error( "LZMA decompression error: truncated input" );
            return *in++;
        }

        auto normalize( ) -> void
        {
            while ( range < k_top_value )
            {
                range <<= 8;
                code = ( code << 8 ) | read_byte( );
            }
        }

        auto bit( std::uint16_t* p ) -> unsigned
        {
            const auto bound = ( range >> 11 ) * *p;
            if ( code < bound )
            {
                range = bound;
                *p = static_cast< std::uint16_t >( *p + ( ( k_bit_model_total - *p ) >> k_num_move_bits ) );
                normalize( );
                return 0;
            }

            range -= bound;
            code -= bound;
            *p = static_cast< std::uint16_t >( *p - ( *p >> k_num_move_bits ) );
            normalize( );
            return 1;
        }

        auto bit_tree( std::uint16_t* p, unsigned bits ) -> unsigned
        {
            unsigned m = 1;
            for ( unsigned i = 0; i < bits; ++i )
                m = ( m << 1 ) | bit( p + m );
            return m - ( 1u << bits );
        }

        auto rev_bit_tree( std::uint16_t* p, unsigned bits ) -> unsigned
        {
            unsigned m = 1;
            unsigned sym = 0;
            for ( unsigned i = 0; i < bits; ++i )
            {
                const auto b = bit( p + m );
                m = ( m << 1 ) | b;
                sym |= b << i;
            }
            return sym;
        }

        auto direct( unsigned n ) -> std::uint32_t
        {
            std::uint32_t v = 0;
            do
            {
                range >>= 1;
                code -= range;
                const auto t = 0u - ( code >> 31 );
                code += range & t;
                v = ( v << 1 ) + ( t + 1 );
                normalize( );
            } while ( --n );

            return v;
        }

        auto len( std::uint16_t* p, unsigned pos_state ) -> unsigned
        {
            if ( !bit( p + k_len_choice ) )
                return bit_tree( p + k_len_low + ( pos_state << k_len_num_low_bits ), k_len_num_low_bits );

            if ( !bit( p + k_len_choice2 ) )
                return k_len_num_low_symbols + bit_tree( p + k_len_mid + ( pos_state << k_len_num_mid_bits ), k_len_num_mid_bits );

            return k_len_num_low_symbols + k_len_num_mid_symbols + bit_tree( p + k_len_high, k_len_num_high_bits );
        }
    };

    auto lzma_decompress(
        const std::uint8_t* props,
        std::size_t props_size,
        const std::uint8_t* src,
        std::size_t src_size,
        std::size_t max_out ) -> std::vector< std::uint8_t >
    {
        if ( props_size < 1 )
            throw std::runtime_error( "LZMA decompression error: missing properties" );

        const auto d = props[ 0 ];
        if ( d >= ( 9 * 5 * 5 ) )
            throw std::runtime_error( "LZMA decompression error: bad properties byte" );

        const auto lc = d % 9;
        const auto lp = ( d / 9 ) % 5;
        const auto pb = d / 45;

        std::uint32_t dict_size = 0;
        if ( props_size >= k_lzma_props )
            dict_size = read_u32( props + 1 );
        if ( dict_size < ( 1u << 12 ) )
            dict_size = 1u << 12;

        ( void )dict_size;

        if ( src_size < 5 )
            throw std::runtime_error( "LZMA decompression error: truncated stream" );

        lzma_dec dec{};
        dec.in = src;
        dec.in_end = src + src_size;
        dec.range = 0xFFFFFFFFu;
        dec.code = 0;

        const auto first = dec.read_byte( );
        if ( first )
            throw std::runtime_error( "LZMA decompression error: bad range coder marker" );

        for ( int i = 0; i < 4; ++i )
            dec.code = ( dec.code << 8 ) | dec.read_byte( );

        const auto lit_count = k_lit_size << ( lc + lp );
        dec.probs.assign( k_base_probs + lit_count, static_cast< std::uint16_t >( k_prob_init ) );

        const auto pos_mask = ( 1u << pb ) - 1u;
        const auto lp_mask = ( 1u << lp ) - 1u;

        std::vector< std::uint8_t > out;
        out.reserve( ( std::min )( max_out, static_cast< std::size_t >( 1u << 20 ) ) );

        unsigned state = 0;
        std::uint32_t rep0 = 1, rep1 = 1, rep2 = 1, rep3 = 1;
        auto prev = 0u;

        while ( out.size( ) < max_out )
        {
            const auto pos_state = static_cast< unsigned >( out.size( ) ) & pos_mask;
            auto* probs = dec.probs.data( );

            if ( !dec.bit( probs + k_is_match + ( state << k_num_pos_bits_max ) + pos_state ) )
            {
                auto* lit = probs + k_literal + ( k_lit_size * ( ( ( static_cast< unsigned >( out.size( ) ) & lp_mask ) << lc ) + ( prev >> ( 8u - lc ) ) ) );

                unsigned sym = 1;
                if ( state < k_num_lit_states )
                {
                    do
                    {
                        sym = ( sym << 1 ) | dec.bit( lit + sym );
                    } while ( sym < 0x100 );
                }
                else
                {
                    if ( rep0 > out.size( ) )
                        throw std::runtime_error( "LZMA decompression error: bad match distance" );

                    auto match_byte = out[ out.size( ) - rep0 ];
                    do
                    {
                        const auto match_bit = ( match_byte >> 7 ) & 1u;
                        match_byte = static_cast< std::uint8_t >( match_byte << 1 );
                        const auto bit = dec.bit( lit + ( ( 1u + match_bit ) << 8 ) + sym );
                        sym = ( sym << 1 ) | bit;
                        if ( match_bit != bit )
                        {
                            while ( sym < 0x100 )
                                sym = ( sym << 1 ) | dec.bit( lit + sym );
                            break;
                        }
                    } while ( sym < 0x100 );
                }

                const auto b = static_cast< std::uint8_t >( sym );
                out.push_back( b );
                prev = b;
                state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
                continue;
            }

            unsigned len = 0;
            if ( !dec.bit( probs + k_is_rep + state ) )
            {
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;

                len = k_match_min_len + dec.len( probs + k_len_coder, pos_state );
                state = state < k_num_lit_states ? 7 : 10;

                auto lps = len - k_match_min_len;
                if ( lps >= k_num_len_to_pos_states )
                    lps = k_num_len_to_pos_states - 1;

                const auto slot = dec.bit_tree( probs + k_pos_slot + ( lps << k_num_pos_slot_bits ), k_num_pos_slot_bits );
                std::uint32_t dist;
                if ( slot < k_start_pos_model_index )
                {
                    dist = slot;
                }
                else
                {
                    const auto direct_bits = ( slot >> 1 ) - 1;
                    dist = ( 2u | ( slot & 1u ) ) << direct_bits;
                    if ( slot < k_end_pos_model_index )
                    {
                        dist += dec.rev_bit_tree( probs + k_spec_pos + dist - slot - 1, direct_bits );
                    }
                    else
                    {
                        dist += dec.direct( direct_bits - k_num_align_bits ) << k_num_align_bits;
                        dist += dec.rev_bit_tree( probs + k_align, k_num_align_bits );
                    }
                }

                if ( dist == 0xFFFFFFFFu )
                    break;

                rep0 = dist + 1;
            }
            else
            {
                if ( !out.size( ) )
                    throw std::runtime_error( "LZMA decompression error: rep match at start" );

                if ( !dec.bit( probs + k_is_rep_g0 + state ) )
                {
                    if ( !dec.bit( probs + k_is_rep0_long + ( state << k_num_pos_bits_max ) + pos_state ) )
                    {
                        if ( rep0 > out.size( ) )
                            throw std::runtime_error( "LZMA decompression error: bad short-rep distance" );

                        const auto b = out[ out.size( ) - rep0 ];
                        out.push_back( b );
                        prev = b;
                        state = state < k_num_lit_states ? 9 : 11;
                        continue;
                    }
                }
                else
                {
                    std::uint32_t dist;
                    if ( !dec.bit( probs + k_is_rep_g1 + state ) )
                    {
                        dist = rep1;
                    }
                    else
                    {
                        if ( !dec.bit( probs + k_is_rep_g2 + state ) )
                        {
                            dist = rep2;
                        }
                        else
                        {
                            dist = rep3;
                            rep3 = rep2;
                        }
                        rep2 = rep1;
                    }
                    rep1 = rep0;
                    rep0 = dist;
                }

                len = k_match_min_len + dec.len( probs + k_rep_len_coder, pos_state );
                state = state < k_num_lit_states ? 8 : 11;
            }

            if ( !rep0 || rep0 > out.size( ) )
                throw std::runtime_error( "LZMA decompression error: bad match distance" );

            if ( out.size( ) + len > max_out )
                len = static_cast< unsigned >( max_out - out.size( ) );

            for ( unsigned i = 0; i < len; ++i )
            {
                const auto b = out[ out.size( ) - rep0 ];
                out.push_back( b );
                prev = b;
            }
        }

        return out;
    }
}

auto unpack_pe( const std::vector< std::uint8_t >& packed ) -> std::vector< std::uint8_t >
{
    if ( packed.empty( ) )
        throw std::runtime_error( "Packed PE data is null or empty." );

    const auto pe = parse_pe( packed );

    std::vector< std::uint8_t > image( pe.size_of_image );
    std::memcpy( image.data( ), packed.data( ), pe.size_of_headers );

    std::vector< std::uint8_t > rva_pat;
    rva_pat.reserve( pe.section_count * 8 );

    for ( std::uint32_t i = 0; i < pe.section_count; ++i )
    {
        const auto& s = pe.sections[ i ];
        if ( s.SizeOfRawData )
            continue;
        if ( s.PointerToRawData )
            continue;
        if ( s.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
            continue;

        const auto va = s.VirtualAddress;
        rva_pat.insert( rva_pat.end( ), { 0xFF, 0xFF, 0xFF, 0xFF } );
        rva_pat.push_back( static_cast< std::uint8_t >( va ) );
        rva_pat.push_back( static_cast< std::uint8_t >( va >> 8 ) );
        rva_pat.push_back( static_cast< std::uint8_t >( va >> 16 ) );
        rva_pat.push_back( static_cast< std::uint8_t >( va >> 24 ) );
    }

    std::vector< packer_info > infos;
    if ( !rva_pat.empty( ) )
    {
        const auto pos = find_pattern( packed.data( ), packed.size( ), rva_pat.data( ), rva_pat.size( ) );
        if ( pos < 0 )
            throw std::runtime_error( "RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected." );

        if ( pos < 8 )
            throw std::runtime_error( "Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0]." );

        const auto n = static_cast< std::size_t >( rva_pat.size( ) / 8 );
        const auto off = static_cast< std::size_t >( pos ) - 8;
        if ( off + ( n + 1 ) * sizeof( packer_info ) > packed.size( ) )
            throw std::runtime_error( "Located PACKER_INFO array extends beyond packed PE buffer or has invalid start." );

        infos.resize( n + 1 );
        std::memcpy( infos.data( ), packed.data( ) + off, ( n + 1 ) * sizeof( packer_info ) );
    }
    else
    {
        std::printf( "Warning: RVA pattern array is empty. No PACKER_INFO entries to process for LZMA.\n" );
    }

    for ( std::uint32_t i = 0; i < pe.section_count; ++i )
    {
        const auto& s = pe.sections[ i ];
        const auto name = section_name( s );

        if ( s.PointerToRawData && s.SizeOfRawData )
        {
            const auto raw_end = static_cast< std::uint64_t >( s.PointerToRawData ) + s.SizeOfRawData;
            const auto va_end = static_cast< std::uint64_t >( s.VirtualAddress ) + s.SizeOfRawData;
            if ( raw_end <= packed.size( ) && va_end <= pe.size_of_image )
            {
                std::memcpy( image.data( ) + s.VirtualAddress, packed.data( ) + s.PointerToRawData, s.SizeOfRawData );
            }
            else
            {
                std::printf(
                    "Warning: Section %s data exceeds boundaries. RawOffset=%s, RawSize=%s, VA=%s. Skipping copy.\n",
                    name.c_str( ),
                    hex( s.PointerToRawData ).c_str( ),
                    hex( s.SizeOfRawData ).c_str( ),
                    hex( s.VirtualAddress ).c_str( ) );
            }
        }

        const auto hdr = pe.section_table_off + i * static_cast< std::uint32_t >( sizeof( IMAGE_SECTION_HEADER ) );
        if ( hdr + sizeof( IMAGE_SECTION_HEADER ) <= image.size( ) )
        {
            write_u32( image.data( ) + hdr + 20, s.VirtualAddress );
            if ( s.Misc.VirtualSize )
                write_u32( image.data( ) + hdr + 16, s.Misc.VirtualSize );
        }
    }

    if ( infos.size( ) > 1 )
    {
        const auto& props_info = infos[ 0 ];
        const auto props_off = rva_to_offset( pe, props_info.src );
        const auto props_size = props_info.dst;

        if ( static_cast< std::uint64_t >( props_off ) + props_size > packed.size( ) )
        {
            throw std::runtime_error(
                "LZMA properties data (RVA " + hex( props_info.src ) + " -> Raw " + hex( props_off ) +
                ", Size from Dst " + std::to_string( props_size ) + ") extends beyond packed PE size (" +
                hex( packed.size( ) ) + ")." );
        }

        if ( props_size != k_lzma_props )
        {
            std::printf(
                "Warning: PACKER_INFO[0].Dst (LZMA properties size) is %u. Standard is %u. Using provided size.\n",
                props_size,
                k_lzma_props );
        }

        const auto* props = packed.data( ) + props_off;

        for ( std::size_t block = 1; block < infos.size( ) ; ++block )
        {
            const auto compressed_rva = infos[ block ].src;
            const auto target_rva = infos[ block ].dst;

            std::uint32_t raw_off = 0;
            try
            {
                raw_off = rva_to_offset( pe, compressed_rva );
            }
            catch ( const std::exception& ex )
            {
                throw std::runtime_error( "Block " + std::to_string( block ) + ": Cannot convert RVA to file offset: " + ex.what( ) );
            }

            if ( raw_off >= packed.size( ) )
                throw std::runtime_error( "Block " + std::to_string( block ) + ": compressed data offset is past the packed file" );

            if ( target_rva >= pe.size_of_image )
            {
                throw std::runtime_error(
                    "Block " + std::to_string( block ) + ": PACKER_INFO.Dst (decompression target RVA " +
                    hex( target_rva ) + ") exceeds image boundary (" + hex( pe.size_of_image ) + ")." );
            }

            const auto available = pe.size_of_image - target_rva;
            auto decoded = lzma_decompress(
                props,
                props_size,
                packed.data( ) + raw_off,
                packed.size( ) - raw_off,
                available );

            const auto copy = ( std::min )( decoded.size( ), static_cast< std::size_t >( available ) );
            std::memcpy( image.data( ) + target_rva, decoded.data( ), copy );
        }
    }

    return image;
}
