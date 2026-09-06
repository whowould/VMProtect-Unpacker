#include "iat.hxx"
#include "oep.hxx"
#include "vmp.hxx"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    constexpr auto k_max_sections = 96u;
    constexpr auto k_section_hdr = 40u;
    constexpr auto k_dos = 64u;
    constexpr auto k_nt_prefix = 24u;

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

    auto write_u16( std::uint8_t* p, std::uint16_t v ) -> void
    {
        std::memcpy( p, &v, sizeof( v ) );
    }

    auto write_u32( std::uint8_t* p, std::uint32_t v ) -> void
    {
        std::memcpy( p, &v, sizeof( v ) );
    }

    auto write_u64( std::uint8_t* p, std::uint64_t v ) -> void
    {
        std::memcpy( p, &v, sizeof( v ) );
    }

    auto align_up( std::uint32_t v, std::uint32_t a ) -> std::uint32_t
    {
        if ( !a )
            return v;
        return ( v + ( a - 1 ) ) / a * a;
    }

    auto lower_copy( std::string s ) -> std::string
    {
        for ( auto& c : s )
            c = static_cast< char >( ::tolower( static_cast< unsigned char >( c ) ) );
        return s;
    }

    struct pe_info
    {
        bool is64;
        std::uint32_t nt;
        std::uint32_t file;
        std::uint32_t opt;
        std::uint32_t dir_off;
        std::uint32_t section_off;
        std::uint32_t section_align;
        std::uint32_t file_align;
        std::uint32_t size_of_image;
        std::uint32_t size_of_headers;
        std::uint16_t section_count;
        std::uint16_t characteristics;
    };

    auto parse_pe( const std::vector< std::uint8_t >& img ) -> pe_info
    {
        if ( img.size( ) < k_dos || read_u16( img.data( ) ) != IMAGE_DOS_SIGNATURE )
            throw std::runtime_error( "bad dos header" );

        const auto nt = read_u32( img.data( ) + 0x3c );
        if ( nt < k_dos || img.size( ) < static_cast< std::size_t >( nt ) + k_nt_prefix + 2 )
            throw std::runtime_error( "truncated nt headers" );
        if ( read_u32( img.data( ) + nt ) != IMAGE_NT_SIGNATURE )
            throw std::runtime_error( "bad nt signature" );

        pe_info p{};
        p.nt = nt;
        p.file = nt + 4;
        p.opt = p.file + static_cast< std::uint32_t >( sizeof( IMAGE_FILE_HEADER ) );
        p.section_count = read_u16( img.data( ) + p.file + 2 );
        p.characteristics = read_u16( img.data( ) + p.file + 18 );
        const auto opt_size = read_u16( img.data( ) + p.file + 16 );
        if ( !p.section_count || p.section_count > k_max_sections )
            throw std::runtime_error( "bad section count" );
        if ( img.size( ) < p.opt + opt_size )
            throw std::runtime_error( "truncated optional header" );

        const auto magic = read_u16( img.data( ) + p.opt );
        if ( magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
        {
            p.is64 = true;
            p.dir_off = p.opt + 112;
        }
        else if ( magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
        {
            p.is64 = false;
            p.dir_off = p.opt + 96;
        }
        else
        {
            throw std::runtime_error( "unknown optional magic" );
        }

        p.section_align = read_u32( img.data( ) + p.opt + 32 );
        p.file_align = read_u32( img.data( ) + p.opt + 36 );
        p.size_of_image = read_u32( img.data( ) + p.opt + 56 );
        p.size_of_headers = read_u32( img.data( ) + p.opt + 60 );
        p.section_off = p.opt + opt_size;
        if ( !p.section_align || ( p.section_align & ( p.section_align - 1 ) ) )
            p.section_align = 0x1000;
        if ( !p.file_align || ( p.file_align & ( p.file_align - 1 ) ) )
            p.file_align = 0x200;
        return p;
    }

    struct sec
    {
        char name[ 9 ];
        std::uint32_t va;
        std::uint32_t vsize;
        std::uint32_t raw;
        std::uint32_t raw_size;
        std::uint32_t ch;
    };

    auto read_sections( const std::vector< std::uint8_t >& img, const pe_info& p ) -> std::vector< sec >
    {
        std::vector< sec > out;
        out.reserve( p.section_count );
        for ( std::uint16_t i = 0; i < p.section_count; ++i )
        {
            const auto off = p.section_off + i * k_section_hdr;
            if ( off + k_section_hdr > img.size( ) )
                throw std::runtime_error( "truncated section table" );
            sec s{};
            std::memcpy( s.name, img.data( ) + off, 8 );
            s.vsize = read_u32( img.data( ) + off + 8 );
            s.va = read_u32( img.data( ) + off + 12 );
            s.raw_size = read_u32( img.data( ) + off + 16 );
            s.raw = read_u32( img.data( ) + off + 20 );
            s.ch = read_u32( img.data( ) + off + 36 );
            out.push_back( s );
        }
        return out;
    }

    auto mapped( const sec& s ) -> std::uint32_t
    {
        return ( std::max )( s.vsize, s.raw_size );
    }

    auto is_api_set( const std::string& m ) -> bool
    {
        const auto s = lower_copy( m );
        return s.rfind( "api-ms-", 0 ) == 0 || s.rfind( "ext-ms-", 0 ) == 0;
    }

    auto better( const export_sym& a, const export_sym& b ) -> bool
    {
        if ( is_api_set( a.module ) != is_api_set( b.module ) )
            return !is_api_set( a.module );
        if ( a.name.empty( ) != b.name.empty( ) )
            return a.name.empty( ) < b.name.empty( );
        if ( a.module != b.module )
            return lower_copy( a.module ) < lower_copy( b.module );
        return a.name < b.name;
    }

    auto lookup( const std::map< std::uint64_t, std::vector< export_sym > >& idx, std::uint64_t addr ) -> const export_sym*
    {
        const auto it = idx.find( addr );
        if ( it == idx.end( ) || it->second.empty( ) )
            return nullptr;
        const export_sym* best = &it->second.front( );
        for ( const auto& s : it->second )
        {
            if ( better( s, *best ) )
                best = &s;
        }
        return best;
    }

    auto index_exports( const runtime_image& img ) -> std::map< std::uint64_t, std::vector< export_sym > >
    {
        std::map< std::uint64_t, std::vector< export_sym > > idx;
        for ( const auto& e : img.exports )
            idx[ e.address ].push_back( e );
        return idx;
    }

    struct recovered
    {
        std::string module;
        std::string name;
        std::uint32_t ordinal;
        std::uint64_t dest;
    };

    auto ident( const recovered& r ) -> std::pair< std::string, std::string >
    {
        if ( !r.name.empty( ) )
            return { lower_copy( r.module ), r.name };
        return { lower_copy( r.module ), std::string( "#" ) + std::to_string( r.ordinal ) };
    }

    struct pointer
    {
        std::uint32_t rva;
        recovered imp;
    };

    auto find_pointers( const runtime_image& img, const std::vector< sec >& secs, const std::map< std::uint64_t, std::vector< export_sym > >& idx ) -> std::vector< pointer >
    {
        const auto width = img.is64 ? 8u : 4u;
        std::vector< pointer > out;

        for ( const auto& s : secs )
        {
            if ( !( s.ch & IMAGE_SCN_MEM_READ ) || ( s.ch & IMAGE_SCN_MEM_EXECUTE ) )
                continue;
            if ( s.ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
                continue;

            const auto begin = s.va;
            const auto span = mapped( s );
            if ( !span || begin >= img.bytes.size( ) )
                continue;
            const auto end = static_cast< std::uint32_t >( ( std::min )( img.bytes.size( ), static_cast< std::size_t >( begin ) + span ) );
            auto rva = begin + ( ( width - ( begin % width ) ) % width );

            for ( ; rva + width <= end; rva += width )
            {
                const auto addr = img.is64 ? read_u64( img.bytes.data( ) + rva ) : read_u32( img.bytes.data( ) + rva );
                if ( !addr )
                    continue;
                const auto* exp = lookup( idx, addr );
                if ( !exp )
                    continue;
                recovered rec{};
                rec.module = exp->module;
                rec.name = exp->name;
                rec.ordinal = exp->ordinal;
                rec.dest = addr;
                out.push_back( { rva, rec } );
            }
        }
        return out;
    }

    struct ref
    {
        std::uint32_t insn_rva;
        std::uint32_t disp_off;
        std::uint32_t insn_len;
        bool rip;
        std::uint64_t dest;
    };

    auto is_prefix( std::uint8_t b, bool is64 ) -> bool
    {
        switch ( b )
        {
        case 0xF0:
        case 0xF2:
        case 0xF3:
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            return true;
        default:
            return is64 && ( b & 0xF0 ) == 0x40;
        }
    }

    auto scan_refs( const runtime_image& img, const std::vector< sec >& secs, const std::map< std::uint64_t, recovered >& slots ) -> std::vector< ref >
    {
        std::vector< ref > refs;
        if ( slots.empty( ) )
            return refs;

        const auto* b = img.bytes.data( );
        const auto n = img.bytes.size( );

        for ( const auto& s : secs )
        {
            if ( !( s.ch & IMAGE_SCN_MEM_EXECUTE ) )
                continue;
            if ( is_vm_section_name( s.name ) )
                continue;
            const auto begin = s.va;
            const auto span = mapped( s );
            if ( !span || begin >= n )
                continue;
            const auto end = static_cast< std::uint32_t >( ( std::min )( n, static_cast< std::size_t >( begin ) + span ) );

            for ( auto i = begin; i + 6 < end; )
            {
                auto p = i;
                auto prefixes = 0;
                while ( p < end && prefixes < 15 && is_prefix( b[ p ], img.is64 ) )
                {
                    ++p;
                    ++prefixes;
                }
                if ( p >= end )
                    break;

                const auto op = b[ p++ ];
                auto take = false;
                auto ff_reg_ok = true;
                if ( op == 0xFF || op == 0x8B )
                    take = true;
                else
                {
                    i += 1;
                    continue;
                }

                if ( p >= end )
                    break;
                const auto modrm = b[ p++ ];
                const auto mod = ( modrm >> 6 ) & 3;
                const auto reg = ( modrm >> 3 ) & 7;
                const auto rm = modrm & 7;
                if ( op == 0xFF && reg != 2 && reg != 4 && reg != 6 )
                {
                    i += 1;
                    continue;
                }
                if ( mod == 3 )
                {
                    i += 1;
                    continue;
                }

                auto sib = 0u;
                auto has_sib = mod != 3 && rm == 4;
                if ( has_sib )
                {
                    if ( p >= end )
                        break;
                    sib = b[ p++ ];
                }

                const auto rip = img.is64 && mod == 0 && rm == 5;
                const auto abs32 = mod == 0 && ( rm == 5 || ( has_sib && ( sib & 7 ) == 5 ) ) && !rip;
                std::uint32_t disp_size = 0;
                if ( mod == 1 )
                    disp_size = 1;
                else if ( mod == 2 || rip || abs32 )
                    disp_size = 4;

                if ( disp_size != 4 || p + 4 > end )
                {
                    i += 1;
                    continue;
                }

                const auto disp_off = static_cast< std::uint32_t >( p - i );
                const auto disp = static_cast< std::int32_t >( read_u32( b + p ) );
                p += 4;
                const auto insn_len = static_cast< std::uint32_t >( p - i );

                std::uint64_t target = 0;
                if ( rip )
                    target = img.base + i + insn_len + static_cast< std::int64_t >( disp );
                else if ( abs32 )
                    target = static_cast< std::uint32_t >( disp );
                else
                {
                    i += 1;
                    continue;
                }

                const auto it = slots.find( target );
                if ( it != slots.end( ) )
                    refs.push_back( { i, disp_off, insn_len, rip, it->second.dest } );

                ( void )take;
                ( void )ff_reg_ok;
                i += insn_len ? insn_len : 1;
            }
        }
        return refs;
    }

    auto pad( std::vector< std::uint8_t >& b, std::size_t a ) -> void
    {
        if ( !a )
            return;
        b.resize( ( b.size( ) + a - 1 ) / a * a, 0 );
    }
}

auto count_resolved_imports( const runtime_image& img ) -> std::size_t
{
    if ( img.bytes.size( ) < 0x200 || img.exports.empty( ) )
        return 0;
    try
    {
        const auto p = parse_pe( img.bytes );
        const auto secs = read_sections( img.bytes, p );
        return find_pointers( img, secs, index_exports( img ) ).size( );
    }
    catch ( ... )
    {
        return 0;
    }
}

auto rebuild_iat( runtime_image& img ) -> std::vector< std::uint8_t >
{
    if ( img.bytes.size( ) < 0x200 )
        throw std::runtime_error( "empty dump" );

    auto p = parse_pe( img.bytes );
    auto secs = read_sections( img.bytes, p );
    const auto idx = index_exports( img );
    const auto pointers = find_pointers( img, secs, idx );
    const auto stubs = recover_vm_stubs( img );
    if ( pointers.empty( ) && stubs.empty( ) )
        throw std::runtime_error( "no recovered imports are available" );

    std::map< std::uint64_t, recovered > slots;
    for ( const auto& pt : pointers )
        slots[ img.base + pt.rva ] = pt.imp;

    auto refs = scan_refs( img, secs, slots );

    std::map< std::pair< std::string, std::string >, recovered > uniq;
    auto add_imp = [ & ]( const recovered& rec )
    {
        const auto key = ident( rec );
        auto it = uniq.find( key );
        if ( it == uniq.end( ) || rec.dest < it->second.dest )
            uniq[ key ] = rec;
    };

    if ( !refs.empty( ) )
    {
        for ( const auto& r : refs )
        {
            for ( const auto& pt : pointers )
            {
                if ( pt.imp.dest == r.dest )
                    add_imp( pt.imp );
            }
        }
    }
    else
    {
        for ( const auto& pt : pointers )
            add_imp( pt.imp );
    }
    for ( const auto& st : stubs )
    {
        recovered rec{};
        rec.module = st.module;
        rec.name = st.name;
        rec.ordinal = st.ordinal;
        rec.dest = st.dest;
        add_imp( rec );
    }

    std::map< std::string, std::vector< recovered > > by_mod;
    for ( auto& kv : uniq )
        by_mod[ lower_copy( kv.second.module ) ].push_back( kv.second );
    if ( by_mod.empty( ) )
        throw std::runtime_error( "no recovered imports are available" );

    const auto width = img.is64 ? 8u : 4u;
    const auto ord_flag = img.is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

    std::uint32_t last_end = p.size_of_image;
    for ( const auto& s : secs )
        last_end = ( std::max )( last_end, s.va + mapped( s ) );
    const auto new_va = align_up( last_end, p.section_align );

    std::vector< std::uint8_t > extra( ( by_mod.size( ) + 1 ) * sizeof( IMAGE_IMPORT_DESCRIPTOR ), 0 );

    struct planned
    {
        std::string module;
        std::vector< recovered > imps;
        std::uint32_t ilt;
        std::uint32_t iat;
        std::uint32_t name;
    };
    std::vector< planned > mods;
    mods.reserve( by_mod.size( ) );

    pad( extra, width );
    for ( auto& kv : by_mod )
    {
        planned m{};
        m.module = kv.second.front( ).module;
        m.imps = std::move( kv.second );
        std::sort( m.imps.begin( ), m.imps.end( ), [ ]( const recovered& a, const recovered& b )
        {
            if ( a.name.empty( ) != b.name.empty( ) )
                return a.name.empty( ) < b.name.empty( );
            if ( a.name != b.name )
                return a.name < b.name;
            return a.ordinal < b.ordinal;
        } );
        m.ilt = static_cast< std::uint32_t >( extra.size( ) );
        extra.resize( extra.size( ) + ( m.imps.size( ) + 1 ) * width, 0 );
        mods.push_back( std::move( m ) );
    }

    const auto iat_off = static_cast< std::uint32_t >( extra.size( ) );
    for ( auto& m : mods )
    {
        m.iat = static_cast< std::uint32_t >( extra.size( ) );
        extra.resize( extra.size( ) + ( m.imps.size( ) + 1 ) * width, 0 );
    }
    const auto iat_size = static_cast< std::uint32_t >( extra.size( ) ) - iat_off;

    for ( auto& m : mods )
    {
        m.name = new_va + static_cast< std::uint32_t >( extra.size( ) );
        extra.insert( extra.end( ), m.module.begin( ), m.module.end( ) );
        extra.push_back( 0 );
    }

    pad( extra, 2 );
    std::map< std::uint64_t, std::uint32_t > dest_to_iat;
    auto write_ptr = [ & ]( std::uint32_t off, std::uint64_t v )
    {
        if ( img.is64 )
            write_u64( extra.data( ) + off, v );
        else
            write_u32( extra.data( ) + off, static_cast< std::uint32_t >( v ) );
    };

    for ( auto& m : mods )
    {
        for ( std::size_t i = 0; i < m.imps.size( ); ++i )
        {
            std::uint64_t thunk = 0;
            if ( m.imps[ i ].name.empty( ) )
            {
                thunk = ord_flag | m.imps[ i ].ordinal;
            }
            else
            {
                pad( extra, 2 );
                const auto ibn = new_va + static_cast< std::uint32_t >( extra.size( ) );
                extra.push_back( 0 );
                extra.push_back( 0 );
                extra.insert( extra.end( ), m.imps[ i ].name.begin( ), m.imps[ i ].name.end( ) );
                extra.push_back( 0 );
                if ( extra.size( ) & 1 )
                    extra.push_back( 0 );
                thunk = ibn;
            }
            const auto slot = static_cast< std::uint32_t >( i * width );
            write_ptr( m.ilt + slot, thunk );
            write_ptr( m.iat + slot, thunk );
            dest_to_iat[ m.imps[ i ].dest ] = new_va + m.iat + slot;
        }
    }

    for ( std::size_t i = 0; i < mods.size( ); ++i )
    {
        auto* d = extra.data( ) + i * sizeof( IMAGE_IMPORT_DESCRIPTOR );
        write_u32( d + 0, new_va + mods[ i ].ilt );
        write_u32( d + 12, mods[ i ].name );
        write_u32( d + 16, new_va + mods[ i ].iat );
    }

    for ( const auto& r : refs )
    {
        const auto it = dest_to_iat.find( r.dest );
        if ( it == dest_to_iat.end( ) )
            continue;
        const auto slot_va = img.base + it->second;
        std::uint32_t bits = 0;
        if ( r.rip )
        {
            const auto next = img.base + r.insn_rva + r.insn_len;
            const auto d = static_cast< std::int64_t >( slot_va ) - static_cast< std::int64_t >( next );
            if ( d < static_cast< std::int64_t >( INT32_MIN ) || d > static_cast< std::int64_t >( INT32_MAX ) )
                continue;
            bits = static_cast< std::uint32_t >( static_cast< std::int32_t >( d ) );
        }
        else
        {
            if ( slot_va > 0xffffffffull )
                continue;
            bits = static_cast< std::uint32_t >( slot_va );
        }
        if ( static_cast< std::size_t >( r.insn_rva ) + r.disp_off + 4 <= img.bytes.size( ) )
            write_u32( img.bytes.data( ) + r.insn_rva + r.disp_off, bits );
    }
    apply_vm_stubs( img, stubs, dest_to_iat );

    const auto extra_vsize = static_cast< std::uint32_t >( extra.size( ) );
    const auto extra_raw = align_up( extra_vsize, p.file_align );
    const auto import_dir_rva = new_va;
    const auto import_dir_size = static_cast< std::uint32_t >( ( mods.size( ) + 1 ) * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
    const auto iat_rva = new_va + iat_off;

    auto size_of_headers = p.size_of_headers;
    const auto hdr_need = p.section_off + ( p.section_count + 1 ) * k_section_hdr;
    if ( hdr_need > size_of_headers )
        size_of_headers = align_up( hdr_need, p.file_align );

    std::vector< std::uint32_t > sec_raw( secs.size( ) );
    std::vector< std::uint32_t > sec_raw_sz( secs.size( ) );
    auto laid = size_of_headers;
    for ( std::size_t i = 0; i < secs.size( ); ++i )
    {
        const auto span = mapped( secs[ i ] );
        sec_raw_sz[ i ] = span ? align_up( span, p.file_align ) : 0;
        sec_raw[ i ] = laid;
        laid += sec_raw_sz[ i ];
    }
    const auto extra_raw_off = laid;
    std::vector< std::uint8_t > out( extra_raw_off + extra_raw, 0 );

    const auto hdr_copy = ( std::min )( { static_cast< std::size_t >( p.size_of_headers ), static_cast< std::size_t >( size_of_headers ), img.bytes.size( ) } );
    std::memcpy( out.data( ), img.bytes.data( ), hdr_copy );
    for ( std::size_t i = 0; i < secs.size( ); ++i )
    {
        if ( !sec_raw_sz[ i ] || secs[ i ].va >= img.bytes.size( ) )
            continue;
        const auto nbytes = ( std::min )( { static_cast< std::size_t >( mapped( secs[ i ] ) ), img.bytes.size( ) - secs[ i ].va, static_cast< std::size_t >( sec_raw_sz[ i ] ) } );
        std::memcpy( out.data( ) + sec_raw[ i ], img.bytes.data( ) + secs[ i ].va, nbytes );
    }
    std::memcpy( out.data( ) + extra_raw_off, extra.data( ), extra.size( ) );

    write_u16( out.data( ) + p.file + 2, static_cast< std::uint16_t >( p.section_count + 1 ) );
    write_u16( out.data( ) + p.file + 18, static_cast< std::uint16_t >( p.characteristics | IMAGE_FILE_RELOCS_STRIPPED ) );
    if ( img.is64 )
        write_u64( out.data( ) + p.opt + 24, img.base );
    else
        write_u32( out.data( ) + p.opt + 28, static_cast< std::uint32_t >( img.base ) );

    write_u32( out.data( ) + p.opt + 56, align_up( new_va + extra_vsize, p.section_align ) );
    write_u32( out.data( ) + p.opt + 60, size_of_headers );
    write_u32( out.data( ) + p.opt + 64, 0 );
    write_u16( out.data( ) + p.opt + 70, static_cast< std::uint16_t >( read_u16( out.data( ) + p.opt + 70 ) & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) );

    auto write_dir = [ & ]( std::size_t i, std::uint32_t rva, std::uint32_t sz )
    {
        write_u32( out.data( ) + p.dir_off + static_cast< std::uint32_t >( i ) * 8, rva );
        write_u32( out.data( ) + p.dir_off + static_cast< std::uint32_t >( i ) * 8 + 4, sz );
    };
    write_dir( IMAGE_DIRECTORY_ENTRY_IMPORT, import_dir_rva, import_dir_size );
    write_dir( IMAGE_DIRECTORY_ENTRY_IAT, iat_rva, iat_size );
    write_dir( IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0 );
    write_dir( IMAGE_DIRECTORY_ENTRY_SECURITY, 0, 0 );
    write_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0 );
    write_dir( IMAGE_DIRECTORY_ENTRY_TLS, 0, 0 );

    for ( std::size_t i = 0; i < secs.size( ); ++i )
    {
        const auto off = p.section_off + static_cast< std::uint32_t >( i ) * k_section_hdr;
        write_u32( out.data( ) + off + 16, sec_raw_sz[ i ] );
        write_u32( out.data( ) + off + 20, sec_raw[ i ] );
    }

    const auto nh = p.section_off + p.section_count * k_section_hdr;
    if ( nh + k_section_hdr > out.size( ) )
        throw std::runtime_error( "no room for another section header" );
    std::memset( out.data( ) + nh, 0, k_section_hdr );
    std::memcpy( out.data( ) + nh, ".iat", 4 );
    write_u32( out.data( ) + nh + 8, extra_vsize );
    write_u32( out.data( ) + nh + 12, new_va );
    write_u32( out.data( ) + nh + 16, extra_raw );
    write_u32( out.data( ) + nh + 20, extra_raw_off );
    write_u32( out.data( ) + nh + 36, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE );
    apply_oep( out, find_oep( img.bytes, img.is64 ) );
    return out;
}
