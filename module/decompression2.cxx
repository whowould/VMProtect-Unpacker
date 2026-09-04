#include "decompression2.hxx"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <psapi.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#pragma comment( lib, "psapi.lib" )

namespace
{
    auto last_error( const char* what ) -> std::runtime_error
    {
        return std::runtime_error( std::string( what ) + " (" + std::to_string( GetLastError( ) ) + ")" );
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

    auto wide_to_utf8( const wchar_t* s ) -> std::string
    {
        if ( !s || !*s )
            return {};
        const auto n = WideCharToMultiByte( CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr );
        if ( n <= 1 )
            return {};
        std::string out( static_cast< std::size_t >( n ), '\0' );
        WideCharToMultiByte( CP_UTF8, 0, s, -1, &out[ 0 ], n, nullptr, nullptr );
        if ( !out.empty( ) && out.back( ) == '\0' )
            out.pop_back( );
        return out;
    }

    auto file_name( const std::string& path ) -> std::string
    {
        const auto slash = path.find_last_of( "\\/" );
        return slash == std::string::npos ? path : path.substr( slash + 1 );
    }

    auto read_proc( HANDLE hp, std::uint64_t addr, void* dst, std::size_t n ) -> void
    {
        SIZE_T got = 0;
        if ( !ReadProcessMemory( hp, reinterpret_cast< LPCVOID >( static_cast< std::uintptr_t >( addr ) ), dst, n, &got ) || got != n )
            throw last_error( "ReadProcessMemory" );
    }

    auto read_proc_partial( HANDLE hp, std::uint64_t addr, void* dst, std::size_t n ) -> std::size_t
    {
        SIZE_T got = 0;
        ReadProcessMemory( hp, reinterpret_cast< LPCVOID >( static_cast< std::uintptr_t >( addr ) ), dst, n, &got );
        return got;
    }

    auto ascii_z( HANDLE hp, std::uint64_t addr, std::size_t maxn = 512 ) -> std::string
    {
        if ( !maxn )
            return {};
        std::string s( maxn, '\0' );
        const auto n = read_proc_partial( hp, addr, &s[ 0 ], s.size( ) );
        s.resize( n );
        const auto z = s.find( '\0' );
        if ( z != std::string::npos )
            s.resize( z );
        return s;
    }

    struct owned_handle
    {
        HANDLE h{};
        ~owned_handle( )
        {
            if ( h && h != INVALID_HANDLE_VALUE )
                CloseHandle( h );
        }
        owned_handle( ) = default;
        explicit owned_handle( HANDLE x ) : h( x ) {}
        owned_handle( const owned_handle& ) = delete;
        auto operator=( const owned_handle& ) -> owned_handle& = delete;
        owned_handle( owned_handle&& o ) noexcept : h( o.h ) { o.h = nullptr; }
        auto operator=( owned_handle&& o ) noexcept -> owned_handle&
        {
            if ( this != &o )
            {
                if ( h && h != INVALID_HANDLE_VALUE )
                    CloseHandle( h );
                h = o.h;
                o.h = nullptr;
            }
            return *this;
        }
    };

    auto enable_debug( ) -> void
    {
        HANDLE tok = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok ) )
            return;
        owned_handle t( tok );
        TOKEN_PRIVILEGES tp{};
        if ( !LookupPrivilegeValueA( nullptr, "SeDebugPrivilege", &tp.Privileges[ 0 ].Luid ) )
            return;
        tp.PrivilegeCount = 1;
        tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges( t.h, FALSE, &tp, sizeof( tp ), nullptr, nullptr );
    }

    auto spawn( const char* path ) -> PROCESS_INFORMATION
    {
        STARTUPINFOA si{};
        si.cb = sizeof( si );
        PROCESS_INFORMATION pi{};
        std::string cmd = std::string( "\"" ) + path + "\"";
        std::vector< char > buf( cmd.begin( ), cmd.end( ) );
        buf.push_back( 0 );
        if ( !CreateProcessA( path, buf.data( ), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi ) )
            throw last_error( "CreateProcess" );
        return pi;
    }

    auto wait_init( HANDLE hp, DWORD wait_ms ) -> void
    {
        const auto t0 = GetTickCount( );
        while ( GetTickCount( ) - t0 < wait_ms )
        {
            DWORD n = 0;
            EnumProcessModulesEx( hp, nullptr, 0, &n, LIST_MODULES_ALL );
            if ( n >= 3 * sizeof( HMODULE ) )
                break;
            Sleep( 50 );
        }
        Sleep( 250 );
    }

    auto module_list( HANDLE hp, DWORD pid ) -> std::vector< module_info >
    {
        std::vector< module_info > out;
        owned_handle snap( CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid ) );
        if ( snap.h == INVALID_HANDLE_VALUE )
            throw last_error( "CreateToolhelp32Snapshot" );

        MODULEENTRY32W me{};
        me.dwSize = sizeof( me );
        if ( !Module32FirstW( snap.h, &me ) )
            throw last_error( "Module32First" );

        do
        {
            module_info m{};
            m.name = wide_to_utf8( me.szModule );
            m.path = wide_to_utf8( me.szExePath );
            m.base = static_cast< std::uint64_t >( reinterpret_cast< std::uintptr_t >( me.modBaseAddr ) );
            m.size = me.modBaseSize;
            out.push_back( std::move( m ) );
        } while ( Module32NextW( snap.h, &me ) );

        ( void )hp;
        return out;
    }

    auto parse_remote_pe( HANDLE hp, std::uint64_t base ) -> std::tuple< bool, std::uint32_t, std::uint32_t, std::uint32_t >
    {
        std::uint8_t dos[ 64 ];
        read_proc( hp, base, dos, sizeof( dos ) );
        if ( read_u16( dos ) != IMAGE_DOS_SIGNATURE )
            throw std::runtime_error( "remote image has no MZ" );
        const auto nt = read_u32( dos + 0x3c );
        std::uint8_t ntbuf[ 24 + 240 ];
        read_proc( hp, base + nt, ntbuf, sizeof( ntbuf ) );
        if ( read_u32( ntbuf ) != IMAGE_NT_SIGNATURE )
            throw std::runtime_error( "remote image has no PE" );
        const auto opt_size = read_u16( ntbuf + 20 );
        const auto magic = read_u16( ntbuf + 24 );
        const auto is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        const auto size_of_image = read_u32( ntbuf + 24 + 56 );
        const auto size_of_headers = read_u32( ntbuf + 24 + 60 );
        ( void )opt_size;
        return { is64, size_of_image, size_of_headers, nt };
    }

    auto dump_image( HANDLE hp, std::uint64_t base, std::uint32_t size ) -> std::vector< std::uint8_t >
    {
        if ( !size || size > 0x20000000u )
            throw std::runtime_error( "remote SizeOfImage is invalid" );

        std::vector< std::uint8_t > img( size, 0 );
        std::size_t off = 0;
        while ( off < img.size( ) )
        {
            MEMORY_BASIC_INFORMATION mbi{};
            const auto queried = VirtualQueryEx(
                hp,
                reinterpret_cast< LPCVOID >( static_cast< std::uintptr_t >( base + off ) ),
                &mbi,
                sizeof( mbi ) );
            if ( !queried )
                break;

            auto region = static_cast< std::size_t >( mbi.RegionSize );
            if ( !region )
                region = 0x1000;
            const auto chunk = ( std::min )( region, img.size( ) - off );
            const auto protect = mbi.Protect & 0xff;
            const auto readable = mbi.State == MEM_COMMIT
                && protect != PAGE_NOACCESS
                && protect != PAGE_GUARD
                && ( protect & ( PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) );

            if ( readable )
                read_proc_partial( hp, base + off, &img[ off ], chunk );

            off += chunk;
        }
        return img;
    }

    auto collect_exports( HANDLE hp, const module_info& m ) -> std::vector< export_sym >
    {
        std::vector< export_sym > out;
        std::uint8_t dos[ 64 ];
        if ( read_proc_partial( hp, m.base, dos, sizeof( dos ) ) != sizeof( dos ) )
            return out;
        if ( read_u16( dos ) != IMAGE_DOS_SIGNATURE )
            return out;
        const auto nt = read_u32( dos + 0x3c );
        std::uint8_t ntbuf[ 24 + 240 ];
        if ( read_proc_partial( hp, m.base + nt, ntbuf, sizeof( ntbuf ) ) != sizeof( ntbuf ) )
            return out;
        if ( read_u32( ntbuf ) != IMAGE_NT_SIGNATURE )
            return out;
        const auto magic = read_u16( ntbuf + 24 );
        const auto dir_off = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112 : 96;
        const auto exp_rva = read_u32( ntbuf + 24 + dir_off );
        const auto exp_sz = read_u32( ntbuf + 24 + dir_off + 4 );
        if ( !exp_rva || !exp_sz || exp_rva >= m.size )
            return out;

        IMAGE_EXPORT_DIRECTORY exp{};
        if ( read_proc_partial( hp, m.base + exp_rva, &exp, sizeof( exp ) ) != sizeof( exp ) )
            return out;
        if ( !exp.NumberOfFunctions || exp.NumberOfFunctions > 1000000 )
            return out;

        std::vector< std::uint32_t > funcs( exp.NumberOfFunctions );
        if ( funcs.empty( ) || read_proc_partial( hp, m.base + exp.AddressOfFunctions, &funcs[ 0 ], funcs.size( ) * 4 ) != funcs.size( ) * 4 )
            return out;

        std::vector< std::uint32_t > names;
        std::vector< std::uint16_t > ords;
        if ( exp.NumberOfNames && exp.NumberOfNames < 1000000 )
        {
            names.resize( exp.NumberOfNames );
            ords.resize( exp.NumberOfNames );
            if ( !names.empty( ) && read_proc_partial( hp, m.base + exp.AddressOfNames, &names[ 0 ], names.size( ) * 4 ) != names.size( ) * 4 )
                names.clear( );
            if ( !ords.empty( ) && read_proc_partial( hp, m.base + exp.AddressOfNameOrdinals, &ords[ 0 ], ords.size( ) * 2 ) != ords.size( ) * 2 )
                ords.clear( );
        }

        std::vector< std::string > named( funcs.size( ) );
        for ( std::size_t i = 0; i < names.size( ) && i < ords.size( ); ++i )
        {
            if ( ords[ i ] >= named.size( ) )
                continue;
            named[ ords[ i ] ] = ascii_z( hp, m.base + names[ i ] );
        }

        const auto dir_end = exp_rva + exp_sz;
        for ( std::uint32_t i = 0; i < exp.NumberOfFunctions; ++i )
        {
            const auto rva = funcs[ i ];
            if ( !rva )
                continue;
            if ( rva >= exp_rva && rva < dir_end )
                continue;
            export_sym s{};
            s.module = m.name;
            s.name = i < named.size( ) ? named[ i ] : std::string{};
            s.ordinal = exp.Base + i;
            s.address = m.base + rva;
            out.push_back( std::move( s ) );
        }
        return out;
    }

    auto capture( HANDLE hp, DWORD pid, const char* want_name ) -> runtime_image
    {
        auto mods = module_list( hp, pid );
        if ( mods.empty( ) )
            throw std::runtime_error( "no modules in target" );

        auto main = mods.front( );
        if ( want_name && *want_name )
        {
            const auto want = file_name( want_name );
            for ( const auto& m : mods )
            {
                if ( _stricmp( m.name.c_str( ), want.c_str( ) ) == 0 )
                {
                    main = m;
                    break;
                }
            }
        }

        bool is64 = false;
        std::uint32_t size_of_image = 0, size_of_headers = 0, nt = 0;
        std::tie( is64, size_of_image, size_of_headers, nt ) = parse_remote_pe( hp, main.base );
        ( void )size_of_headers;
        ( void )nt;

        runtime_image img{};
        img.bytes = dump_image( hp, main.base, size_of_image ? size_of_image : main.size );
        img.base = main.base;
        img.is64 = is64;
        img.modules = std::move( mods );
        for ( const auto& m : img.modules )
        {
            if ( m.base == main.base )
                continue;
            auto ex = collect_exports( hp, m );
            img.exports.insert( img.exports.end( ), ex.begin( ), ex.end( ) );
        }
        return img;
    }
}

auto dump_runtime( const char* packed_path, std::uint32_t wait_ms ) -> runtime_image
{
    enable_debug( );

    auto pi = spawn( packed_path );
    owned_handle proc( pi.hProcess );
    owned_handle thr( pi.hThread );

    if ( ResumeThread( pi.hThread ) == static_cast< DWORD >( -1 ) )
        throw last_error( "ResumeThread" );

    wait_init( pi.hProcess, ( std::min )( wait_ms, 1500u ) );

    runtime_image best{};
    std::size_t best_hits = 0;
    const auto t0 = GetTickCount( );
    do
    {
        try
        {
            auto img = capture( pi.hProcess, pi.dwProcessId, packed_path );
            const auto hits = count_resolved_imports( img );
            if ( hits > best_hits )
            {
                best_hits = hits;
                best = std::move( img );
            }
            if ( best_hits >= 32 )
                break;
        }
        catch ( ... )
        {
        }
        Sleep( 200 );
    } while ( GetTickCount( ) - t0 < wait_ms );

    if ( pi.hProcess )
        TerminateProcess( pi.hProcess, 0 );
    if ( pi.hProcess )
        WaitForSingleObject( pi.hProcess, 2000 );
    proc.h = nullptr;
    thr.h = nullptr;

    if ( best.bytes.empty( ) )
        throw std::runtime_error( "failed to dump target image" );
    if ( !best_hits )
        throw std::runtime_error( "no recovered imports are available" );
    return best;
}

auto dump_and_fix( const char* packed_path, std::uint32_t wait_ms ) -> std::vector< std::uint8_t >
{
    auto img = dump_runtime( packed_path, wait_ms );
    return rebuild_iat( img );
}

auto dump_pid( std::uint32_t pid, const char* module_name ) -> runtime_image
{
    enable_debug( );
    owned_handle hp( OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid ) );
    if ( !hp.h )
        throw last_error( "OpenProcess" );
    auto img = capture( hp.h, pid, module_name );
    if ( !count_resolved_imports( img ) )
        throw std::runtime_error( "no recovered imports are available" );
    return img;
}

auto dump_pid_and_fix( std::uint32_t pid, const char* module_name ) -> std::vector< std::uint8_t >
{
    auto img = dump_pid( pid, module_name );
    return rebuild_iat( img );
}
