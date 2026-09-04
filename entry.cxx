#include "module/decompression.hxx"
#include "module/decompression2.hxx"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

auto read_file( const char* path ) -> std::vector< std::uint8_t >
{
    std::ifstream in( path, std::ios::binary );
    if ( !in )
        throw std::runtime_error( std::string( "failed to open " ) + path );

    in.seekg( 0, std::ios::end );
    const auto size = static_cast< std::size_t >( in.tellg( ) );
    in.seekg( 0, std::ios::beg );

    std::vector< std::uint8_t > buf( size );
    if ( size && !in.read( reinterpret_cast< char* >( buf.data( ) ), static_cast< std::streamsize >( size ) ) )
        throw std::runtime_error( std::string( "failed to read " ) + path );

    return buf;
}

auto write_file( const char* path, const std::vector< std::uint8_t >& buf ) -> void
{
    std::ofstream out( path, std::ios::binary );
    if ( !out )
        throw std::runtime_error( std::string( "failed to create " ) + path );

    if ( !buf.empty( ) && !out.write( reinterpret_cast< const char* >( buf.data( ) ), static_cast< std::streamsize >( buf.size( ) ) ) )
        throw std::runtime_error( std::string( "failed to write " ) + path );
}

auto parse_u32_opt( int argc, char** argv, const char* name, std::uint32_t fallback ) -> std::uint32_t
{
    for ( int i = 1; i + 1 < argc; ++i )
    {
        if ( !std::strcmp( argv[ i ], name ) )
            return static_cast< std::uint32_t >( std::strtoul( argv[ i + 1 ], nullptr, 10 ) );
    }
    return fallback;
}

auto main( int argc, char** argv ) -> int
{
    auto runtime = false;
    auto pid = 0u;
    const char* module_name = nullptr;
    std::vector< const char* > pos;
    for ( int i = 1; i < argc; ++i )
    {
        if ( !std::strcmp( argv[ i ], "--runtime" ) )
        {
            runtime = true;
            continue;
        }
        if ( !std::strcmp( argv[ i ], "--wait" ) || !std::strcmp( argv[ i ], "--pid" ) || !std::strcmp( argv[ i ], "--module" ) )
        {
            if ( i + 1 < argc )
            {
                if ( !std::strcmp( argv[ i ], "--pid" ) )
                    pid = static_cast< std::uint32_t >( std::strtoul( argv[ i + 1 ], nullptr, 10 ) );
                else if ( !std::strcmp( argv[ i ], "--module" ) )
                    module_name = argv[ i + 1 ];
                ++i;
            }
            continue;
        }
        pos.push_back( argv[ i ] );
    }

    if ( ( pid && pos.size( ) < 1 ) || ( !pid && pos.size( ) < 2 ) )
    {
        std::printf( "usage: %s [--runtime] [--wait ms] <in> <out>\n", argv[ 0 ] );
        std::printf( "       %s --pid <pid> [--module name] <out>\n", argv[ 0 ] );
        return 1;
    }

    try
    {
        if ( pid )
        {
            const auto dumped = dump_pid_and_fix( pid, module_name );
            write_file( pos[ 0 ], dumped );
            std::printf( "dumped %zu bytes\n", dumped.size( ) );
            return 0;
        }

        if ( runtime )
        {
            const auto wait_ms = parse_u32_opt( argc, argv, "--wait", 15000 );
            const auto dumped = dump_and_fix( pos[ 0 ], wait_ms );
            write_file( pos[ 1 ], dumped );
            std::printf( "dumped %zu bytes\n", dumped.size( ) );
            return 0;
        }

        const auto packed = read_file( pos[ 0 ] );
        const auto unpacked = unpack_pe( packed );
        if ( unpacked.empty( ) )
        {
            std::printf( "failed\n" );
            return 1;
        }

        write_file( pos[ 1 ], unpacked );
        std::printf( "unpacked %zu bytes\n", unpacked.size( ) );
        return 0;
    }
    catch ( const std::exception& ex )
    {
        std::printf( "failed: %s\n", ex.what( ) );
        return 1;
    }
}
