#include <stdint.h>  // For uint64_t
#include <stdio.h>   // For printf
#include <stdlib.h>  // For EXIT_SUCCESS EXIT_FAILURE
#include <inttypes.h>  // For PRIx64

/// The standard hash for ABIv3
typedef uint64_t abi_hash_t;


/// A 64-bit GNU Hash function
///
/// @see https://blogs.oracle.com/solaris/post/gnu-hash-elf-sections
/// @see https://sourceware.org/legacy-ml/binutils/2006-10/msg00377.html
/// The original was Dan Bernstein's string hash function posted eons ago on comp.lang.c.
///
/// @param stringToHash The string to hash
///
/// @return The hash of `s`
abi_hash_t gnu_hash64( const char *stringToHash ) {
   abi_hash_t hash = 0x1505;   /// The seed value for the hash is 0x1505 (5381 decimal)

   for( unsigned char c = *stringToHash ; c != '\0' ; c = *++stringToHash ) {
      hash = ((hash << 5) + hash) + c;
   }

   return hash;
}


int main( int argc, char* argv[] ) {

   if( argc <= 1 ) {
      fprintf( stderr, "Filename required\n" );
      return EXIT_FAILURE;
   }   
   FILE* file = fopen ( argv[1], "r" );

   if( file != NULL ) {
      char symbol [4096];
      while( fgets( symbol, sizeof symbol, file ) != NULL ) {
         size_t len = strlen( symbol );
         if( len == 0 ) 
            continue;
         symbol[ len - 1 ] = '\0';
         fprintf( stdout, "%s,%" PRIx64 "\n", symbol, gnu_hash64( symbol ) );
      }

   } else {
      perror( argv[1] );
      return EXIT_FAILURE;
   }

  fclose(file);

  return EXIT_SUCCESS;   
}
