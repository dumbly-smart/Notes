## Elf interactively ide
https://www.google.com/url?q=https://ide.kaitai.io/&sa=D&source=editors&ust=1779359711743772&usg=AOvVaw3oCpUiKc_lUKDxzTM5tqNB

## Process interaction

How a binary file is compiled

compiler -> assembler -> linker

compiler - converts the code into assembly

assembler - converts assembly to raw bytes and add segments like .data .variables etc

linker - add the interpreter information and links everything add entry and exit and makes it into a full ELF

### Dynamically linked ELFs: the loading process
1. The program and its interpreter are loaded by the kernel.
    
2. The interpreter locates the libraries.
    

3. LD_PRELOAD environment variable, and anything in /etc/ld.so.preload
    
4. LD_LIBRARY_PATH environment variable (can be set in the shell)
    
5. DT_RUNPATH or DT_RPATH specified in the binary file (both can be modified with patchelf)
    
6. system-wide configuration (/etc/ld.so.conf)
    
7. /lib and /usr/lib
    

8. The interpreter loads the libraries.
    

9. these libraries can depend on other libraries, causing more to be loaded
    
10. relocations updated

where its loaded - [https://gist.github.com/CMCDragonkai/10ab53654b2aa6ce55c11cfc5b2432a4](https://gist.github.com/CMCDragonkai/10ab53654b2aa6ce55c11cfc5b2432a4)

### Initialization
Every ELF binary can specify constructors, which are functions that run before the program is actually launched.

  

For example, depending on the version, libc can initialize memory regions for dynamic allocations (malloc/free) when the program launches.

  

You can specify your own!

  

__attribute__((constructor)) void haha()

{

puts("Hello world!");

}

  

Demo: LD_PRELOAD and constructors.