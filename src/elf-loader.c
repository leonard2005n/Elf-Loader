// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <limits.h>
#include <string.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/auxv.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	// Verifing if the magic word is correct at the start of the elf file
	uint16_t elf_magic_word = *(uint16_t *)elf_contents;

	if (elf_magic_word != *(uint16_t *)ELFMAG) {
		perror("Not a valid ELF file");
		exit(3);	
	}

	// Verifing if the ELF file is for 64 bits system
	uint8_t elf_class_byte = *(uint8_t *)(elf_contents + 4);

	if (elf_class_byte != ELFCLASS64) {
		perror("Not a 64-bit ELF");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */

	// Getting the page size of the system
	long page_size = sysconf(_SC_PAGESIZE);
	
	// Getting the the elf heder file
	Elf64_Ehdr *elf_header = (Elf64_Ehdr *)elf_contents;
	struct stat statbuf;

	// Opening the file
	int file = open(filename, O_RDONLY);
	int x = fstat(file, &statbuf);

	// Mapping the file in the memory
	void *ptr_file = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, file, 0);
	close(file);

	// Getting the first program hadder
	Elf64_Phdr *start = (Elf64_Phdr *)(ptr_file + elf_header->e_phoff);
	int off_bytes = 0;

	// This is interrating thru the program hadders
	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *ptr = (void *)start + off_bytes;


		if (ptr->p_type == PT_LOAD) {
			void * map_address = (void *)(ptr->p_vaddr & ~(page_size - 1));
			unsigned long offset = ptr->p_vaddr - (unsigned long) map_address;

			void *page = mmap(map_address, ptr->p_memsz + offset, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			memcpy(page + offset, ptr_file + ptr->p_offset, ptr->p_filesz);
		}
		off_bytes += elf_header->e_phentsize;
	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	off_bytes = 0;
	// Iterating to change the the permission of the segments
	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *ptr = (void *)start + off_bytes;

		if (ptr->p_type == PT_LOAD) {
			void * map_address = (void *)(ptr->p_vaddr & ~(page_size - 1));
			unsigned long offset = ptr->p_vaddr - (unsigned long) map_address;

			unsigned char prot = PROT_NONE;
			unsigned char flags = ptr->p_flags;
			
			if (flags & PF_X) {
				prot |= PROT_EXEC;
			}

			if (flags & PF_W) {
				prot |= PROT_WRITE;
			}

			if (flags & PF_R) {
				prot |= PROT_READ;
			}

			mprotect(map_address, ptr->p_memsz + offset, prot);
		}
		off_bytes += elf_header->e_phentsize;
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */

	void *sp = NULL;
	
	unsigned long stack;

	sp = mmap(NULL, page_size * 4096, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	
	// stack = (unsigned long)sp + page_size * 4096;

	// stack -= 20;
	// unsigned long vector_random = stack;

	// // Puting the argv on the stack
	// unsigned char *new_argv[20000];
	// for (int i = 0; i < argc; i++) {
	// 	stack -= strlen(argv[i]) + 1;
	// 	memcpy((void *)stack, argv[i], strlen(argv[i]) + 1);
	// 	new_argv[i] = (char *)stack;
	// }


	// // Puting the envp on the stack
	// int i = 0;
	// unsigned char *new_envp[20000];
	// while (envp[i]) {
	// 	stack -= strlen(envp[i]) + 1;
	// 	memcpy((void *)stack, envp[i], strlen(envp[i]) + 1);
	// 	new_envp[i] = (char *)stack;
	// 	i++;
	// }

	// unsigned long value;
	// unsigned long *value_ptr = &value;


	// // Alliging the stack
	// stack = (unsigned long)stack & ~(page_size - 1);

	// // Put null
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, 0, sizeof(unsigned long));

	// stack -= (sizeof(unsigned long));
	// value = AT_NULL;
	// memcpy((void *)stack, value_ptr, sizeof(unsigned long));

	// // Put Random
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, vector_random, sizeof(unsigned long));

	// stack -= (sizeof(unsigned long));
	// value = AT_RANDOM;
	// memcpy((void *)stack, value_ptr, sizeof(unsigned long));
	
	// // Put entry
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, elf_header->e_entry, sizeof(unsigned long));

	// stack -= (sizeof(unsigned long));
	// value = AT_ENTRY;
	// memcpy((void *)stack, value_ptr, sizeof(unsigned long));

	// // Put pages
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, (unsigned long)page_size, sizeof(unsigned long));

	// stack -= (sizeof(unsigned long));
	// value = AT_PAGESZ;
	// memcpy((void *)stack, value_ptr, sizeof(unsigned long));

	
	// // Distance between auxv and envp
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, 0, sizeof(unsigned long));

	// i = 0;
	// while (envp[i]) {
	// 	stack -= sizeof(unsigned char *);
	// 	memcpy((void *)stack, new_envp[i], sizeof(unsigned char *));
	// 	i++;
	// }

	// // Distance between envp and argv
	// stack -= (sizeof(unsigned long));
	// memset((void *)stack, 0, sizeof(unsigned long));

	// for (int i = 0; i < argc; i++) {
	// 	stack -= sizeof(unsigned char *);
	// 	memcpy((void *)stack, new_argv[i], sizeof(unsigned char *));
	// }

	// stack -= (sizeof(unsigned long));
	// value = argc;
	// memcpy((void *)stack, value_ptr, sizeof(unsigned long));


	sp = (void *)start;

	// // Copying the argv element to the stack frame
	// void *elements = sp + page_size * 3;
	// char **new_argv = sp + page_size * 2;
	// for (int i = 0; i < argc; i++) {
	// 	elements -= strlen(argv[i]) + 1;
	// 	memcpy(elements, argv[i], strlen(argv[i]) + 1);
	// 	new_argv[i] = elements;
	// }

	// // Copying the envp to the stack frame
	// char **new_envp = sp + page_size;
	// int i = 0;
	// while(envp[i]) {
	// 	elements -= strlen(envp[i]) + 1;
	// 	memcpy(elements, envp[i], strlen(envp[i]) + 1);
	// 	new_envp[i] = elements;
	// 	i++;
	// }

	// // Where the stack will be
	// void *start_sp = sp;

	// // where the argc will be
	// long number = argc;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	
	// // Argv arguments
	// for (int i = 0; i < argc; i++) {
	// 	memcpy(sp, &new_argv[i], sizeof(void *));
	// 	sp += sizeof(void *);
	// }

	// // Zero section
	// char *aux = sp;
	// for (int i = 0; i < sizeof(void *); i++) {
	// 	aux[i] = 0;
	// }
	// sp += sizeof(void *);

	// // evnp arguments
	// i = 0;
	// while (envp[i]) {
	// 	memcpy(sp, &new_envp[i], sizeof(void *));
	// 	sp += sizeof(void *);
	// 	i++;
	// }

	// // Zero section
	// aux = sp;
	// for (int i = 0; i < sizeof(void *); i++) {
	// 	aux[i] = 0;
	// }
	// sp += sizeof(void *);

	// // AT_PHDR
	// long res = lowest_address;
	// number = AT_PHDR;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);

	// // AT_PHRNT
	// res = (long) elf_header->e_phentsize;
	// number = AT_PHENT;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);
	
	// // AT_PHNUM
	// res = (long) elf_header->e_phnum;
	// number = AT_PHNUM;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);

	// // AT_PAGESZ
	// res = page_size;
	// number = AT_PAGESZ;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);

	// // At random
	// elements -= 20;
	// res = (long)elements;
	// number = AT_RANDOM;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);

	// // AT_NULL
	// res = 0;
	// number = AT_NULL;
	// memcpy(sp, &number, sizeof(long));
	// sp += sizeof(long);
	// memcpy(sp, &res, sizeof(long));
	// sp += sizeof(long);

	// sp = start_sp;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	
	void (*entry)() = (void (*)) elf_header->e_entry;


	// Un mapping the file from memory
	munmap(ptr_file, statbuf.st_size);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
