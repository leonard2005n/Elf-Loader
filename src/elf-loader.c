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

// Function that retuns the alligned memory block and his offest
void *allign_memory(unsigned long vaddr, unsigned long allignment, unsigned long *offset)
{
		void *map_address = (void *)(vaddr & ~(allignment - 1));
		*offset = vaddr - (unsigned long) map_address;
		return map_address;
}

// Function that puts auxv argument on the stack
void put_auxv(unsigned long *stack, unsigned long flag, unsigned long value)
{

	unsigned long aux = *stack;

	aux -= (sizeof(unsigned long));
	memcpy((void *)aux, &value, sizeof(unsigned long));

	aux -= (sizeof(unsigned long));
	memcpy((void *)aux, &flag, sizeof(unsigned long));

	*stack = aux;
}

// Function that adds a null field
void null_field(unsigned long *stack)
{

	unsigned long aux = *stack;

	aux -= (sizeof(unsigned long));
	memset((void *)stack, 0, sizeof(unsigned long));

	*stack = aux;

}

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

	// Getting the elf heder file
	Elf64_Ehdr *elf_header = (Elf64_Ehdr *)elf_contents;
	struct stat statbuf;

	// Opening the file
	int file = open(filename, O_RDONLY);
	int x = fstat(file, &statbuf);

	// Mapping the file in the memory
	void *ptr_file = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, file, 0);

	// Closeing the file because we don't need it anymore
	close(file);

	// Getting the first program hadder
	Elf64_Phdr *start = (Elf64_Phdr *)(ptr_file + elf_header->e_phoff);
	int off_bytes = 0;
	unsigned long offset;
	void *map_address;

	// This is interrating thru the program hadders
	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *ptr = (void *)start + off_bytes;


		if (ptr->p_type == PT_LOAD) {
			map_address = allign_memory(ptr->p_vaddr, page_size, &offset);

			void *page = mmap(map_address, ptr->p_memsz + offset, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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
	// Iterating to change the permission of the segments
	for (int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *ptr = (void *)start + off_bytes;

		if (ptr->p_type == PT_LOAD) {
			map_address = allign_memory(ptr->p_vaddr, page_size, &offset);

			unsigned char prot = PROT_NONE;
			unsigned char flags = ptr->p_flags;

			if (flags & PF_X)
				prot |= PROT_EXEC;

			if (flags & PF_W)
				prot |= PROT_WRITE;

			if (flags & PF_R)
				prot |= PROT_READ;

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

	sp = mmap(NULL, page_size * 4096, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	stack = (unsigned long)sp + page_size * 4096;

	stack -= 16;
	unsigned long vector_random = stack;

	// Puting the argv on the stack
	unsigned long new_argv[20000];

	for (int i = 0; i < argc; i++) {
		stack -= strlen(argv[i]) + 1;
		memcpy((void *)stack, argv[i], strlen(argv[i]) + 1);
		printf("%s %s\n", argv[i], (char *)stack);
		new_argv[i] = stack;
	}


	// Puting the envp on the stack
	int i = 0;
	unsigned long new_envp[20000];

	while (envp[i]) {
		stack -= strlen(envp[i]) + 1;
		memcpy((void *)stack, envp[i], strlen(envp[i]) + 1);
		new_envp[i] = stack;
		i++;
	}


	unsigned long value;
	unsigned long *value_ptr = &value;

	// Alliging the stack
	stack = (unsigned long) allign_memory(stack, 16, &offset);


	// Put null
	put_auxv(&stack, AT_NULL, 0);

	// Put Random
	put_auxv(&stack, AT_RANDOM, vector_random);

	// Put entry
	put_auxv(&stack, AT_ENTRY, elf_header->e_entry);

	// // Put pages
	put_auxv(&stack, AT_PAGESZ, page_size);


	// Distance between auxv and envp
	null_field(&stack);

	i = 0;
	while (envp[i]) {
		stack -= sizeof(unsigned long *);
		memcpy((void *)stack, &new_envp[i], sizeof(unsigned long *));
		i++;
	}


	// Distance between envp and argv
	null_field(&stack);


	for (int i = argc - 1; i >= 0; i--) {
		stack -= sizeof(unsigned char *);
		memcpy((void *)stack, &new_argv[i], sizeof(unsigned long));
	}

	stack -= sizeof(unsigned long);
	value = argc;
	memcpy((void *)stack, value_ptr, sizeof(unsigned long));


	sp = (void *)stack;

	/*
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
