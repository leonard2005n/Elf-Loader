// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <string.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

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
			unsigned long map_address = ptr->p_vaddr & ~(page_size - 1);
			unsigned long offset = ptr->p_vaddr - map_address;

			void *page = mmap((void *)map_address, ptr->p_memsz + offset, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
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
		// printf("%d\n", ptr->p_type);
		if (ptr->p_type == PT_LOAD) {\
			unsigned long map_address = ptr->p_vaddr & ~(page_size - 1);
			unsigned long offset = ptr->p_vaddr - map_address;

			mprotect((void *)map_address, ptr->p_memsz + offset, ptr->p_flags);
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
	sp = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	sp = sp + page_size;

	
	// // Puting the envp into position on the stack
	// int i = 0;
	// char *real_sp = sp;
	// while (envp[i]) {
	// 	char *aux = (char *)sp + i * sizeof(char *);
	// 	memcpy(aux, envp[i], sizeof(char *));
	// 	real_sp = aux;
	// 	i++;
	// }
	
	// sp -= sizeof(void *);
	// for (int i = 0 ; i < sizeof(void*); i++) {
	// 	char *aux = (char *)sp;
	// 	aux[i] = 0;
	// }

	// // Puting the arguments into position on the stack
	// sp -= sizeof(void *) * argc;

	// void *aux = sp;
	// for (int i = 0; i < argc; i++) {
	// 	memcpy(aux, *(argv + i * sizeof(char *)), sizeof(void *));
	// 	aux += sizeof(void *);
	// }

	// sp -= sizeof(int);
	// memcpy(sp, &argc, sizeof(int));

	// sp = real_sp;

	// char **new_argv;
	// for (int i = 0; i < argc; i++) {
		
	// }

	// void *start_sp = sp;
	// char *aux = sp;

	// for (int i = 0; i < sizeof(void *); i++) {
	// 	aux[i] = 0;
	// }

	// memcpy(sp, &argc, sizeof(int));
	// sp += sizeof(void *);

	// for (int i = 0; i < argc; i++) {
	// 	memcpy(sp, *argv[i], sizeof(void *));
	// 	sp += sizeof(void *);
	// }

	// for (int i = 0; i < sizeof(void *); i++) {
	// 	aux[i] = 0;
	// }
	// sp += sizeof(void *);

	// int i = 0;
	// while (envp[i]) {
	// 	memcpy(sp, envp[i], sizeof(void *));
	// 	sp += sizeof(void *);
	// }

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
