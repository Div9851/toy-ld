#define _GNU_SOURCE
#include "hashmap.h"
#include "vec.h"
#include <elf.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BUF_SIZE 65536
#define SECTIONS_SIZE 32
#define INITIAL_ADDR 0x400000
#define SEGMENT_ALIGN (1 << 21)
#define PH_NUM 2
#define ENTRY_POINT_SYMBOL "_start"

enum {
    UNKNOWN_SECTION = -1,
    NULL_SECTION,
    INIT_SECTION,
    TEXT_SECTION,
    RODATA_SECTION,
    DATA_SECTION,
    BSS_SECTION,
    SYMTAB_SECTION,
    STRTAB_SECTION,
    SHSTRTAB_SECTION,
    MAX_SECTION_INDEX,
};

typedef struct {
    Elf64_Shdr *header;
    char *name;
    char *data;
    uint64_t addr;
    uint64_t offset;
} Section;

typedef struct {
    Elf64_Ehdr *header;
    Section sections[SECTIONS_SIZE];
    Elf64_Sym *symbols_begin;
    Elf64_Sym *symbols_end;
    char *symbol_str_table;
    char *data;
    HashMap *local_symbols;
} Obj;

void error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    exit(1);
}

int section_name_to_idx(const char *shname) {
    if (strcmp(shname, ".init") == 0) {
        return INIT_SECTION;
    } else if (strcmp(shname, ".text") == 0) {
        return TEXT_SECTION;
    } else if (strcmp(shname, ".rodata") == 0) {
        return RODATA_SECTION;
    } else if (strcmp(shname, ".data") == 0) {
        return DATA_SECTION;
    } else if (strcmp(shname, ".bss") == 0) {
        return BSS_SECTION;
    }

    return UNKNOWN_SECTION;
}

Obj *parse_obj(char *data) {
    Obj *obj = calloc(1, sizeof(Obj));
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *)data;
    Elf64_Shdr *section_header_table =
        (Elf64_Shdr *)(data + elf_header->e_shoff);
    char *shstr_table =
        data + section_header_table[elf_header->e_shstrndx].sh_offset;
    Section *symbol_table_section = NULL;
    obj->header = elf_header;
    for (int i = 0; i < elf_header->e_shnum; ++i) {
        obj->sections[i].header = section_header_table + i;
        obj->sections[i].name = shstr_table + section_header_table[i].sh_name;
        obj->sections[i].data = data + section_header_table[i].sh_offset;
        if (obj->sections[i].header->sh_type == SHT_SYMTAB) {
            symbol_table_section = &obj->sections[i];
        }
    }
    if (symbol_table_section != NULL) {
        obj->symbols_begin = (Elf64_Sym *)symbol_table_section->data;
        obj->symbols_end = (Elf64_Sym *)(symbol_table_section->data +
                                         symbol_table_section->header->sh_size);
        obj->symbol_str_table =
            obj->sections[symbol_table_section->header->sh_link].data;
    }
    obj->data = data;
    obj->local_symbols = new_hashmap();
    return obj;
}

uint64_t align_to(uint64_t value, uint64_t align) {
    if (align == 0 || align == 1) {
        return value;
    }
    return (value + align - 1) / align * align;
}

void apply_rela(Obj *obj, Section *rela_section, HashMap *global_symbols) {
    Elf64_Rela *rela_begin = (Elf64_Rela *)rela_section->data;
    Elf64_Rela *rela_end =
        (Elf64_Rela *)(rela_section->data + rela_section->header->sh_size);
    for (Elf64_Rela *rela = rela_begin; rela != rela_end; ++rela) {
        Section *target_section = &obj->sections[rela_section->header->sh_info];
        char *symbol_name =
            obj->symbol_str_table +
            obj->symbols_begin[ELF64_R_SYM(rela->r_info)].st_name;
        HashMapItem *symbol = hashmap_find(obj->local_symbols, symbol_name);
        if (symbol == NULL) {
            symbol = hashmap_find(global_symbols, symbol_name);
        }
        if (symbol == NULL) {
            error("symbol '%s' does not exist\n", symbol_name);
        }
        uint64_t symbol_addr = symbol->val;
        uint32_t rela_type = ELF64_R_TYPE(rela->r_info);
        if (rela_type == R_X86_64_PC32 || rela_type == R_X86_64_PLT32) {
            uint32_t val = symbol_addr + rela->r_addend -
                           (target_section->addr + rela->r_offset);
            *(uint32_t *)(target_section->data + rela->r_offset) = val;
        } else if (rela_type == R_X86_64_32S) {
            uint32_t val = symbol_addr + rela->r_addend;
            *(uint32_t *)(target_section->data + rela->r_offset) = val;
        } else {
            error("relocation type '%u' is not supported yet\n", rela_type);
        }
    }
}

void generate_executable(Vec *objs, char *output_path) {
    Vec **sections = calloc(MAX_SECTION_INDEX, sizeof(Vec *));
    for (int i = 0; i < MAX_SECTION_INDEX; ++i) {
        sections[i] = new_vec();
    }

    for (int i = 0; i < objs->len; ++i) {
        Obj *obj = (Obj *)objs->array[i];
        Section *sections_end = obj->sections + obj->header->e_shnum;
        for (Section *section = obj->sections; section != sections_end;
             ++section) {
            int section_idx = section_name_to_idx(section->name);
            if (section_idx == UNKNOWN_SECTION) {
                continue;
            }
            vec_push_back(sections[section_idx], section);
        }
    }

    Vec *code_segments = new_vec();
    vec_concat(code_segments, sections[INIT_SECTION]);
    vec_concat(code_segments, sections[TEXT_SECTION]);
    vec_concat(code_segments, sections[RODATA_SECTION]);

    // compute addr / offset of each section
    uint64_t header_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * PH_NUM;
    uint64_t base_offset = 0;
    uint64_t code_segment_begin = INITIAL_ADDR;
    uint64_t code_segment_end = code_segment_begin + header_size;
    for (int i = 0; i < code_segments->len; ++i) {
        Section *section = (Section *)code_segments->array[i];
        code_segment_end =
            align_to(code_segment_end, section->header->sh_addralign);
        section->addr = code_segment_end;
        section->offset = base_offset + (section->addr - code_segment_begin);
        code_segment_end += section->header->sh_size;
    }
    base_offset += code_segment_end - code_segment_begin;
    uint64_t data_segment_begin =
        align_to(code_segment_end, SEGMENT_ALIGN) + base_offset % SEGMENT_ALIGN;
    uint64_t data_segment_end = data_segment_begin;
    for (int i = 0; i < sections[DATA_SECTION]->len; ++i) {
        Section *section = (Section *)(sections[DATA_SECTION]->array[i]);
        data_segment_end =
            align_to(data_segment_end, section->header->sh_addralign);
        section->addr = data_segment_end;
        section->offset = base_offset + (section->addr - data_segment_begin);
        data_segment_end += section->header->sh_size;
    }
    uint64_t data_sections_end = data_segment_end;
    for (int i = 0; i < sections[BSS_SECTION]->len; ++i) {
        Section *section = (Section *)(sections[BSS_SECTION]->array[i]);
        data_segment_end =
            align_to(data_segment_end, section->header->sh_addralign);
        section->addr = data_segment_end;
        data_segment_end += section->header->sh_size;
    }

    // compute address of each symbol
    HashMap *global_symbols = new_hashmap();
    for (int i = 0; i < objs->len; ++i) {
        Obj *obj = (Obj *)objs->array[i];
        for (Elf64_Sym *symbol = obj->symbols_begin; symbol != obj->symbols_end;
             ++symbol) {
            if (symbol->st_shndx == SHN_UNDEF || symbol->st_shndx == SHN_ABS) {
                continue;
            }
            char *symbol_name = obj->symbol_str_table + symbol->st_name;
            uint64_t section_addr = obj->sections[symbol->st_shndx].addr;
            uint64_t symbol_addr = section_addr + symbol->st_value;
            if (ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL) {
                hashmap_insert(global_symbols, symbol_name, symbol_addr);
            } else if (ELF64_ST_BIND(symbol->st_info) == STB_LOCAL) {
                hashmap_insert(obj->local_symbols, symbol_name, symbol_addr);
            }
        }
    }

    // apply relocation
    for (int i = 0; i < objs->len; ++i) {
        Obj *obj = (Obj *)objs->array[i];
        Section *sections_end = obj->sections + obj->header->e_shnum;
        for (Section *section = obj->sections; section != sections_end;
             ++section) {
            if (section->header->sh_type == SHT_RELA) {
                apply_rela(obj, section, global_symbols);
            }
        }
    }

    HashMapItem *entry_point = hashmap_find(global_symbols, ENTRY_POINT_SYMBOL);
    if (entry_point == NULL) {
        error("entry point symbol '%s' is not found\n", ENTRY_POINT_SYMBOL);
    }

    Elf64_Ehdr *ehdr = calloc(1, sizeof(Elf64_Ehdr));
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_LINUX;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = entry_point->val;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = PH_NUM;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);

    Elf64_Phdr *phdr = calloc(PH_NUM, sizeof(Elf64_Phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_X;
    phdr[0].p_offset = 0;
    phdr[0].p_vaddr = phdr[0].p_paddr = code_segment_begin;
    phdr[0].p_filesz = code_segment_end - code_segment_begin;
    phdr[0].p_memsz = code_segment_end - code_segment_begin;
    phdr[0].p_align = SEGMENT_ALIGN;

    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_offset = base_offset;
    phdr[1].p_vaddr = phdr[1].p_paddr = data_segment_begin;
    phdr[1].p_filesz = data_sections_end - data_segment_begin;
    phdr[1].p_memsz = data_segment_end - data_segment_begin;
    phdr[1].p_align = SEGMENT_ALIGN;

    char *buf = calloc(BUF_SIZE, 1);
    memcpy(buf, ehdr, sizeof(Elf64_Ehdr));
    memcpy(buf + sizeof(Elf64_Ehdr), phdr, sizeof(Elf64_Phdr) * PH_NUM);
    for (int i = 0; i < code_segments->len; ++i) {
        Section *section = (Section *)code_segments->array[i];
        memcpy(buf + section->offset, section->data, section->header->sh_size);
    }
    for (int i = 0; i < sections[DATA_SECTION]->len; ++i) {
        Section *section = (Section *)sections[DATA_SECTION]->array[i];
        memcpy(buf + section->offset, section->data, section->header->sh_size);
    }

    FILE *out = fopen(output_path, "w");
    fwrite(buf, 1, base_offset + (data_sections_end - data_segment_begin), out);
    fclose(out);
    chmod(output_path, 0755);
}

int main(int argc, char **argv) {
    char *output_path = "a.out";
    Vec *objs = new_vec();
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-o") == 0) {
            output_path = argv[i + 1];
            i += 2;
            continue;
        }

        FILE *in = fopen(argv[i], "r");
        char *buf = calloc(BUF_SIZE, 1);
        fread(buf, BUF_SIZE, 1, in);
        fclose(in);

        Obj *obj = parse_obj(buf);
        vec_push_back(objs, obj);
        ++i;
    }

    generate_executable(objs, output_path);
}
