#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char magicType='L';

void PrintHex(const void* buffer, size_t length) {
    const unsigned char* data = (const unsigned char*) buffer;
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);
    }
}
typedef struct virus {
unsigned short SigSize;
char virusName[16];
unsigned char* sig;
}virus;

typedef struct link link;
struct link {
link *nextVirus;
virus *vir;
};


virus* read_virus(FILE* file) {
    unsigned short signatureSize;
    
    if (fread(&signatureSize, sizeof(unsigned short), 1, file) != 1) {
        return NULL;
    }

    virus* v = (virus*)malloc(sizeof(virus));
    if (v == NULL) {
        return NULL;
    }
    if(magicType=='B'){
        signatureSize=__builtin_bswap16(signatureSize);
    }

    fread(v->virusName, sizeof(char), 16, file);

    v->SigSize = signatureSize;
    v->sig = (unsigned char*)malloc(v->SigSize);
    if (v->sig == NULL) {
        free(v); 
        return NULL;
    }

    fread(v->sig, sizeof(unsigned char), v->SigSize, file);

    return v;
}


void print_virus(virus* virus, FILE* output){

    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    fprintf(output, "signature:\n");
    
    for (int i = 0; i < virus->SigSize; i++) {
        if(i == virus->SigSize-1)
            fprintf(output, "%02X", virus->sig[i]);
        else
            fprintf(output, "%02X ", virus->sig[i]);
        if ((i + 1) % 20 == 0 || i == virus->SigSize - 1) { 
            fprintf(output, "\n");
        }
    }
    fprintf(output, "\n");
}


link* list_print(link* virus_list, FILE* output,const char* string){
   if (virus_list == NULL) {
        return virus_list;
    }
    list_print(virus_list->nextVirus, output,string);
    print_virus(virus_list->vir, output);
    return virus_list;
}

link* list_append(link* virus_list, virus* data){
    link* ans = (link*)malloc(sizeof(link));
    ans->vir = data;
    ans->nextVirus = virus_list;
    return ans;
}

void list_free(link *virus_list){

    while (virus_list != NULL) {
        link* next_node = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = next_node;
    }
}

link* load_sig(link* virus_list, FILE* input, const char* string) {
    char filename[256];
    printf("Enter signature file name: ");
    scanf("%s", filename);

    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Error: failed to open file '%s'\n", filename);
        return virus_list;
    }

    char magic[5];
    fread(magic, sizeof(char), 4, fp);
    magic[4] = '\0';
   
    if (strcmp(magic, "VIRL") == 0)
        magicType = 'L';
    else if (strcmp(magic, "VIRB") == 0)
        magicType = 'B';
    else {
        fprintf(stderr, "Error: incorrect magic number\n");
        exit(1);
    }


    virus* v;
    while ((v = read_virus(fp)) != NULL) {
        virus_list = list_append(virus_list, v);
    }

    fclose(fp);
     printf("Loaded\n");
    return virus_list;
}

link* quit(link* list,FILE* in, const char* string){
    list_free(list);
    exit(0);
}


int detect_virus(char *buffer, unsigned int size, link *virus_list)
{
    int i=0;
    while(i<size)
    {
        link *curr = virus_list;
        while (curr != NULL)
        {
            virus *v = curr->vir;
            if (i + v->SigSize <= size && memcmp(&buffer[i], v->sig, v->SigSize) == 0)
            {
                printf("Starting byte location: %d\n", i);
                printf("Virus name: %s\n", v->virusName);
                printf("Virus size: %d\n", v->SigSize);
                return i;
            }
            curr = curr->nextVirus;
        }
        i++;
    }
    return -1;
}



link* detect_virus_outsource(link* virus_list, FILE* input, const char* file_name) {

    int max_size = 10000;
    char buffer[max_size]; 
    FILE *fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("Error: failed to open file '%s'\n", file_name);
    }

    int acc_size = fread(buffer, sizeof(char), max_size, fp);
    detect_virus(buffer, acc_size, virus_list);
    
    return virus_list;
}

void neutralize_virus(const char *fileName, int signatureOffset){ 
     FILE *file = fopen(fileName, "rb+");
     fseek(file, signatureOffset, SEEK_SET);
     unsigned char ret[] = {0xC3};
     fwrite(ret, 1, 1, file);
     fclose(file);
}

link* fix_file(link* virus_list, FILE* input, const char* filename) {
    const int chunk_size = 10000;  
    char buffer[chunk_size]; 
    int virus_loc;

    FILE *file = fopen(filename, "rb+");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", filename);
        return virus_list;
    }

    while (!feof(file)) {
        size_t bytes_read = fread(buffer, sizeof(unsigned char), chunk_size, file);
        if (bytes_read == 0) {
            if (ferror(file)) {
                perror("Error reading file");
            }
            break;  
        }

        virus_loc = detect_virus(buffer, bytes_read, virus_list);
        while (virus_loc != -1) {
            neutralize_virus(filename, virus_loc);
            fseek(file, virus_loc + 1, SEEK_SET);

            bytes_read = fread(buffer, sizeof(unsigned char), chunk_size, file);
            virus_loc = detect_virus(buffer, bytes_read, virus_list);
        }
    }

    fclose(file);
    return virus_list;
}

int main(int argc, char const *argv[])
{
    struct funDesc {
    char *name;
    link* (*fun)(link*,FILE*, const char*);
    };

    struct funDesc menu[] = {{"Load Signatures",load_sig}, {"Print Signatures",list_print},
    {"Detect viruses",detect_virus_outsource}, {"Fix file",fix_file},
     {"Quit",quit}, {NULL, NULL}};
    
    int bound = sizeof(menu) / sizeof(menu[0]) - 1;
    int counter = 0;
    int choice =0;
    link* list = NULL;
    while (1)
    {
        struct funDesc *ptr = menu;
        printf("\nchoose function:\n");

        while ((ptr->name) != NULL)
        {
            printf("%d) ", counter);
            printf("%s\n", ptr->name);
            ptr++;
            counter++;
        }
        counter = 0;
        printf("Your Option: ");
        if (scanf("%d", &choice) == EOF) { // Check for EOF
            printf("\nEOF detected. Exiting program.\n");
            break;
        }
        getchar();


        if (choice < 0 || choice > bound)
        {
            printf("not within bounds\n");
            break;
        }
        else
        {
            printf("within bounds\n");
            list = menu[choice].fun(list,stdout, argv[1]);

        }
            
    }
    list_free(list);
    return 0;
}

